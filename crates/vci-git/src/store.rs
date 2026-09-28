//! Attestation storage on git refs, one ref per signer.
//!
//! Layout of each signer ref's tree:
//! `<test_key[0..2]>/<test_key>/<input_root>.dsse.json` -> envelope bytes.
//!
//! Only plumbing is used: blobs via `hash-object -w`, trees via a throwaway
//! index file (`GIT_INDEX_FILE` in a temp dir) plus `write-tree`, commits via
//! `commit-tree`, and ref updates via compare-and-swap `update-ref`. The
//! user's index, HEAD and working tree are never read or written.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::GitError;
use crate::cmd::{Git, IDENTITY, command_error};
use crate::repo::{Repo, TreeEntry, is_oid, parse_oid};
use crate::validate;

/// Local namespace holding one ref per signer.
pub const REF_PREFIX: &str = "refs/attest/v1/";
/// Where `fetch` puts the remote's signer refs before merging them.
pub const REMOTE_REF_PREFIX: &str = "refs/attest-remote/v1/";

const ENVELOPE_SUFFIX: &str = ".dsse.json";
const CAS_ATTEMPTS: u32 = 40;
const PUSH_ATTEMPTS: u32 = 10;

/// An envelope read back from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// Full ref name the envelope was found on, e.g. `refs/attest/v1/0123456789abcdef`.
    pub signer_ref: String,
    pub test_key: String,
    pub input_root: String,
    /// The stored bytes, exactly as passed to `put`.
    pub bytes: Vec<u8>,
}

/// Map of tree path -> blob id for the valid envelope entries of one tree.
type Entries = BTreeMap<String, String>;

/// Attestation store backed by `refs/attest/v1/*` in a repository.
#[derive(Debug, Clone, Copy)]
pub struct AttestStore<'a> {
    repo: &'a Repo,
}

impl<'a> AttestStore<'a> {
    pub fn new(repo: &'a Repo) -> Self {
        AttestStore { repo }
    }

    /// Adds `<test_key[0..2]>/<test_key>/<input_root>.dsse.json` to
    /// `refs/attest/v1/<signer_id>` as a new commit, without touching the index
    /// or working tree. Storing identical bytes again is a no-op; different
    /// bytes under the same key replace the old envelope.
    pub fn put(
        &self,
        signer_id: &str,
        test_key: &str,
        input_root: &str,
        bytes: &[u8],
    ) -> Result<(), GitError> {
        validate::signer_id(signer_id)?;
        validate::hex_id("test_key", test_key)?;
        validate::hex_id("input_root", input_root)?;
        let path = entry_path(test_key, input_root);
        let refname = format!("{REF_PREFIX}{signer_id}");

        let blob = self
            .repo
            .git()
            .args(["hash-object", "-w", "--no-filters", "--stdin"])
            .stdin(bytes.to_vec())
            .run()?;
        let blob = parse_oid(&blob)?;

        let mut last = String::new();
        for attempt in 1..=CAS_ATTEMPTS {
            let old = self.read_ref(&refname)?;
            let mut entries = match &old {
                Some(commit) => self.tree_entries(commit, None)?,
                None => Entries::new(),
            };
            if entries.get(&path) == Some(&blob) {
                return Ok(());
            }
            entries.insert(path.clone(), blob.clone());
            let tree = self.write_tree(&entries)?;
            let parents: Vec<&str> = old.iter().map(String::as_str).collect();
            let commit = self.commit(
                &tree,
                &parents,
                &format!("vci: put {test_key} {input_root}"),
            )?;
            match self.cas(&refname, &commit, old.as_deref())? {
                Ok(()) => return Ok(()),
                Err(detail) => last = detail,
            }
            backoff(attempt, 5, 200);
        }
        Err(GitError::Contention {
            refname,
            attempts: CAS_ATTEMPTS,
            detail: last,
        })
    }

    /// All stored envelopes across every signer ref, optionally only those for
    /// one test key. Entries that don't match the layout are ignored. Sorted
    /// by (signer_ref, test_key, input_root).
    pub fn list(&self, test_key: Option<&str>) -> Result<Vec<StoredEnvelope>, GitError> {
        let under = match test_key {
            Some(k) => {
                validate::hex_id("test_key", k)?;
                Some(format!("{}/{}", &k[..2], k))
            }
            None => None,
        };
        let mut found = Vec::new();
        for (signer, commit) in self.signer_refs(REF_PREFIX)? {
            let signer_ref = format!("{REF_PREFIX}{signer}");
            for (path, oid) in self.tree_entries(&commit, under.as_deref())? {
                let Some((key, root)) = parse_layout(&path) else {
                    continue;
                };
                if test_key.is_some_and(|k| k != key) {
                    continue;
                }
                found.push((signer_ref.clone(), key.to_owned(), root.to_owned(), oid));
            }
        }
        let oids: Vec<&str> = found.iter().map(|f| f.3.as_str()).collect();
        let blobs = self.read_blobs(&oids)?;
        let mut out: Vec<StoredEnvelope> = found
            .into_iter()
            .zip(blobs)
            .map(
                |((signer_ref, test_key, input_root, _), bytes)| StoredEnvelope {
                    signer_ref,
                    test_key,
                    input_root,
                    bytes,
                },
            )
            .collect();
        out.sort_by(|a, b| {
            (&a.signer_ref, &a.test_key, &a.input_root).cmp(&(
                &b.signer_ref,
                &b.test_key,
                &b.input_root,
            ))
        });
        Ok(out)
    }

    /// Fetch the remote's signer refs into `refs/attest-remote/v1/*`, then
    /// union-merge each into the matching local ref.
    pub fn fetch(&self, remote: &str) -> Result<(), GitError> {
        validate::remote(remote)?;
        self.repo
            .git()
            .args([
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--recurse-submodules=no",
                remote,
            ])
            .arg(format!("+{REF_PREFIX}*:{REMOTE_REF_PREFIX}*"))
            .run()?;
        for (signer, remote_commit) in self.signer_refs(REMOTE_REF_PREFIX)? {
            self.merge_into_local(&signer, &remote_commit)?;
        }
        Ok(())
    }

    /// Fetch and merge, then push every local signer ref (fast-forward only),
    /// retrying from the fetch when the remote rejects an update because it
    /// moved in the meantime.
    pub fn push(&self, remote: &str) -> Result<(), GitError> {
        self.push_with_hook(remote, |_| {})
    }

    /// `push`, calling `before_push(attempt)` between the merge and the actual
    /// `git push` of each attempt. Exists so tests can simulate a concurrent
    /// writer landing in that window.
    #[doc(hidden)]
    pub fn push_with_hook(
        &self,
        remote: &str,
        mut before_push: impl FnMut(u32),
    ) -> Result<(), GitError> {
        validate::remote(remote)?;
        let mut last = String::new();
        for attempt in 1..=PUSH_ATTEMPTS {
            self.fetch(remote)?;
            let refs = self.signer_refs(REF_PREFIX)?;
            if refs.is_empty() {
                return Ok(());
            }
            before_push(attempt);
            let mut git = self.repo.git().args([
                "push",
                "--porcelain",
                "--no-verify",
                "--recurse-submodules=no",
                remote,
            ]);
            for (signer, _) in &refs {
                git = git.arg(format!("{REF_PREFIX}{signer}:{REF_PREFIX}{signer}"));
            }
            let (describe, out) = git.output_described()?;
            if out.status.success() {
                return Ok(());
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let rejected: Vec<&str> = stdout.lines().filter(|l| l.starts_with("!\t")).collect();
            if rejected.is_empty() {
                // Not a per-ref rejection (unreachable remote, auth...): don't retry.
                return Err(command_error(&describe, &out));
            }
            last = rejected.join("; ");
            if attempt < PUSH_ATTEMPTS {
                backoff(attempt, 20, 1000);
            }
        }
        Err(GitError::PushRejected {
            remote: remote.to_owned(),
            attempts: PUSH_ATTEMPTS,
            detail: last,
        })
    }

    // ---- internals -------------------------------------------------------

    /// Merge `remote_commit` into `refs/attest/v1/<signer>` so the local ref
    /// ends up containing every envelope from both.
    fn merge_into_local(&self, signer: &str, remote_commit: &str) -> Result<(), GitError> {
        let refname = format!("{REF_PREFIX}{signer}");
        let mut last = String::new();
        for attempt in 1..=CAS_ATTEMPTS {
            let local = self.read_ref(&refname)?;
            let new = match &local {
                None => remote_commit.to_owned(),
                Some(l) if l == remote_commit => return Ok(()),
                Some(l) => {
                    if self.is_ancestor(remote_commit, l)? {
                        return Ok(());
                    }
                    if self.is_ancestor(l, remote_commit)? {
                        remote_commit.to_owned()
                    } else {
                        self.union_commit(l, remote_commit)?
                    }
                }
            };
            match self.cas(&refname, &new, local.as_deref())? {
                Ok(()) => return Ok(()),
                Err(detail) => last = detail,
            }
            backoff(attempt, 5, 200);
        }
        Err(GitError::Contention {
            refname,
            attempts: CAS_ATTEMPTS,
            detail: last,
        })
    }

    /// A commit whose tree is the union of both sides' envelopes. If the same
    /// path holds different blobs, the larger blob id wins, so every clone
    /// converges on the same tree whichever side it merges from.
    fn union_commit(&self, local: &str, remote: &str) -> Result<String, GitError> {
        let mut merged = self.tree_entries(local, None)?;
        for (path, oid) in self.tree_entries(remote, None)? {
            merged
                .entry(path)
                .and_modify(|cur| {
                    if oid > *cur {
                        cur.clone_from(&oid);
                    }
                })
                .or_insert(oid);
        }
        let tree = self.write_tree(&merged)?;
        let remote_tree = self
            .repo
            .git()
            .args(["rev-parse", "--verify"])
            .arg(format!("{remote}^{{tree}}"))
            .run()?;
        if parse_oid(&remote_tree)? == tree {
            // The remote already holds everything we have: adopt it as-is so
            // clones don't keep minting merge commits for identical trees.
            return Ok(remote.to_owned());
        }
        self.commit(&tree, &[local, remote], "vci: union-merge attestations")
    }

    fn is_ancestor(&self, a: &str, b: &str) -> Result<bool, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args(["merge-base", "--is-ancestor", a, b])
            .output_described()?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(command_error(&describe, &out)),
        }
    }

    /// Current value of a ref, or None if it doesn't exist.
    fn read_ref(&self, refname: &str) -> Result<Option<String>, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args(["rev-parse", "--verify", "--quiet", refname])
            .output_described()?;
        if out.status.success() {
            return parse_oid(&out.stdout).map(Some);
        }
        if out.status.code() == Some(1) {
            return Ok(None);
        }
        Err(command_error(&describe, &out))
    }

    /// Compare-and-swap a ref. Inner Err carries git's reason on a lost race.
    fn cas(
        &self,
        refname: &str,
        new: &str,
        old: Option<&str>,
    ) -> Result<Result<(), String>, GitError> {
        let (_, out) = self
            .repo
            .git()
            .args([
                "update-ref",
                "-m",
                "vci attest",
                refname,
                new,
                old.unwrap_or(""),
            ])
            .output_described()?;
        if out.status.success() {
            Ok(Ok(()))
        } else {
            Ok(Err(String::from_utf8_lossy(&out.stderr).trim().to_owned()))
        }
    }

    /// `(signer_id, commit)` for every well-formed signer ref under `prefix`.
    /// Refs with malformed names or pointing at non-commits are skipped.
    fn signer_refs(&self, prefix: &str) -> Result<Vec<(String, String)>, GitError> {
        let out = self
            .repo
            .git()
            .args([
                "for-each-ref",
                "--format=%(objecttype) %(objectname) %(refname)",
                prefix,
            ])
            .run_str()?;
        let mut refs = Vec::new();
        for line in out.lines().filter(|l| !l.is_empty()) {
            let mut parts = line.splitn(3, ' ');
            let (Some(kind), Some(oid), Some(name)) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(GitError::Parse(format!("for-each-ref line {line:?}")));
            };
            let Some(signer) = name.strip_prefix(prefix) else {
                continue;
            };
            if kind == "commit" && is_oid(oid) && validate::is_signer_id(signer) {
                refs.push((signer.to_owned(), oid.to_owned()));
            }
        }
        refs.sort();
        Ok(refs)
    }

    /// Valid envelope entries in a commit's tree (optionally under a subdir).
    fn tree_entries(&self, commit: &str, under: Option<&str>) -> Result<Entries, GitError> {
        let mut git = self
            .repo
            .git()
            .args(["ls-tree", "-r", "-z", "--full-tree", commit]);
        if let Some(dir) = under {
            git = git.args(["--", dir]);
        }
        let listing = git.run()?;
        let mut entries = Entries::new();
        for record in listing.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let e = TreeEntry::parse(record)?;
            let Ok(path) = std::str::from_utf8(e.path) else {
                continue;
            };
            if e.mode == "100644" && e.kind == "blob" && parse_layout(path).is_some() {
                entries.insert(path.to_owned(), e.oid);
            }
        }
        Ok(entries)
    }

    /// Write a tree containing exactly `entries`, using a temporary index file.
    fn write_tree(&self, entries: &Entries) -> Result<String, GitError> {
        let dir = tempfile::Builder::new().prefix("vci-git-").tempdir()?;
        let index = dir.path().join("index");
        let isolated = |git: Git| {
            git.env("GIT_INDEX_FILE", &index).args([
                "-c",
                "core.splitIndex=false",
                "-c",
                "core.fsmonitor=false",
            ])
        };
        if !entries.is_empty() {
            let mut info = Vec::new();
            for (path, oid) in entries {
                info.extend_from_slice(format!("100644 {oid}\t{path}").as_bytes());
                info.push(0);
            }
            isolated(self.repo.git())
                .args(["update-index", "-z", "--index-info"])
                .stdin(info)
                .run()?;
        }
        let tree = isolated(self.repo.git()).arg("write-tree").run()?;
        parse_oid(&tree)
    }

    fn commit(&self, tree: &str, parents: &[&str], message: &str) -> Result<String, GitError> {
        let mut git = self
            .repo
            .git()
            .args(["commit-tree", "--no-gpg-sign", tree, "-m", message]);
        for p in parents {
            git = git.args(["-p", p]);
        }
        for (k, v) in IDENTITY {
            git = git.env(k, v);
        }
        parse_oid(&git.run()?)
    }

    /// Contents of the given blobs, in order, via one `cat-file --batch`.
    fn read_blobs(&self, oids: &[&str]) -> Result<Vec<Vec<u8>>, GitError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let mut input = String::new();
        for oid in oids {
            input.push_str(oid);
            input.push('\n');
        }
        let out = self
            .repo
            .git()
            .args(["cat-file", "--batch"])
            .stdin(input.into_bytes())
            .run()?;
        let mut rest = out.as_slice();
        let mut blobs = Vec::with_capacity(oids.len());
        for oid in oids {
            let bad =
                |what: &str| GitError::Parse(format!("cat-file --batch output for {oid}: {what}"));
            let nl = rest
                .iter()
                .position(|b| *b == b'\n')
                .ok_or_else(|| bad("no header"))?;
            let header = std::str::from_utf8(&rest[..nl]).map_err(|_| bad("header not UTF-8"))?;
            let mut parts = header.split(' ');
            let (Some(got), Some(kind), Some(size), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(bad(header));
            };
            if got != *oid || kind != "blob" {
                return Err(bad(header));
            }
            let size: usize = size.parse().map_err(|_| bad("bad size"))?;
            let body = &rest[nl + 1..];
            if body.len() < size + 1 || body[size] != b'\n' {
                return Err(bad("truncated"));
            }
            blobs.push(body[..size].to_vec());
            rest = &body[size + 1..];
        }
        Ok(blobs)
    }
}

fn entry_path(test_key: &str, input_root: &str) -> String {
    format!(
        "{}/{test_key}/{input_root}{ENVELOPE_SUFFIX}",
        &test_key[..2]
    )
}

/// Split a tree path into (test_key, input_root) if it follows the layout.
fn parse_layout(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.split('/');
    let (Some(prefix), Some(key), Some(file), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let root = file.strip_suffix(ENVELOPE_SUFFIX)?;
    (validate::is_hex_id(key)
        && validate::is_hex_id(root)
        && prefix.len() == 2
        && key.starts_with(prefix))
    .then_some((key, root))
}

/// Sleep a random duration in `[base, base + min(base * 2^attempt, cap))` ms,
/// so contending writers spread out instead of retrying in lockstep.
fn backoff(attempt: u32, base_ms: u64, cap_ms: u64) {
    use std::hash::{BuildHasher, Hasher};
    // RandomState is seeded randomly per instance: a dependency-free RNG.
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let window = (base_ms << attempt.min(10)).min(cap_ms).max(1);
    std::thread::sleep(Duration::from_millis(base_ms + random % window));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_round_trip() {
        let key = "ab".repeat(32);
        let root = "cd".repeat(32);
        let p = entry_path(&key, &root);
        assert_eq!(p, format!("ab/{key}/{root}.dsse.json"));
        assert_eq!(parse_layout(&p), Some((key.as_str(), root.as_str())));
    }

    #[test]
    fn layout_rejects_junk() {
        for bad in [
            "README",
            "ab/abcd/ef.json",
            "ac/abcd/ef.dsse.json",
            "ab/abcd/EF.dsse.json",
            "ab/abcd/x/ef.dsse.json",
            "ab/abcd/.dsse.json",
        ] {
            assert_eq!(parse_layout(bad), None, "{bad}");
        }
    }
}
