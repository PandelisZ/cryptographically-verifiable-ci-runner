//! Tests for capture, root and diff. Each detection test captures a manifest
//! from a temp repo, changes one thing and asserts the change is reported.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;

use camino::{Utf8Path, Utf8PathBuf};

use crate::hash::{ChildType, dir_listing_hash};
use crate::*;

struct Repo {
    _dir: tempfile::TempDir,
    root: Utf8PathBuf,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().join("repo")).unwrap();
        fs::create_dir(&root).unwrap();
        Repo { _dir: dir, root }
    }

    /// A directory next to the repo (outside it).
    fn outside(&self) -> Utf8PathBuf {
        self.root.parent().unwrap().join("outside")
    }

    fn write(&self, p: &str, content: &str) {
        let abs = self.root.join(p);
        fs::create_dir_all(abs.parent().unwrap()).unwrap();
        fs::write(abs, content).unwrap();
    }

    fn mkdir(&self, p: &str) {
        fs::create_dir_all(self.root.join(p)).unwrap();
    }

    fn rm(&self, p: &str) {
        let abs = self.root.join(p);
        let md = fs::symlink_metadata(&abs).unwrap();
        if md.is_dir() {
            fs::remove_dir_all(abs).unwrap();
        } else {
            fs::remove_file(abs).unwrap();
        }
    }

    #[cfg(unix)]
    fn chmod(&self, p: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(self.root.join(p), fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn symlink(&self, link: &str, target: &str) {
        let abs = self.root.join(link);
        fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, abs).unwrap();
    }
}

fn rp(s: &str) -> RepoPath {
    RepoPath::new(s).unwrap()
}

fn read(s: &str) -> (RepoPath, Observation) {
    (rp(s), Observation::Read)
}
fn probe(s: &str) -> (RepoPath, Observation) {
    (rp(s), Observation::Probe)
}
fn readdir(s: &str) -> (RepoPath, Observation) {
    (rp(s), Observation::ReadDir)
}

type Env = HashMap<String, OsString>;

fn env_of(pairs: &[(&str, &str)]) -> Env {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), OsString::from(v)))
        .collect()
}

fn capture(root: &Utf8Path, obs: &[(RepoPath, Observation)]) -> InputManifest {
    capture_env(root, obs, &[], &Env::new())
}

fn capture_env(
    root: &Utf8Path,
    obs: &[(RepoPath, Observation)],
    keys: &[&str],
    env: &Env,
) -> InputManifest {
    let keys: Vec<String> = keys.iter().map(|s| s.to_string()).collect();
    InputManifest::capture_with_env(root, obs, vec![], &keys, |k| env.get(k).cloned())
        .unwrap_or_else(|e| panic!("capture failed: {e}"))
}

fn diff(m: &InputManifest, root: &Utf8Path) -> Vec<Mismatch> {
    diff_env(m, root, &Env::new())
}

fn diff_env(m: &InputManifest, root: &Utf8Path, env: &Env) -> Vec<Mismatch> {
    m.diff_against_checkout_with_env(root, |k| env.get(k).cloned())
        .unwrap_or_else(|e| panic!("diff failed: {e}"))
}

fn whats(ms: &[Mismatch]) -> Vec<&str> {
    ms.iter().map(|m| m.what.as_str()).collect()
}

fn entry<'a>(m: &'a InputManifest, p: &str) -> &'a InputEntry {
    m.entries
        .iter()
        .find(|e| e.path.as_str() == p)
        .unwrap_or_else(|| panic!("no entry {p} in {:#?}", m.entries))
}

fn b3(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

// ---------------------------------------------------------------- root ----

fn golden_manifest() -> InputManifest {
    InputManifest {
        entries: vec![
            InputEntry {
                path: rp("src"),
                kind: EntryKind::DirListing,
                exec: false,
                size: 2,
                hash: dir_listing_hash(&mut [
                    ("b.ts".to_owned(), ChildType::File),
                    ("a.ts".to_owned(), ChildType::File),
                ]),
            },
            InputEntry {
                path: rp("a.txt"),
                kind: EntryKind::File,
                exec: false,
                size: 5,
                hash: b3(b"hello"),
            },
            InputEntry {
                path: rp("bin/run.sh"),
                kind: EntryKind::File,
                exec: true,
                size: 10,
                hash: b3(b"#!/bin/sh\n"),
            },
            InputEntry::absent(rp("missing.json")),
            InputEntry {
                path: rp("link"),
                kind: EntryKind::Symlink,
                exec: false,
                size: 5,
                hash: b3(b"a.txt"),
            },
        ],
        externals: vec![
            External {
                name: "vitest".into(),
                version: "5.0.2".into(),
            },
            External {
                name: "ms".into(),
                version: "2.1.3".into(),
            },
        ],
        env: vec![
            EnvEntry {
                key: "TZ".into(),
                hash: b3(b"UTC"),
            },
            EnvEntry {
                key: "HOME".into(),
                hash: ABSENT_HASH.into(),
            },
        ],
    }
}

/// Changing the encoding (or any hash it depends on) changes this value and
/// invalidates every stored attestation. Update only deliberately, with a
/// version bump of the domain tag.
const GOLDEN_ROOT: &str = "8b5271ee2f4b0e37e9021f0e40a7578d672c86f0e080b5592757a113f77c9ff7";

#[test]
fn golden_root_is_pinned() {
    let m = golden_manifest();
    assert_eq!(
        m.entries[0].hash, "17e5ee4d0aa23a6ad703f341ead19246803487a73f000416a4f2d9e488d68707",
        "dir listing hash encoding changed"
    );
    assert_eq!(m.root(), GOLDEN_ROOT);
}

/// Independent re-implementation of the encoding documented on
/// `InputManifest::root`, written out by hand.
#[test]
fn golden_root_matches_documented_encoding() {
    fn lp(h: &mut blake3::Hasher, b: &[u8]) {
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(b);
    }
    fn n(h: &mut blake3::Hasher, v: u64) {
        h.update(&v.to_le_bytes());
    }
    let mut dh = blake3::Hasher::new();
    lp(&mut dh, b"vci/dir-listing/v1");
    n(&mut dh, 2);
    lp(&mut dh, b"a.ts");
    lp(&mut dh, b"file");
    lp(&mut dh, b"b.ts");
    lp(&mut dh, b"file");
    let dir_hash = dh.finalize().to_hex().to_string();

    let mut h = blake3::Hasher::new();
    lp(&mut h, b"vci/input-root/v1");
    lp(&mut h, b"entries");
    n(&mut h, 5);
    // Sorted by path bytes: a.txt, bin/run.sh, link, missing.json, src.
    for (path, kind, exec, size, hash) in [
        ("a.txt", "file", 0u64, 5u64, b3(b"hello")),
        ("bin/run.sh", "file", 1, 10, b3(b"#!/bin/sh\n")),
        ("link", "symlink", 0, 5, b3(b"a.txt")),
        ("missing.json", "absent", 0, 0, ABSENT_HASH.to_owned()),
        ("src", "dirListing", 0, 2, dir_hash.clone()),
    ] {
        lp(&mut h, path.as_bytes());
        lp(&mut h, kind.as_bytes());
        n(&mut h, exec);
        n(&mut h, size);
        lp(&mut h, hash.as_bytes());
    }
    lp(&mut h, b"externals");
    n(&mut h, 2);
    for (name, ver) in [("ms", "2.1.3"), ("vitest", "5.0.2")] {
        lp(&mut h, name.as_bytes());
        lp(&mut h, ver.as_bytes());
    }
    lp(&mut h, b"env");
    n(&mut h, 2);
    for (k, v) in [("HOME", ABSENT_HASH.to_owned()), ("TZ", b3(b"UTC"))] {
        lp(&mut h, k.as_bytes());
        lp(&mut h, v.as_bytes());
    }
    let expected = h.finalize().to_hex().to_string();

    let m = golden_manifest();
    assert_eq!(m.entries[0].hash, dir_hash);
    assert_eq!(m.root(), expected);
}

#[test]
fn root_is_order_independent() {
    let m = golden_manifest();
    let mut r = m.clone();
    r.entries.reverse();
    r.externals.reverse();
    r.env.reverse();
    assert_eq!(m.root(), r.root());
    let mut r2 = m.clone();
    r2.entries.rotate_left(2);
    assert_eq!(m.root(), r2.root());
}

#[test]
fn root_is_sensitive_to_every_field() {
    let base = golden_manifest();
    let r0 = base.root();
    let mut variants: Vec<(&str, InputManifest)> = Vec::new();
    let mut add = |name: &'static str, f: &dyn Fn(&mut InputManifest)| {
        let mut m = base.clone();
        f(&mut m);
        variants.push((name, m));
    };
    add("path", &|m| m.entries[1].path = rp("a.txu"));
    add("kind", &|m| m.entries[1].kind = EntryKind::Symlink);
    add("exec", &|m| m.entries[1].exec = true);
    add("size", &|m| m.entries[1].size = 6);
    add("hash", &|m| m.entries[1].hash = b3(b"hellp"));
    add("drop entry", &|m| {
        m.entries.remove(3);
    });
    add("dup entry", &|m| {
        let e = m.entries[1].clone();
        m.entries.push(e)
    });
    add("ext name", &|m| m.externals[1].name = "mt".into());
    add("ext version", &|m| m.externals[1].version = "2.1.4".into());
    add("drop ext", &|m| {
        m.externals.pop();
    });
    add("env key", &|m| m.env[0].key = "TZZ".into());
    add("env hash", &|m| m.env[0].hash = b3(b"UTC0"));
    add("env unset", &|m| m.env[0].hash = ABSENT_HASH.into());
    add("drop env", &|m| {
        m.env.pop();
    });
    add("ext moved to env", &|m| {
        let x = m.externals.pop().unwrap();
        m.env.push(EnvEntry {
            key: x.name,
            hash: x.version,
        });
    });
    let mut seen = std::collections::HashSet::new();
    seen.insert(r0.clone());
    for (name, m) in &variants {
        let r = m.root();
        assert_ne!(r, r0, "root did not change for {name}");
        assert!(seen.insert(r), "root collided for {name}");
    }
}

#[test]
fn root_survives_json_round_trip() {
    let m = golden_manifest();
    let json = serde_json::to_string(&m).unwrap();
    let back: InputManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.root(), m.root());
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["entries"][0]["kind"], "dirListing");
    assert_eq!(v["entries"][3]["kind"], "absent");
    assert_eq!(v["entries"][3]["hash"], ABSENT_HASH);
    assert_eq!(v["env"][0]["key"], "TZ");
}

#[test]
fn empty_manifest_root_is_stable() {
    let a = InputManifest::default().root();
    assert_eq!(a, InputManifest::default().root());
    assert_ne!(a, golden_manifest().root());
    assert_eq!(a.len(), 64);
}

// ------------------------------------------------------------- capture ----

fn sample_repo() -> Repo {
    let r = Repo::new();
    r.write("src/a.ts", "export const a = 1;\n");
    r.write("src/b.ts", "export const b = 2;\n");
    r.write("src/b.test.ts", "import { b } from './b';\n");
    r.write("fixtures/b.json", "{\"x\":1}\n");
    r.write("fixtures/other.json", "{}\n");
    r.write("bin/tool.sh", "#!/bin/sh\necho hi\n");
    #[cfg(unix)]
    r.chmod("bin/tool.sh", 0o755);
    r
}

fn sample_obs() -> Vec<(RepoPath, Observation)> {
    vec![
        read("src/b.ts"),
        read("src/b.test.ts"),
        read("fixtures/b.json"),
        read("bin/tool.sh"),
        probe("src/b.local.ts"),
        probe("fixtures/b.override.json"),
        readdir("fixtures"),
    ]
}

#[test]
fn capture_records_expected_entries() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());

    let paths: Vec<&str> = m.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "bin/tool.sh",
            "fixtures",
            "fixtures/b.json",
            "fixtures/b.override.json",
            "src/b.local.ts",
            "src/b.test.ts",
            "src/b.ts",
        ],
        "sorted by path bytes"
    );

    let f = entry(&m, "fixtures/b.json");
    assert_eq!(f.kind, EntryKind::File);
    assert!(!f.exec);
    assert_eq!(f.size, 8);
    assert_eq!(f.hash, b3(b"{\"x\":1}\n"));

    #[cfg(unix)]
    assert!(entry(&m, "bin/tool.sh").exec);

    let a = entry(&m, "src/b.local.ts");
    assert_eq!(a, &InputEntry::absent(rp("src/b.local.ts")));

    let d = entry(&m, "fixtures");
    assert_eq!(d.kind, EntryKind::DirListing);
    assert_eq!(d.size, 2);
    assert_eq!(
        d.hash,
        dir_listing_hash(&mut [
            ("b.json".to_owned(), ChildType::File),
            ("other.json".to_owned(), ChildType::File),
        ])
    );

    assert!(diff(&m, &r.root).is_empty());
}

#[test]
fn capture_is_order_independent_and_dedups() {
    let r = sample_repo();
    let obs = sample_obs();
    let m1 = capture(&r.root, &obs);

    let mut rev = obs.clone();
    rev.reverse();
    let m2 = capture(&r.root, &rev);

    let mut dup = obs.clone();
    dup.rotate_left(3);
    dup.extend(obs.iter().cloned());
    dup.push(read("fixtures")); // Read of a dir == ReadDir of it
    let m3 = capture(&r.root, &dup);

    assert_eq!(m1, m2);
    assert_eq!(m1, m3);
    assert_eq!(m1.root(), m3.root());

    // Externals and env keys too.
    let env = env_of(&[("TZ", "UTC"), ("LANG", "C")]);
    let ext = |v: &[(&str, &str)]| -> Vec<External> {
        v.iter()
            .map(|(n, ver)| External {
                name: n.to_string(),
                version: ver.to_string(),
            })
            .collect()
    };
    let keys = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
    let a = InputManifest::capture_with_env(
        &r.root,
        &obs,
        ext(&[("ms", "2.1.3"), ("chalk", "5.0.0")]),
        &keys(&["TZ", "LANG", "NOPE"]),
        |k| env.get(k).cloned(),
    )
    .unwrap();
    let b = InputManifest::capture_with_env(
        &r.root,
        &rev,
        ext(&[("chalk", "5.0.0"), ("ms", "2.1.3"), ("chalk", "5.0.0")]),
        &keys(&["NOPE", "LANG", "TZ", "TZ"]),
        |k| env.get(k).cloned(),
    )
    .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.root(), b.root());
    assert_eq!(a.externals.len(), 2);
    assert_eq!(a.externals[0].name, "chalk");
    let keys_sorted: Vec<&str> = a.env.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys_sorted, vec!["LANG", "NOPE", "TZ"]);
    assert_eq!(a.env[1].hash, ABSENT_HASH);
    assert_eq!(a.env[2].hash, b3(b"UTC"));
}

#[test]
fn capture_is_stable_across_many_files_and_runs() {
    let r = Repo::new();
    let mut obs = Vec::new();
    for i in 0..300 {
        let p = format!("d{}/f{i}.ts", i % 7);
        r.write(&p, &format!("content {i}\n").repeat(i + 1));
        obs.push(read(&p));
    }
    let m1 = capture(&r.root, &obs);
    obs.reverse();
    let m2 = capture(&r.root, &obs);
    assert_eq!(m1.entries.len(), 300);
    assert_eq!(m1.root(), m2.root());
    assert!(diff(&m1, &r.root).is_empty());
}

#[test]
fn large_file_hash_matches_one_shot_blake3() {
    let r = Repo::new();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i * 31 % 251) as u8).collect();
    fs::write(r.root.join("big.bin"), &big).unwrap();
    let m = capture(&r.root, &[read("big.bin")]);
    let e = entry(&m, "big.bin");
    assert_eq!(e.size, big.len() as u64);
    assert_eq!(e.hash, b3(&big));
}

#[test]
fn diff_is_clean_on_an_identical_copy_elsewhere() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());
    let other = Repo::new();
    for p in [
        "src/a.ts",
        "src/b.ts",
        "src/b.test.ts",
        "fixtures/b.json",
        "fixtures/other.json",
        "bin/tool.sh",
    ] {
        fs::create_dir_all(other.root.join(p).parent().unwrap()).unwrap();
        fs::copy(r.root.join(p), other.root.join(p)).unwrap();
    }
    #[cfg(unix)]
    other.chmod("bin/tool.sh", 0o755);
    assert!(diff(&m, &other.root).is_empty());
    assert_eq!(capture(&other.root, &sample_obs()).root(), m.root());
}

#[test]
fn capture_errors_fail_open() {
    let r = sample_repo();
    let err = |obs: &[(RepoPath, Observation)]| {
        InputManifest::capture_with_env(&r.root, obs, vec![], &[], |_| None).unwrap_err()
    };
    assert!(matches!(
        err(&[read("nope.ts")]),
        ManifestError::ReadMissing(_)
    ));
    assert!(matches!(
        err(&[readdir("nope")]),
        ManifestError::ReadMissing(_)
    ));
    assert!(matches!(
        err(&[probe("src/a.ts")]),
        ManifestError::ProbeExists(_)
    ));
    assert!(matches!(
        err(&[probe("src")]),
        ManifestError::ProbeExists(_)
    ));
    assert!(matches!(
        err(&[readdir("src/a.ts")]),
        ManifestError::NotADirectory(_)
    ));
    // One bad observation poisons the whole capture.
    let mut obs = sample_obs();
    obs.push(read("nope.ts"));
    assert!(matches!(err(&obs), ManifestError::ReadMissing(_)));

    for bad in ["", "A=B", "A\0"] {
        let e = InputManifest::capture_with_env(&r.root, &[], vec![], &[bad.to_owned()], |_| None)
            .unwrap_err();
        assert!(matches!(e, ManifestError::InvalidEnvKey(_)), "{bad:?}");
    }
}

#[test]
fn probe_under_a_file_is_absent() {
    let r = sample_repo();
    // stat("src/a.ts/x") fails with ENOTDIR.
    let m = capture(&r.root, &[probe("src/a.ts/x")]);
    assert_eq!(entry(&m, "src/a.ts/x").kind, EntryKind::Absent);
    assert!(diff(&m, &r.root).is_empty());
    r.rm("src/a.ts");
    r.write("src/a.ts/x", "now exists");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:src/a.ts/x"]);
}

#[test]
fn repo_root_listing() {
    let r = sample_repo();
    let m = capture(&r.root, &[readdir(".")]);
    let e = entry(&m, ".");
    assert_eq!(e.kind, EntryKind::DirListing);
    assert_eq!(e.size, 3); // bin, fixtures, src
    assert!(diff(&m, &r.root).is_empty());
    r.write("new.txt", "");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:."]);
}

// ----------------------------------------------------------- detection ----

#[test]
fn detects_content_change() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());
    r.write("fixtures/b.json", "{\"x\":2}\n"); // same size, different bytes
    let d = diff(&m, &r.root);
    assert_eq!(whats(&d), vec!["entry:fixtures/b.json"]);
    assert!(d[0].expected.contains(&b3(b"{\"x\":1}\n")));
    assert!(d[0].actual.contains(&b3(b"{\"x\":2}\n")));
}

#[test]
fn detects_deletion_of_read_file() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());
    r.rm("src/b.ts");
    let d = diff(&m, &r.root);
    assert_eq!(whats(&d), vec!["entry:src/b.ts"]);
    assert_eq!(d[0].actual, "absent");
}

#[test]
fn unrelated_change_is_not_a_mismatch() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());
    r.write("src/a.ts", "export const a = 42;\n"); // only A depends on this
    assert!(diff(&m, &r.root).is_empty());
}

#[cfg(unix)]
#[test]
fn detects_exec_bit_change() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());
    r.chmod("bin/tool.sh", 0o644);
    let d = diff(&m, &r.root);
    assert_eq!(whats(&d), vec!["entry:bin/tool.sh"]);
    assert!(d[0].expected.contains("exec=true"));
    assert!(d[0].actual.contains("exec=false"));

    // Non-exec -> exec as well.
    r.chmod("fixtures/b.json", 0o755);
    assert_eq!(
        whats(&diff(&m, &r.root)),
        vec!["entry:bin/tool.sh", "entry:fixtures/b.json"]
    );
}

#[cfg(unix)]
#[test]
fn only_the_exec_bit_of_mode_is_recorded() {
    let r = sample_repo();
    r.chmod("fixtures/b.json", 0o644);
    let m = capture(&r.root, &sample_obs());
    r.chmod("fixtures/b.json", 0o600); // not executable either way
    assert!(diff(&m, &r.root).is_empty());
    r.chmod("fixtures/b.json", 0o611); // group/other x only: git says non-exec
    assert!(diff(&m, &r.root).is_empty());
}

#[test]
fn detects_absent_file_appearing() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());
    r.write("src/b.local.ts", "");
    let d = diff(&m, &r.root);
    assert_eq!(whats(&d), vec!["entry:src/b.local.ts"]);
    assert_eq!(d[0].expected, "absent");
    assert!(d[0].actual.starts_with("file "));

    // A directory appearing at a probed path counts too.
    r.rm("src/b.local.ts");
    r.mkdir("src/b.local.ts");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:src/b.local.ts"]);
}

#[test]
fn detects_directory_listing_change() {
    let r = sample_repo();
    let m = capture(&r.root, &sample_obs());

    // Added child.
    r.write("fixtures/new.json", "");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fixtures"]);
    r.rm("fixtures/new.json");
    assert!(diff(&m, &r.root).is_empty());

    // Removed child (content of remaining files unchanged).
    r.rm("fixtures/other.json");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fixtures"]);

    // Renamed child: same count.
    r.write("fixtures/renamed.json", "{}\n");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fixtures"]);
    r.rm("fixtures/renamed.json");
    r.write("fixtures/other.json", "{}\n");
    assert!(diff(&m, &r.root).is_empty());

    // Child changes type but keeps its name.
    r.rm("fixtures/other.json");
    r.mkdir("fixtures/other.json");
    assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fixtures"]);

    // Listing replaced by a file.
    r.rm("fixtures");
    r.write("fixtures", "");
    let d = diff(&m, &r.root);
    assert!(whats(&d).contains(&"entry:fixtures"));
}

#[test]
fn listing_content_edits_do_not_change_listing() {
    let r = sample_repo();
    let m = capture(&r.root, &[readdir("fixtures")]);
    r.write("fixtures/other.json", "changed but only listed, never read");
    assert!(diff(&m, &r.root).is_empty());
}

#[test]
fn detects_env_value_change() {
    let r = sample_repo();
    let env = env_of(&[("TZ", "UTC"), ("EMPTY", "")]);
    let m = capture_env(&r.root, &sample_obs(), &["TZ", "EMPTY", "UNSET"], &env);
    assert!(diff_env(&m, &r.root, &env).is_empty());

    let d = diff_env(
        &m,
        &r.root,
        &env_of(&[("TZ", "Europe/Athens"), ("EMPTY", "")]),
    );
    assert_eq!(whats(&d), vec!["env:TZ"]);
    assert_eq!(d[0].expected, format!("blake3={}", b3(b"UTC")));

    // Set -> unset.
    let d = diff_env(&m, &r.root, &env_of(&[("EMPTY", "")]));
    assert_eq!(whats(&d), vec!["env:TZ"]);
    assert_eq!(d[0].actual, "unset");

    // Unset -> set, and empty -> unset (empty string is not the same as unset).
    let d = diff_env(&m, &r.root, &env_of(&[("TZ", "UTC"), ("UNSET", "1")]));
    assert_eq!(whats(&d), vec!["env:EMPTY", "env:UNSET"]);

    // Variables that were not recorded are ignored.
    let d = diff_env(
        &m,
        &r.root,
        &env_of(&[("TZ", "UTC"), ("EMPTY", ""), ("OTHER", "x")]),
    );
    assert!(d.is_empty());
}

#[test]
fn process_env_is_the_default_source() {
    let r = sample_repo();
    let keys = vec![
        "PATH".to_owned(),
        "VCI_CORE_TEST_SURELY_UNSET_7f3a".to_owned(),
    ];
    let m = InputManifest::capture(&r.root, &sample_obs(), vec![], &keys).unwrap();
    let path_hash = env_value_hash(std::env::var_os("PATH").as_deref());
    assert_eq!(m.env[0].hash, path_hash);
    assert_eq!(m.env[1].hash, ABSENT_HASH);
    assert!(m.diff_against_checkout(&r.root).unwrap().is_empty());
}

#[test]
fn every_change_is_reported_at_once() {
    let r = sample_repo();
    let env = env_of(&[("TZ", "UTC")]);
    let m = capture_env(&r.root, &sample_obs(), &["TZ"], &env);
    r.write("src/b.ts", "changed");
    r.write("src/b.local.ts", "");
    r.write("fixtures/new.json", "");
    let d = diff_env(&m, &r.root, &Env::new());
    assert_eq!(
        whats(&d),
        vec![
            "entry:fixtures",
            "entry:src/b.local.ts",
            "entry:src/b.ts",
            "env:TZ"
        ]
    );
}

#[test]
fn diff_rejects_invalid_env_key_in_manifest() {
    let r = sample_repo();
    let mut m = capture(&r.root, &sample_obs());
    m.env.push(EnvEntry {
        key: "A=B".into(),
        hash: ABSENT_HASH.into(),
    });
    assert!(matches!(
        m.diff_against_checkout_with_env(&r.root, |_| None),
        Err(ManifestError::InvalidEnvKey(_))
    ));
}

// ------------------------------------------------------------ symlinks ----

#[cfg(unix)]
mod symlinks {
    use super::*;

    #[test]
    fn records_link_and_resolved_target() {
        let r = sample_repo();
        r.symlink("fixtures/current.json", "b.json");
        let m = capture(&r.root, &[read("fixtures/current.json")]);
        assert_eq!(m.entries.len(), 2);
        let l = entry(&m, "fixtures/current.json");
        assert_eq!(l.kind, EntryKind::Symlink);
        assert_eq!(l.hash, b3(b"b.json"));
        assert_eq!(l.size, 6);
        let t = entry(&m, "fixtures/b.json");
        assert_eq!(t.kind, EntryKind::File);
        assert_eq!(t.hash, b3(b"{\"x\":1}\n"));
        assert!(diff(&m, &r.root).is_empty());

        // Content change of the target.
        r.write("fixtures/b.json", "{\"x\":9}\n");
        assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fixtures/b.json"]);
    }

    #[test]
    fn detects_retarget_even_with_identical_content() {
        let r = sample_repo();
        r.write("fixtures/copy.json", "{\"x\":1}\n");
        r.symlink("fixtures/current.json", "b.json");
        let m = capture(&r.root, &[read("fixtures/current.json")]);
        r.rm("fixtures/current.json");
        r.symlink("fixtures/current.json", "copy.json");
        let d = diff(&m, &r.root);
        assert_eq!(whats(&d), vec!["entry:fixtures/current.json"]);
    }

    #[test]
    fn detects_file_replaced_by_symlink() {
        let r = sample_repo();
        let m = capture(&r.root, &[read("fixtures/b.json")]);
        fs::rename(
            r.root.join("fixtures/b.json"),
            r.root.join("fixtures/real.json"),
        )
        .unwrap();
        r.symlink("fixtures/b.json", "real.json");
        let d = diff(&m, &r.root);
        assert_eq!(whats(&d), vec!["entry:fixtures/b.json"]);
        assert!(d[0].actual.starts_with("symlink"));
    }

    #[test]
    fn records_every_hop_of_a_chain() {
        let r = sample_repo();
        r.write("fixtures/c.json", "C");
        r.write("fixtures/d.json", "D");
        r.symlink("a.json", "fixtures/b-link.json");
        r.symlink("fixtures/b-link.json", "c.json");
        let m = capture(&r.root, &[read("a.json")]);
        let kinds: Vec<(&str, EntryKind)> = m
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("a.json", EntryKind::Symlink),
                ("fixtures/b-link.json", EntryKind::Symlink),
                ("fixtures/c.json", EntryKind::File),
            ]
        );
        assert!(diff(&m, &r.root).is_empty());
        // Retarget the middle hop only.
        r.rm("fixtures/b-link.json");
        r.symlink("fixtures/b-link.json", "d.json");
        assert_eq!(
            whats(&diff(&m, &r.root)),
            vec!["entry:fixtures/b-link.json"]
        );
    }

    #[test]
    fn dotdot_through_real_directory_is_resolved() {
        let r = sample_repo();
        r.symlink("src/deep/link.json", "../../fixtures/b.json");
        let m = capture(&r.root, &[read("src/deep/link.json")]);
        assert_eq!(entry(&m, "fixtures/b.json").kind, EntryKind::File);
        assert!(diff(&m, &r.root).is_empty());
    }

    #[test]
    fn absolute_target_inside_repo_is_resolved() {
        let r = sample_repo();
        let target = r.root.join("fixtures/b.json");
        r.symlink("abs.json", target.as_str());
        let m = capture(&r.root, &[read("abs.json")]);
        assert_eq!(entry(&m, "abs.json").hash, b3(target.as_str().as_bytes()));
        assert_eq!(entry(&m, "fixtures/b.json").kind, EntryKind::File);
    }

    #[test]
    fn target_outside_repo_is_an_error() {
        let r = sample_repo();
        fs::create_dir_all(r.outside()).unwrap();
        fs::write(r.outside().join("secret.json"), "{}").unwrap();
        r.symlink("rel.json", "../outside/secret.json");
        r.symlink("abs.json", r.outside().join("secret.json").as_str());
        r.symlink("sub/escape.json", "../../../x");
        for p in ["rel.json", "abs.json", "sub/escape.json"] {
            let e = InputManifest::capture_with_env(&r.root, &[read(p)], vec![], &[], |_| None)
                .unwrap_err();
            assert!(
                matches!(e, ManifestError::SymlinkOutsideRepo { .. }),
                "{p}: {e}"
            );
        }
        // Even probing through a link that leaves the repo is refused.
        r.symlink("gone.json", "../outside/missing.json");
        let e =
            InputManifest::capture_with_env(&r.root, &[probe("gone.json")], vec![], &[], |_| None)
                .unwrap_err();
        assert!(matches!(e, ManifestError::SymlinkOutsideRepo { .. }));
    }

    #[test]
    fn dotdot_across_symlinked_directory_is_refused() {
        let r = sample_repo();
        // "alias" -> "src/deep"; "alias/../x" physically means "src/x",
        // lexically "x". Must not be guessed.
        r.mkdir("src/deep");
        r.symlink("alias", "src/deep");
        r.write("src/x.json", "physical");
        r.write("x.json", "lexical");
        r.symlink("l.json", "alias/../x.json");
        let e = InputManifest::capture_with_env(&r.root, &[read("l.json")], vec![], &[], |_| None)
            .unwrap_err();
        assert!(
            matches!(e, ManifestError::SymlinkUnresolvable { .. }),
            "{e}"
        );
    }

    #[test]
    fn loop_is_an_error() {
        let r = sample_repo();
        r.symlink("loop1", "loop2");
        r.symlink("loop2", "loop1");
        let e = InputManifest::capture_with_env(&r.root, &[read("loop1")], vec![], &[], |_| None)
            .unwrap_err();
        assert!(matches!(e, ManifestError::SymlinkLoop(_)));
    }

    #[test]
    fn symlinked_directory_listing() {
        let r = sample_repo();
        r.symlink("fx", "fixtures");
        let m = capture(&r.root, &[readdir("fx")]);
        assert_eq!(entry(&m, "fx").kind, EntryKind::Symlink);
        assert_eq!(entry(&m, "fixtures").kind, EntryKind::DirListing);
        r.write("fixtures/new.json", "");
        assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fixtures"]);
    }

    #[test]
    fn dangling_link_probe_detects_target_appearing() {
        let r = sample_repo();
        r.symlink("opt.json", "fixtures/optional.json");
        let m = capture(&r.root, &[probe("opt.json")]);
        assert_eq!(entry(&m, "opt.json").kind, EntryKind::Symlink);
        assert_eq!(entry(&m, "fixtures/optional.json").kind, EntryKind::Absent);
        r.write("fixtures/optional.json", "{}");
        assert_eq!(
            whats(&diff(&m, &r.root)),
            vec!["entry:fixtures/optional.json"]
        );
        // And a dangling link cannot satisfy a Read.
        r.rm("fixtures/optional.json");
        let e =
            InputManifest::capture_with_env(&r.root, &[read("opt.json")], vec![], &[], |_| None)
                .unwrap_err();
        assert!(matches!(e, ManifestError::ReadMissing(_)));
    }

    #[test]
    fn read_through_symlinked_parent_directory_hashes_content_at_path() {
        let r = sample_repo();
        r.symlink("fx", "fixtures");
        let m = capture(&r.root, &[read("fx/b.json")]);
        assert_eq!(m.entries.len(), 1);
        assert_eq!(entry(&m, "fx/b.json").kind, EntryKind::File);
        // Repointing the directory at other content is caught via the content.
        r.write("fixtures2/b.json", "different");
        r.rm("fx");
        r.symlink("fx", "fixtures2");
        assert_eq!(whats(&diff(&m, &r.root)), vec!["entry:fx/b.json"]);
    }

    #[test]
    fn repo_root_given_via_symlink() {
        let r = sample_repo();
        let alias = r.root.parent().unwrap().join("alias-root");
        std::os::unix::fs::symlink(&r.root, &alias).unwrap();
        let m1 = capture(&r.root, &[readdir("."), read("fixtures/b.json")]);
        let m2 = capture(&alias, &[readdir("."), read("fixtures/b.json")]);
        assert_eq!(m1, m2);
        assert_eq!(entry(&m2, ".").kind, EntryKind::DirListing);
    }
}

// ------------------------------------------------------- case folding ----

fn manifest_of(paths: &[&str]) -> InputManifest {
    InputManifest {
        entries: paths.iter().map(|p| InputEntry::absent(rp(p))).collect(),
        externals: vec![],
        env: vec![],
    }
}

#[test]
fn case_collisions() {
    assert!(
        manifest_of(&["src/a.ts", "src/b.ts", "README.md"])
            .check_case_collisions()
            .is_ok()
    );
    assert!(
        manifest_of(&["src/a.ts", "src/a.ts"])
            .check_case_collisions()
            .is_ok()
    );
    assert!(manifest_of(&[]).check_case_collisions().is_ok());

    for pair in [
        ["src/A.ts", "src/a.ts"],
        ["README.md", "readme.md"],
        ["Src/a.ts", "src/b.ts"],   // directory prefixes collide
        ["src/x/a.ts", "src/X"],    // prefix vs full path
        ["stra\u{df}e", "STRASSE"], // full case folding
        ["\u{c9}t\u{e9}.ts", "\u{e9}t\u{e9}.ts"], // non-ASCII letters
    ] {
        let e = manifest_of(&pair).check_case_collisions().unwrap_err();
        assert!(matches!(e, ManifestError::CaseCollision { .. }), "{pair:?}");
    }
}

#[test]
fn case_collision_error_names_both_paths() {
    let e = manifest_of(&["b/Foo.ts", "b/foo.ts"])
        .check_case_collisions()
        .unwrap_err();
    match e {
        ManifestError::CaseCollision { a, b } => {
            let mut v = vec![a, b];
            v.sort();
            assert_eq!(v, vec!["b/Foo.ts", "b/foo.ts"]);
        }
        other => panic!("{other}"),
    }
}
