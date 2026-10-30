//! `ci`, `verify`, `init`, `push`, `fetch`, `prune`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::json;
use vci_adapter::Adapter;
use vci_attest::{AllowedSigners, Envelope, FrameExt as _, verify_envelope};
use vci_git::{AttestStore, SETUP_FILE};
use vci_store::{
    AttestationStore, Exchange, Prefetch, PushMode, PushStatus, Record, StoreError, StoreStatus,
    StoredEnvelope, decode_record,
};

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, template_for};
use crate::ctx::{VciPredicate, open_repo};
use crate::partition::{Partition, Share, Split};
use crate::plan::{PlanOptions, plan, print};
use crate::run::StoreMode;
use crate::util::{now_unix, parse_rfc3339, rfc3339};

pub const CI_SNIPPET: &str = include_str!("../../../examples/github-actions.yml");
pub const CI_SNIPPET_PYTEST: &str = include_str!("../../../examples/github-actions-pytest.yml");
pub const CI_SNIPPET_GO: &str = include_str!("../../../examples/github-actions-go.yml");
pub const CI_SNIPPET_CARGO: &str = include_str!("../../../examples/github-actions-cargo.yml");
pub const CI_SNIPPET_RAILS: &str = include_str!("../../../examples/github-actions-rails.yml");
pub const CI_SNIPPET_NODE_TEST: &str =
    include_str!("../../../examples/github-actions-node-test.yml");

/// `vci ci`'s options.
pub struct CiArgs {
    pub base_ref: Option<String>,
    pub audit_log: Option<Utf8PathBuf>,
    /// Attest what runs (as `vci run --key`).
    pub key: Option<Utf8PathBuf>,
    /// Attest what runs keylessly (as `vci run --oidc`), with this Sigstore
    /// instance.
    pub oidc: Option<String>,
    pub ttl: String,
    /// Publish the attestations afterwards (as `vci push`).
    pub push: bool,
    pub remote: Option<String>,
    /// Fetch attestations first (`--fetch [REMOTE]`; `Some(None)`: the
    /// default remote), while the projects are probed.
    pub fetch: Option<Option<String>>,
    /// `--project`: only these `[[projects]]` are planned and run (empty:
    /// every project).
    pub projects: Vec<String>,
    /// `--partition I/N`: run only this partition's share of the units the
    /// plan runs.
    pub partition: Option<Partition>,
}

pub fn ci(args: CiArgs) -> Result<i32> {
    let res = plan(&PlanOptions {
        base_ref: args.base_ref.clone(),
        only: None,
        fetch: args.fetch.clone(),
        projects: args.projects.clone(),
    })?;
    if let Some(w) = &res.fetch_failed {
        github_warning(w);
    }
    print(&res, "text")?;
    let (repo, root) = open_repo()?;
    let split = args
        .partition
        .map(|p| Split::new(&res, p, root.as_std_path()));
    if let Some(s) = &split {
        print_split(&res, s);
    }
    // `1/1` runs what `vci ci` without `--partition` runs, the same way.
    let run_split = split.as_ref().filter(|s| s.part.count > 1);
    let mut attested: Vec<crate::run::AttestedUnit> = Vec::new();
    let mut attest_errors: Vec<String> = Vec::new();
    // Why nothing was attested on purpose (and nothing is pushed).
    let mut not_attested: Option<String> = None;
    let how = match (&args.key, &args.oidc) {
        (Some(key), _) => Some(AttestWith::Key(key)),
        (None, Some(instance)) => Some(AttestWith::Oidc(instance)),
        (None, None) => None,
    };
    let attesting = how.is_some();
    // The publication gate: on a shared store, nothing is stored without
    // --push (docs/STORE-BACKENDS.md section 7).
    let store = crate::store::for_repo(&repo);
    let mode = store_mode(store.caps().shared_writes, args.push);
    let code = match how {
        None => run_plain(&res, &root, None, run_split)?,
        Some(how) => match run_attested(&res, how, &args.ttl, run_split, mode) {
            Ok(Attempt::Ran(mut out)) => {
                // Units the store could not take are reported as errors are.
                out.errors.append(&mut out.store_failures);
                for e in &out.errors {
                    github_warning(&format!("attesting: {e}"));
                }
                let mut code = out.exit;
                // Projects whose tests did not run with the collectors (no
                // verdict yet): run them, and only them, without attesting.
                // What already ran is neither run again nor forgotten.
                if !out.unrun.is_empty() {
                    let c = run_plain(&res, &root, Some(&out.unrun), run_split)?;
                    if code == 0 {
                        code = c;
                    }
                }
                attested = out.attested;
                attest_errors = out.errors;
                code
            }
            Ok(Attempt::NotAttested(why)) => {
                github_warning(&format!("not attesting: {why}"));
                not_attested = Some(why);
                run_plain(&res, &root, None, run_split)?
            }
            // Nothing has run yet (run_units reports what fails after a test
            // ran in RunOutcome::errors instead).
            Err(e) => {
                let msg = format!(
                    "could not run the tests with attestation ({e:#}); running them without attesting"
                );
                github_warning(&msg);
                attest_errors.push(format!("{e:#}"));
                not_attested = Some(msg);
                run_plain(&res, &root, None, run_split)?
            }
        },
    };
    let push_wanted = args.push && not_attested.is_none();
    if attesting {
        let kind = store.kind();
        let stored_where = if mode == StoreMode::SignOnly {
            format!(" (not stored: the {kind} store is shared and --push was not given)")
        } else if store.exchange().is_none() {
            format!(" (stored in the {kind} store)")
        } else {
            " (stored locally; publish with `vci push`)".to_owned()
        };
        eprintln!(
            "vci ci: {} unit(s) attested{}",
            attested.len(),
            if push_wanted {
                ""
            } else if args.push {
                " (nothing to push)"
            } else {
                &stored_where
            }
        );
    }
    let pushed = if push_wanted {
        // Best effort: CI's result is the tests', never the publication's.
        match push_with(&*store, args.remote.as_deref(), false, OnRemote::Ignore) {
            Ok(_) => Some(true),
            Err(e) => {
                github_warning(&format!(
                    "could not push attestations{}: {e:#}",
                    args.remote
                        .as_deref()
                        .map(|r| format!(" to {}", redact_userinfo(r)))
                        .unwrap_or_default()
                ));
                Some(false)
            }
        }
    } else if attesting && mode == StoreMode::SignOnly {
        // Signed, and published nowhere.
        Some(false)
    } else {
        None
    };

    let now = now_unix();
    let log = json!({
        "time": rfc3339(now),
        "head": repo.head_commit().ok(),
        "baseRef": res.base_ref,
        "baseCommit": res.base_commit,
        "runAll": res.run_all,
        "warnings": res.warnings,
        "projects": res.projects,
        "skipped": res.skipped().map(|f| json!({
            "testId": f.test_id,
            "project": f.project,
            "reason": f.reason,
            "by": f.by,
        })).collect::<Vec<_>>(),
        "ran": res.files.iter().enumerate()
            .filter(|(k, f)| split.as_ref().map_or(!f.skip, |s| s.runs(*k)))
            .map(|(_, f)| json!({"testId": f.test_id, "project": f.project, "reason": f.reason})).collect::<Vec<_>>(),
        "partition": split.as_ref().map(|s| json!({
            "index": s.part.index,
            "count": s.part.count,
            "units": s.units(),
            "total": s.total(),
            "unlisted": res.projects.iter().zip(&s.shares)
                .filter(|(_, sh)| **sh == Share::Whole)
                .map(|(p, _)| job_label(p)).collect::<Vec<_>>(),
        })),
        "attested": attested.iter().map(|a| {
            let mut u = json!({"testId": a.test_id, "project": a.project});
            if !a.stored {
                u["stored"] = false.into();
            }
            u
        }).collect::<Vec<_>>(),
        "attestErrors": attest_errors,
        "notAttested": not_attested,
        "pushed": pushed,
        "exitCode": code,
    });
    let path = args
        .audit_log
        .unwrap_or_else(|| root.join(format!(".vci/out/audit-{now}.json")));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&log)?)?;
    eprintln!("vci ci: audit log written to {path}");
    Ok(code)
}

/// A warning for the log and, on GitHub Actions, an annotation (a workflow
/// command: one line, `%`, CR and LF escaped).
fn github_warning(msg: &str) {
    let escaped = msg
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    println!("::warning title=vci::{escaped}");
}

/// `--partition`: what this partition runs, after the plan (stdout).
fn print_split(res: &crate::plan::PlanResult, s: &Split) {
    let part = s.part;
    println!(
        "partition {part}: {} of {} units to run",
        s.units(),
        s.total()
    );
    // Each job lists on its own and cannot know whether another one listed
    // what it could not: it runs that whole (fail open), so those tests may
    // run in more than one job but never in none.
    if res.projects.is_empty() {
        github_warning(&format!(
            "partition {part}: no project could be read: everything runs in this partition (as in every partition that cannot read one)"
        ));
    }
    for (p, share) in res.projects.iter().zip(&s.shares) {
        let label = if res.multi {
            job_label(p)
        } else {
            "the project".to_owned()
        };
        if *share == Share::Whole {
            github_warning(&format!(
                "partition {part}: {label} runs everything and its test files could not be listed: it runs whole in this partition (as in every partition that cannot list it)"
            ));
        }
    }
}

/// What `vci ci` runs of project `i` of the plan.
enum Work {
    /// Every test of the project (it runs everything).
    All,
    /// These units (indexes into the plan's files), of `.1` units the
    /// project runs over all partitions (without `--partition`: the same).
    Units(Vec<usize>, usize),
}

fn work(res: &crate::plan::PlanResult, i: usize, split: Option<&Split>) -> Work {
    match split.and_then(|s| s.shares.get(i)) {
        Some(Share::Whole) => Work::All,
        Some(Share::Units { mine, of }) => Work::Units(mine.clone(), *of),
        None if res.run_all.is_some() || res.projects[i].run_all.is_some() => Work::All,
        None => {
            let units: Vec<usize> = res
                .files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.project_idx == i && !f.skip)
                .map(|(k, _)| k)
                .collect();
            let n = units.len();
            Work::Units(units, n)
        }
    }
}

/// `vci ci`'s line for a project with units to run (`what`: ` of <label>
/// (<adapter>)` or empty; `how`: e.g. `attesting`).
fn running_line(n: usize, of: usize, what: &str, split: Option<&Split>, how: &str) -> String {
    match split {
        None if how.is_empty() => format!("vci ci: running {n} test file(s){what}"),
        None => format!("vci ci: running {n} test file(s){what} ({how})"),
        Some(s) => format!(
            "vci ci: running {n} of {of} test file(s){what} (partition {}{})",
            s.part,
            if how.is_empty() {
                String::new()
            } else {
                format!(", {how}")
            }
        ),
    }
}

/// `vci ci`'s line for a project with no unit to run here.
fn nothing_line(of: usize, what: &str, split: Option<&Split>) -> String {
    match split {
        Some(s) if of > 0 => format!(
            "vci ci: none of the {of} test file(s){what} to run is in partition {}; nothing to run here",
            s.part
        ),
        _ => format!(
            "vci ci: every test file{what} is covered by a valid attestation; nothing to run"
        ),
    }
}

/// The label `vci ci` prints for a project of a multi-project plan.
fn job_label(p: &crate::plan::ProjectPlan) -> String {
    if p.name.is_empty() {
        p.path.clone()
    } else {
        p.name.clone()
    }
}

/// What [`run_attested`] did.
enum Attempt {
    /// The tests ran with the collectors (`RunOutcome::unrun`: those that
    /// could not).
    Ran(crate::run::RunOutcome),
    /// Nothing ran: attesting is not possible or not allowed here (why).
    NotAttested(String),
}

/// `vci ci --key`: run what the plan leaves through `vci run`'s code path
/// (collectors on, inputs recorded, attestations signed and stored). Every
/// unit of a project that runs everything (`run_all`) is attested: that is
/// the run the next commit's plan reuses. An `Err` means nothing ran.
/// How `vci ci` attests: `--key` or `--oidc`.
enum AttestWith<'a> {
    Key(&'a Utf8Path),
    /// The Sigstore instance.
    Oidc(&'a str),
}

fn run_attested(
    res: &crate::plan::PlanResult,
    how: AttestWith<'_>,
    ttl: &str,
    split: Option<&Split>,
    mode: StoreMode,
) -> Result<Attempt> {
    let Some(config) = res.config.clone().filter(|_| !res.projects.is_empty()) else {
        return Ok(Attempt::NotAttested("no project could be read".into()));
    };
    // A key that cannot be read (or a job without an OIDC token) fails
    // before anything runs.
    let keyless;
    let signing = match how {
        AttestWith::Key(key) => {
            let signing = crate::keys::load(key).with_context(|| format!("--key {key}"))?;
            if let Some(why) = attest_refusal(res, &signing.blob) {
                return Ok(Attempt::NotAttested(why));
            }
            crate::run::Signing::Key(Some(key))
        }
        AttestWith::Oidc(instance) => {
            keyless = crate::run::keyless_signer(instance)?;
            if let Some(why) = keyless_attest_refusal(res, keyless.identity()) {
                return Ok(Attempt::NotAttested(why));
            }
            crate::run::Signing::Oidc(&keyless)
        }
    };
    let multi = res.projects.len() > 1;
    let mut units: std::collections::BTreeMap<usize, Option<std::collections::BTreeSet<String>>> =
        Default::default();
    for (i, p) in res.projects.iter().enumerate() {
        let what = if multi {
            format!(" of {} ({})", job_label(p), p.adapter)
        } else {
            String::new()
        };
        let (ix, of) = match work(res, i, split) {
            Work::All => {
                eprintln!("vci ci: running all tests{what} (attesting)");
                units.insert(i, None);
                continue;
            }
            Work::Units(ix, of) => (ix, of),
        };
        let ids: std::collections::BTreeSet<String> =
            ix.iter().map(|&k| res.files[k].test_id.clone()).collect();
        if ids.is_empty() {
            eprintln!("{}", nothing_line(of, &what, split));
        } else {
            eprintln!("{}", running_line(ids.len(), of, &what, split, "attesting"));
            units.insert(i, Some(ids));
        }
    }
    if units.is_empty() {
        return Ok(Attempt::Ran(Default::default()));
    }
    let (repo, root) = open_repo()?;
    crate::run::run_units(
        repo,
        root,
        config,
        crate::run::Selection::Units(units),
        signing,
        ttl,
        None,
        mode,
    )
    .map(Attempt::Ran)
}

/// How `vci ci` uses the store: on a store whose writes every machine sees
/// at once ([`vci_store::Caps::shared_writes`]), it signs but stores
/// nothing unless `--push` was given, so that, as with git-meta, nothing
/// leaves a CI job without `--push` (docs/STORE-BACKENDS.md section 7).
pub(crate) fn store_mode(shared_writes: bool, push: bool) -> StoreMode {
    if shared_writes && !push {
        StoreMode::SignOnly
    } else {
        StoreMode::Write
    }
}

/// [`attest_refusal`] for `vci ci --oidc`: the job's identity signs as the
/// principals of the base identities.toml entries it matches. An identity
/// that matches none attests (nothing will trust it), with a warning.
fn keyless_attest_refusal(
    res: &crate::plan::PlanResult,
    identity: &vci_attest::keyless::CertIdentity,
) -> Option<String> {
    // The base commit's identities (as the plan read them).
    let principals = res
        .base_commit
        .as_deref()
        .and_then(|base| {
            let (repo, _) = open_repo().ok()?;
            let bytes = repo
                .show_file(base, vci_attest::keyless::IDENTITIES_FILE)
                .ok()??;
            vci_attest::keyless::Identities::parse(std::str::from_utf8(&bytes).ok()?).ok()
        })
        .map(|ids| ids.principals(identity));
    if principals.as_ref().is_some_and(Vec::is_empty) {
        github_warning(&format!(
            "this job's identity ({}) matches no [[identity]] in the base commit's {}: its attestations will not be trusted",
            identity.describe(),
            vci_attest::keyless::IDENTITIES_FILE
        ));
    }
    let off: Vec<&crate::plan::ProjectPlan> =
        res.projects.iter().filter(|p| !p.on_no_skip_ref).collect();
    if off.is_empty() {
        return None;
    }
    let Some(principals) = principals else {
        return Some(format!(
            "the current ref does not match policy.no_skip_refs and the base commit's {} could not be read, so whom this job signs as is unknown",
            vci_attest::keyless::IDENTITIES_FILE
        ));
    };
    for p in off {
        if let Some(principal) = principals
            .iter()
            .find(|pr| p.no_skip_refs_except.contains(pr) && !p.attest_on_any_ref.contains(pr))
        {
            return Some(format!(
                "this job's identity ({}) signs as {principal}, which policy.no_skip_refs_except{} lets skip on policy.no_skip_refs (e.g. main), but the current ref does not match policy.no_skip_refs: attestations made here would let main skip tests that never ran on main. Narrow that [[identity]] (ref, event) to main, or list {principal} in policy.attest_on_any_ref",
                identity.describe(),
                if res.multi {
                    format!(" of {}", job_label(p))
                } else {
                    String::new()
                }
            ));
        }
    }
    None
}

/// Why `vci ci --key` must not attest here, if it must not: the key signs as
/// a principal that `policy.no_skip_refs_except` lets skip on
/// `policy.no_skip_refs` (main), and the current ref does not match
/// `no_skip_refs` (a pull request, a feature branch). Such a run executes
/// code main never ran (the branch's tests, dependencies, workflow), and
/// main would skip those units after a merge on the strength of it. Also
/// refused off those refs when the base commit's allowed_signers cannot be
/// read (whom the key signs as is unknown).
///
/// `policy.attest_on_any_ref` names the principals this does not apply to:
/// a pull request's run then attests with them, and the protected refs
/// skip what it ran (the repository's own pull requests, a repository
/// secret forks never get, authors trusted with that).
///
/// This is a guard against a misconfigured workflow, not a security
/// boundary: a branch that can read the key can sign anything with it. The
/// boundary is not handing the key to such runs (a secret of a GitHub
/// Environment restricted to the default branch).
fn attest_refusal(res: &crate::plan::PlanResult, key_blob: &[u8]) -> Option<String> {
    let off: Vec<&crate::plan::ProjectPlan> =
        res.projects.iter().filter(|p| !p.on_no_skip_ref).collect();
    if off.is_empty() {
        return None;
    }
    let Some(allowed) = &res.allowed else {
        return Some(
            "the current ref does not match policy.no_skip_refs and the base commit's allowed_signers could not be read, so whom the key signs as is unknown".into(),
        );
    };
    let principals: Vec<&str> = allowed
        .entries()
        .iter()
        .filter(|e| !e.cert_authority && e.key.to_bytes().is_ok_and(|b| b == key_blob))
        .map(|e| e.principals.as_str())
        .collect();
    for p in off {
        if let Some(principal) = principals.iter().find(|pr| {
            p.no_skip_refs_except.iter().any(|x| x == *pr)
                && !p.attest_on_any_ref.iter().any(|x| x == *pr)
        }) {
            return Some(format!(
                "the key signs as {principal}, which policy.no_skip_refs_except{} lets skip on policy.no_skip_refs (e.g. main), but the current ref does not match policy.no_skip_refs: attestations made here would let main skip tests that never ran on main. Pass this key only to runs on main (a GitHub Environment secret restricted to the default branch), or give other refs a key whose principal is not in no_skip_refs_except",
                if res.multi {
                    format!(" of {}", job_label(p))
                } else {
                    String::new()
                }
            ));
        }
    }
    None
}

/// `vci ci` without `--key`: run what the plan leaves with the adapters'
/// plain runs (no collectors, nothing signed); with `only`, of those
/// projects only; with `split`, this partition's share. Returns the exit
/// code.
fn run_plain(
    res: &crate::plan::PlanResult,
    root: &Utf8Path,
    only: Option<&std::collections::BTreeSet<usize>>,
    split: Option<&Split>,
) -> Result<i32> {
    // What to run, per project. With no project information at all (the
    // repository layout could not be read), run the default project.
    // (label, adapter, child env, files to run; None = everything, of how
    // many over all partitions)
    type Job = (
        String,
        Box<dyn Adapter>,
        vci_adapter::ChildEnv,
        Option<(Vec<String>, usize)>,
    );
    let mut jobs: Vec<Job> = Vec::new();
    // (In every partition: none can know whether another read the layout.)
    if res.projects.is_empty() && only.is_none() {
        let adapter = vci_adapter::adapter_for("vitest", root)?;
        jobs.push(("default project".into(), adapter, None, None));
    }
    let multi = res.projects.len() > 1;
    for (i, p) in res.projects.iter().enumerate() {
        if only.is_some_and(|o| !o.contains(&i)) {
            continue;
        }
        let label = job_label(p);
        let files = match work(res, i, split) {
            Work::All => None,
            Work::Units(ix, of) => {
                let run: Vec<String> = ix.iter().map(|&k| res.files[k].file.clone()).collect();
                // node-test: when nothing of the project is skipped, its test
                // script runs as is (its own file set, `npm run test`); not
                // when a partition runs a share of it.
                if split.is_none()
                    && p.adapter == "node-test"
                    && !run.is_empty()
                    && !res.skipped().any(|f| f.project_idx == i)
                {
                    None
                } else {
                    Some((run, of))
                }
            }
        };
        let adapter = vci_adapter::adapter_for_with(&p.adapter, &p.dir, &p.adapter_options)?;
        let env = p.child_env.as_ref().and_then(|c| c.to_child_env());
        jobs.push((label, adapter, env, files));
    }
    let mut code: Option<i32> = Some(0);
    let multi = jobs.len() > 1 || multi;
    for (label, adapter, env, files) in &jobs {
        let what = if multi {
            format!(" of {label} ({})", adapter.name())
        } else {
            String::new()
        };
        let c = match files {
            None => {
                eprintln!("vci ci: running all tests{what}");
                adapter.run_plain(&[], env)?
            }
            Some((run, of)) if run.is_empty() => {
                eprintln!("{}", nothing_line(*of, &what, split));
                Some(0)
            }
            Some((run, of)) => {
                eprintln!("{}", running_line(run.len(), *of, &what, split, ""));
                adapter.run_plain(run, env)?
            }
        };
        match (code, c) {
            (Some(0), c) => code = c,
            (Some(_), None) => code = None,
            _ => {}
        }
    }
    Ok(code.unwrap_or(1))
}

/// `vci verify`: the envelope's signature against the trust root, its
/// predicate, expiry, and the input manifest it records: inline (before vci
/// 1.9.0) or the one it references, read from `--manifest FILE` or else
/// from the local git-meta store, whose recomputed root must be the signed
/// input root.
pub fn verify(
    envelope_path: &Utf8Path,
    trust: VerifyTrust<'_>,
    base_ref: Option<&str>,
    manifest_file: Option<&Utf8Path>,
    print_envelope: bool,
) -> Result<i32> {
    let bytes = if envelope_path == "-" {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut v)?;
        v
    } else {
        std::fs::read(envelope_path).with_context(|| format!("reading {envelope_path}"))?
    };
    // A format-3 record (the text frame a store holds since 2.9) is
    // verified through the DSSE envelope rebuilt from it: the statement
    // bytes exactly as signed and the signature re-armored, so that the
    // checks below see what they see for a stored envelope. Its
    // descriptor is kept for the manifest line. An envelope's bytes are
    // used as read, as before.
    let (bytes, descriptor) = match decode_record(&bytes) {
        Ok(Record::FormatThree(frame)) => (frame.to_stored_json(), Some(frame.descriptor)),
        // An envelope, or no record at all: the envelope parser says why.
        Ok(Record::FormatOne(_)) | Err(_) => (bytes, None),
    };
    if print_envelope {
        use std::io::Write as _;
        Envelope::from_json(&bytes).with_context(|| format!("{envelope_path} is not a record"))?;
        let mut out = std::io::stdout().lock();
        out.write_all(&bytes)?;
        if !bytes.ends_with(b"\n") {
            out.write_all(b"\n")?;
        }
        return Ok(0);
    }
    let now = now_unix();
    let mut note = None;
    let keyless = vci_attest::keyless::material_from_json(&bytes)?;
    if let Some((why, source)) = trust.unpinned(keyless.is_some()) {
        println!("INVALID: {why}");
        println!("  trust root: {source}");
        return Ok(1);
    }
    let (verified, source) = match keyless {
        Some(m) => {
            let env = Envelope::from_json(&bytes)?;
            let (ids, ids_source) = trust_file(
                trust.identities,
                vci_attest::keyless::IDENTITIES_FILE,
                base_ref,
            )?;
            let (root, root_source) = trust_file(
                trust.trusted_root,
                vci_attest::keyless::TRUSTED_ROOT_FILE,
                base_ref,
            )?;
            let ids = vci_attest::keyless::Identities::parse(&ids)
                .map_err(anyhow::Error::msg)
                .with_context(|| ids_source.clone())?;
            let root = vci_attest::keyless::TrustedRoot::parse(&root)
                .map_err(anyhow::Error::msg)
                .with_context(|| root_source.clone())?;
            let r = vci_attest::keyless::verify_keyless(&env, &m, &ids, &root, now).map(|k| {
                note = Some(format!(
                    "  keyless: signed at {} (timestamp by {}){}",
                    rfc3339(k.timestamp.time),
                    k.timestamp.authority,
                    k.identity
                        .run
                        .as_deref()
                        .map(|r| format!(", run {r}"))
                        .unwrap_or_default()
                ));
                k.verified
            });
            (r, format!("{ids_source}, {root_source}"))
        }
        None => verify_ssh(&bytes, trust.allowed_signers, base_ref, now)?,
    };
    match verified {
        Err(e) => {
            println!("INVALID: {e}");
            println!("  trust root: {source}");
            Ok(1)
        }
        Ok(v) => verified_details(v, &source, note, manifest_file, now, descriptor.as_deref()),
    }
}

/// Where `vci verify` reads trust from (default: the files at `--base-ref`,
/// or HEAD). Trust given on the command line is the only trust: once any of
/// these is given, an envelope whose kind needs a file that was not given is
/// INVALID instead of trusted on the repository's files.
pub struct VerifyTrust<'a> {
    pub allowed_signers: Option<&'a Utf8Path>,
    pub identities: Option<&'a Utf8Path>,
    pub trusted_root: Option<&'a Utf8Path>,
}

impl VerifyTrust<'_> {
    /// Why an envelope (keyless or SSH-signed) cannot be verified with the
    /// trust pinned on the command line, and the files that were given;
    /// `None` when the trust it needs was given, or none was (the
    /// repository's files are then used).
    fn unpinned(&self, keyless: bool) -> Option<(String, String)> {
        let given: Vec<String> = [
            ("--allowed-signers", self.allowed_signers),
            ("--identities", self.identities),
            ("--trusted-root", self.trusted_root),
        ]
        .into_iter()
        .filter_map(|(flag, p)| p.map(|p| format!("{flag} {p}")))
        .collect();
        if given.is_empty() {
            return None;
        }
        let missing: Vec<&str> = if keyless {
            [
                ("--identities", self.identities),
                ("--trusted-root", self.trusted_root),
            ]
            .into_iter()
            .filter(|(_, p)| p.is_none())
            .map(|(flag, _)| flag)
            .collect()
        } else if self.allowed_signers.is_none() {
            vec!["--allowed-signers"]
        } else {
            Vec::new()
        };
        if missing.is_empty() {
            return None;
        }
        let kind = if keyless {
            "signed keylessly (Sigstore), which --identities and --trusted-root trust"
        } else {
            "SSH-signed, which --allowed-signers trusts"
        };
        Some((
            format!(
                "the envelope is {kind}; trust was pinned on the command line without {} (the repository's files are not used then)",
                missing.join(" and ")
            ),
            given.join(", "),
        ))
    }
}

/// A trust file's text and a description of where it came from: `explicit`,
/// else `file` at `base_ref` (or HEAD).
fn trust_file(
    explicit: Option<&Utf8Path>,
    file: &str,
    base_ref: Option<&str>,
) -> Result<(String, String)> {
    match explicit {
        Some(p) => Ok((
            std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?,
            p.to_string(),
        )),
        None => {
            let (repo, _) = open_repo()?;
            let rev = base_ref.unwrap_or("HEAD");
            let sha = repo.resolve(rev)?;
            let b = repo
                .show_file(&sha, file)?
                .with_context(|| format!("{file} is missing at {rev}"))?;
            Ok((String::from_utf8(b)?, format!("{file} at {rev} ({sha})")))
        }
    }
}

/// A verification's result and where its trust came from.
type Checked = (
    Result<vci_attest::Verified, vci_attest::VerifyError>,
    String,
);

/// `vci verify` of an SSH-signed envelope.
fn verify_ssh(
    bytes: &[u8],
    allowed_signers: Option<&Utf8Path>,
    base_ref: Option<&str>,
    now: i64,
) -> Result<Checked> {
    let (text, source) = match allowed_signers {
        Some(p) => (
            std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?,
            p.to_string(),
        ),
        None => {
            let (repo, _) = open_repo()?;
            let rev = base_ref.unwrap_or("HEAD");
            let sha = repo.resolve(rev)?;
            let b = repo
                .show_file(&sha, ALLOWED_SIGNERS_FILE)?
                .with_context(|| format!("{ALLOWED_SIGNERS_FILE} is missing at {rev}"))?;
            (
                String::from_utf8(b)?,
                format!("{ALLOWED_SIGNERS_FILE} at {rev} ({sha})"),
            )
        }
    };
    let allowed = AllowedSigners::parse(&text)?;
    let env = Envelope::from_json(bytes)?;
    Ok((verify_envelope(&env, &allowed, now), source))
}

/// `vci verify`'s report of a verified envelope; the exit code. A v2
/// predicate (a format-3 record, whose `descriptor` is the frame's) is
/// reported through the same lines, read from the resolved view over the
/// hdr and tables objects of the repository's store.
fn verified_details(
    v: vci_attest::Verified,
    source: &str,
    note: Option<String>,
    manifest_file: Option<&Utf8Path>,
    now: i64,
    descriptor: Option<&[u8]>,
) -> Result<i32> {
    println!("VALID signature by {} ({})", v.principal, v.fingerprint);
    println!("  trust root: {source}");
    if let Some(n) = note {
        println!("{n}");
    }
    println!("  predicateType: {}", v.statement.predicate_type);
    if v.statement.predicate_type == vci_core::PREDICATE_TYPE_V2 {
        return verified_details_v2(&v, manifest_file, now, descriptor);
    }
    match serde_json::from_value::<VciPredicate>(v.statement.predicate.clone()) {
        Ok(p) => {
            println!("  test: {}", p.core.test_id);
            println!("  repo id: {}", p.core.repo_id);
            println!("  commit: {} (dirty: {})", p.core.commit, p.core.tree_dirty);
            println!(
                "  result: {} ({} tests)",
                p.core.result.state, p.core.result.tests
            );
            println!("  input root: {}", p.core.input_root);
            let manifest_ok = match verify_manifest(&p, manifest_file) {
                Ok(line) => {
                    println!("  manifest: {line}");
                    true
                }
                Err(line) => {
                    println!("  manifest: INVALID: {line}");
                    false
                }
            };
            let expired = parse_rfc3339(&p.core.expires_at)
                .map(|e| e <= now)
                .unwrap_or(true);
            println!(
                "  issued {}, expires {}{}",
                p.core.issued_at,
                p.core.expires_at,
                if expired { " (EXPIRED)" } else { "" }
            );
            Ok(if expired || !manifest_ok { 1 } else { 0 })
        }
        Err(e) => {
            println!("  predicate is not a vci test predicate: {e}");
            Ok(1)
        }
    }
}

/// The run's hdr, tables and shape objects as `vci verify` needs them for
/// a v2 predicate, read from the repository's store (the shape is the
/// descriptor's, when a descriptor is at hand); or why they could not be.
struct RunObjects {
    hdr: Vec<u8>,
    tables: Vec<u8>,
    /// `None` without a descriptor; otherwise the shape's bytes, or why
    /// they could not be taken (missing, or not the id's bytes), which
    /// fails the manifest line alone: the hdr and tables still resolve.
    shape: Option<Result<Vec<u8>, String>>,
}

fn run_objects(
    p: &vci_core::VciPredicateV2,
    descriptor: Option<&[u8]>,
) -> Result<RunObjects, String> {
    let shape_id = descriptor
        .map(|d| {
            vci_core::Descriptor::shape_id(d)
                .map(|id| vci_core::objects::hex32(&id))
                .map_err(|e| format!("the record's descriptor: {e}"))
        })
        .transpose()?;
    let (repo, _) = open_repo().map_err(|e| {
        format!("the hdr and tables objects are in the repository's attestation store, and {e:#}")
    })?;
    let store = crate::store::for_repo(&repo);
    let mut ids: Vec<&str> = vec![&p.hdr, &p.tables];
    ids.extend(shape_id.as_deref());
    if store.caps().lazy_values {
        // Fetched lazily (see `vci fetch`); a failure reads as not fetched.
        let _ = store.prefetch(Prefetch::Objects { ids: &ids });
    }
    let got = store.get_objects(&ids).map_err(|e| {
        format!(
            "reading the run's objects from the {} store: {e}",
            store.kind()
        )
    })?;
    // Every object is taken by the id asked for, recomputed over the bytes
    // the store returned (docs/CONTRACTS.md: a reader recomputes the id of
    // every object it loads), never by the store's own id column alone:
    // the hdr and tables are checked again by `Context::decode`, the shape
    // nowhere else.
    let take = |id: &str, what: &str| {
        let o = got.iter().find(|o| o.id == id).ok_or_else(|| {
            format!(
                "the {what} object {id} is not in the {} store{}",
                store.kind(),
                if store.caps().lazy_values {
                    " (run `vci fetch`)"
                } else {
                    ""
                }
            )
        })?;
        let found = vci_core::objects::hex32(&vci_core::object_id(&o.bytes));
        if found != id {
            return Err(format!(
                "the {what} object {id} is corrupt (its BLAKE3 is {found})"
            ));
        }
        Ok(o.bytes.clone())
    };
    Ok(RunObjects {
        hdr: take(&p.hdr, "hdr")?,
        tables: take(&p.tables, "tables")?,
        shape: shape_id.as_deref().map(|id| take(id, "shape")),
    })
}

/// [`verified_details`] of a v2 predicate: the same lines, from the
/// resolved view over the run's objects; the manifest line from
/// `--manifest FILE` (the compact JSON of the resolved manifest with its
/// hashes, whose root must be the signed input root) or, without one,
/// the set the descriptor resolves to against the run's shape and tables
/// (the root is not recomputed then: the attested hashes are in no
/// signed object).
fn verified_details_v2(
    v: &vci_attest::Verified,
    manifest_file: Option<&Utf8Path>,
    now: i64,
    descriptor: Option<&[u8]>,
) -> Result<i32> {
    let p = match serde_json::from_value::<vci_core::VciPredicateV2>(v.statement.predicate.clone())
    {
        Ok(p) => p,
        Err(e) => {
            println!("  predicate is not a vci test predicate (v2): {e}");
            return Ok(1);
        }
    };
    let input_root = v
        .statement
        .subject
        .first()
        .and_then(|s| s.digest.get("blake3"))
        .cloned()
        .unwrap_or_default();
    println!("  test: {}", p.test_id);
    let objects = run_objects(&p, descriptor);
    let ctx = objects
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|o| vci_core::Context::decode(&p, &o.hdr, &o.tables).map_err(|e| e.to_string()));
    let resolved = ctx
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|c| c.resolve(&p, &input_root).map_err(|e| e.to_string()));
    match &resolved {
        Ok(r) => println!("  repo id: {}", r.repo_id()),
        Err(why) => println!("  repo id: (in the hdr object {}: {why})", p.hdr),
    }
    println!("  commit: {} (dirty: {})", p.commit, p.tree_dirty);
    println!("  result: {} ({} tests)", p.result.state, p.result.tests);
    println!("  input root: {input_root}");
    let manifest_ok =
        match verify_manifest_v2(&input_root, manifest_file, descriptor, &objects, &ctx) {
            Ok(line) => {
                println!("  manifest: {line}");
                true
            }
            Err(line) => {
                println!("  manifest: INVALID: {line}");
                false
            }
        };
    let expired = parse_rfc3339(&p.expires_at)
        .map(|e| e <= now)
        .unwrap_or(true);
    println!(
        "  issued {}, expires {}{}",
        p.issued_at,
        p.expires_at,
        if expired { " (EXPIRED)" } else { "" }
    );
    Ok(if expired || !manifest_ok || resolved.is_err() {
        1
    } else {
        0
    })
}

/// The manifest line of a v2 predicate ([`verified_details_v2`]).
fn verify_manifest_v2(
    input_root: &str,
    file: Option<&Utf8Path>,
    descriptor: Option<&[u8]>,
    objects: &Result<RunObjects, String>,
    ctx: &Result<vci_core::Context, String>,
) -> Result<String, String> {
    if let Some(f) = file {
        let bytes = std::fs::read(f).map_err(|e| format!("reading {f}: {e}"))?;
        let m = vci_core::InputManifest::from_compact(&bytes)
            .or_else(|e| serde_json::from_slice(&bytes).map_err(|_| e))
            .map_err(|e| format!("{f}: {e}"))?;
        let root = m.root();
        if root != input_root {
            return Err(format!(
                "{f}: its root {root} is not the signed input root {input_root}"
            ));
        }
        return Ok(format!(
            "{} entries, {} externals, {} env (root verified; {f})",
            m.entries.len(),
            m.externals.len(),
            m.env.len()
        ));
    }
    let Some(d) = descriptor else {
        return Err(
            "the envelope was given without its record's descriptor (pass the format-3 record, or --manifest FILE)"
                .to_owned(),
        );
    };
    let ctx = ctx.as_ref().map_err(Clone::clone)?;
    let shape_bytes = objects
        .as_ref()
        .map_err(Clone::clone)?
        .shape
        .as_ref()
        .ok_or_else(|| "the shape object could not be read".to_owned())?
        .as_deref()
        .map_err(Clone::clone)?;
    let shape = vci_core::Shape::decode(shape_bytes).map_err(|e| format!("shape object: {e}"))?;
    let descriptor =
        vci_core::Descriptor::decode(d, &ctx.tables).map_err(|e| format!("descriptor: {e}"))?;
    let m = descriptor
        .resolve(&shape, &ctx.tables)
        .map_err(|e| format!("descriptor: {e}"))?;
    Ok(format!(
        "{} entries, {} externals, {} env (set resolved from the run's shape object; root not recomputed: the attested hashes are in no signed object, pass --manifest FILE with the manifest)",
        m.set.len(),
        m.externals.len(),
        m.env.len()
    ))
}

/// `vci init --oidc`: `.vci/identities.toml` trusting this repository's
/// workflow runs on its default branch (pushes) as principal
/// `github-actions`, and the Sigstore trust root from `gh attestation
/// trusted-root`. An existing identities.toml is left alone; the trust root
/// is refreshed.
fn init_oidc(root: &Utf8Path) -> Result<()> {
    use vci_attest::keyless::{IDENTITIES_FILE, TRUSTED_ROOT_FILE};
    let ids = root.join(IDENTITIES_FILE);
    if ids.exists() {
        eprintln!("vci init: {ids} exists, leaving it alone");
    } else {
        let repository = git_out(root, &["remote", "get-url", "origin"])
            .as_deref()
            .and_then(github_repository)
            .context("vci init --oidc: origin is not a GitHub repository (owner/name could not be read from its URL)")?;
        let branch = git_out(
            root,
            &["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"],
        )
        .and_then(|b| b.strip_prefix("origin/").map(str::to_owned))
        .unwrap_or_else(|| "main".to_owned());
        let workflows: Vec<String> = std::fs::read_dir(root.join(".github/workflows"))
            .map(|d| {
                d.filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
                    .collect()
            })
            .unwrap_or_default();
        let workflow = match workflows.as_slice() {
            [one] => format!(".github/workflows/{one}"),
            _ => ".github/workflows/*".to_owned(),
        };
        let text = format!(
            "# CI identities whose keyless attestations (vci ci --oidc) are trusted, read\n\
             # from the base commit like allowed_signers. Every field must match the\n\
             # certificate Fulcio issued for the job's OIDC token; workflow, ref, event,\n\
             # environment and runner_environment are globs. The principal is the name\n\
             # policy lists use (no_skip_refs_except, attest_on_any_ref).\n\
             [[identity]]\n\
             principal = \"github-actions\"\n\
             issuer = \"https://token.actions.githubusercontent.com\"\n\
             repository = {}\n\
             workflow = {}{}\n\
             ref = {}\n\
             event = \"push\"\n",
            toml_str(&repository),
            toml_str(&workflow),
            if workflows.len() == 1 {
                ""
            } else {
                "   # narrow this to the workflow that runs vci ci --oidc"
            },
            toml_str(&format!("refs/heads/{branch}")),
        );
        vci_attest::keyless::Identities::parse(&text).map_err(anyhow::Error::msg)?;
        std::fs::create_dir_all(ids.parent().expect("has parent"))?;
        std::fs::write(&ids, text)?;
        eprintln!(
            "vci init: wrote {ids} ({repository}, {workflow}, refs/heads/{branch}, principal github-actions)"
        );
    }
    let trust = root.join(TRUSTED_ROOT_FILE);
    match std::process::Command::new("gh")
        .args(["attestation", "trusted-root"])
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8(o.stdout).context("gh attestation trusted-root")?;
            vci_attest::keyless::TrustedRoot::parse(&text)
                .map_err(anyhow::Error::msg)
                .context("gh attestation trusted-root printed no usable trust root")?;
            std::fs::write(&trust, text)?;
            eprintln!("vci init: wrote {trust} (gh attestation trusted-root)");
        }
        r => {
            let why = match r {
                Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_owned(),
                Err(e) => e.to_string(),
            };
            eprintln!(
                "vci init: note: could not run `gh attestation trusted-root` ({why}); write {trust} with it before committing"
            );
        }
    }
    Ok(())
}

fn git_out(root: &Utf8Path, args: &[&str]) -> Option<String> {
    let o = std::process::Command::new("git")
        .arg("-C")
        .arg(root.as_str())
        .args(args)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&o.stdout).trim().to_owned();
    (o.status.success() && !s.is_empty()).then_some(s)
}

/// `owner/name` of a GitHub remote URL (`git@github.com:o/n.git`,
/// `https://github.com/o/n`, `ssh://git@github.com/o/n.git`).
fn github_repository(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.split_once("github.com/").map(|(_, r)| r))?;
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = rest.split('/');
    let (o, n) = (parts.next()?, parts.next()?);
    (parts.next().is_none() && !o.is_empty() && !n.is_empty()).then(|| format!("{o}/{n}"))
}

/// The input manifest of a verified predicate, as one line for `vci
/// verify`: what it holds and where it came from, or why it is not usable.
fn verify_manifest(p: &VciPredicate, file: Option<&Utf8Path>) -> Result<String, String> {
    let (m, source) = match (&p.core.manifest, &p.core.manifest_ref) {
        (Some(m), None) => (m.clone(), "inline".to_owned()),
        (None, Some(r)) if *r != p.core.input_root => {
            return Err(format!(
                "manifestRef {r} is not the input root {}",
                p.core.input_root
            ));
        }
        (None, Some(r)) => match file {
            Some(f) => {
                let bytes = std::fs::read(f).map_err(|e| format!("reading {f}: {e}"))?;
                // A file on top of a base (vci 2.1.8) reads the base from
                // the repository's store when there is one.
                let m = vci_core::InputManifest::from_compact_with(&bytes, |b| {
                    let (repo, _) = open_repo().map_err(|e| {
                        vci_core::ManifestError::Compact(format!("base manifest {b}: {e:#}"))
                    })?;
                    let store = crate::store::for_repo(&repo);
                    let _ = store.prefetch(Prefetch::Manifests { roots: &[b] });
                    match store.manifest(b) {
                        Ok(Some(s)) if s.error.is_none() => Ok(s.bytes),
                        _ => Err(vci_core::ManifestError::MissingBase(b.to_owned())),
                    }
                })
                .or_else(|e| serde_json::from_slice(&bytes).map_err(|_| e))
                .map_err(|e| format!("{f}: {e}"))?;
                (m, f.to_string())
            }
            None => {
                let (repo, _) = open_repo().map_err(|e| {
                    format!("manifest {r} is stored in the repository's git-meta store, and {e:#} (pass --manifest FILE)")
                })?;
                let store = crate::store::for_repo(&repo);
                // Fetched lazily (see `vci fetch`); a failure reads as not fetched.
                let _ = store.prefetch(Prefetch::Manifests {
                    roots: &[r.as_str()],
                });
                let stored = store.manifest(r);
                let m = crate::plan::load_manifest(&*store, r, stored, |b| store.manifest(b))
                    .map_err(|(what, actual)| format!("{what} ({actual})"))?;
                (
                    m,
                    format!("{} project {}", store.kind(), vci_store::manifest_key(r)),
                )
            }
        },
        (Some(_), Some(_)) => return Err("both manifest and manifestRef are set".to_owned()),
        (None, None) => return Err("neither manifest nor manifestRef is set".to_owned()),
    };
    let root = m.root();
    if root != p.core.input_root {
        return Err(format!(
            "{source}: its root {root} is not the signed input root {}",
            p.core.input_root
        ));
    }
    Ok(format!(
        "{} entries, {} externals, {} env (root verified; {source})",
        m.entries.len(),
        m.externals.len(),
        m.env.len()
    ))
}

pub fn init(
    key: Option<&Utf8Path>,
    principal: Option<String>,
    project: Option<String>,
    adapter_name: Option<String>,
    install: bool,
    meta_url: Option<String>,
    oidc: bool,
) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let cfg_path = root.join(CONFIG_FILE);
    let adapter_name = adapter_name.unwrap_or_else(|| "vitest".into());
    if !vci_adapter::ADAPTERS.contains(&adapter_name.as_str()) {
        bail!("unsupported adapter {adapter_name:?}");
    }
    if cfg_path.exists() {
        eprintln!("vci init: {cfg_path} exists, leaving it alone");
    } else {
        let mut text = template_for(&adapter_name).to_owned();
        if let Some(p) = &project {
            text = text.replace("project = \".\"", &format!("project = {}", toml_str(p)));
        }
        crate::config::Config::parse(&text)?;
        std::fs::write(&cfg_path, text)?;
        eprintln!("vci init: wrote {cfg_path}");
    }
    let signers = root.join(ALLOWED_SIGNERS_FILE);
    std::fs::create_dir_all(signers.parent().expect("has parent"))?;
    let mut existing = std::fs::read_to_string(&signers).unwrap_or_default();
    if existing.is_empty() {
        existing.push_str("# principal namespaces=\"vci-attest\" key-type base64-key\n");
    }
    if let Some(k) = key {
        let sk = crate::keys::load(k)?;
        let principal = match principal {
            Some(p) => p,
            None => git_email(&root).unwrap_or_else(|| "vci@localhost".into()),
        };
        if principal.chars().any(char::is_whitespace) {
            bail!("principal must not contain whitespace");
        }
        if existing.contains(&sk.public) {
            eprintln!("vci init: key already in {signers}");
        } else {
            existing.push_str(&format!(
                "{principal} namespaces=\"vci-attest\" {}\n",
                sk.public
            ));
            eprintln!("vci init: added {principal} to {signers}");
        }
    }
    std::fs::write(&signers, existing)?;
    if crate::store::for_repo(&repo).kind() == "git-meta" {
        setup_git_meta(&repo, &root, meta_url.as_deref())?;
    }
    if oidc {
        init_oidc(&root)?;
    }

    let config = crate::ctx::working_tree_config(&root)?;
    let specs = config.project_specs();
    if specs.iter().any(|s| s.adapter == "pytest") {
        for s in specs.iter().filter(|s| s.adapter == "pytest") {
            let dir = root.join(&s.rel);
            if let Err(e) = vci_adapter::find_py_plugin(&dir) {
                eprintln!("vci init: note: {e}");
            }
        }
        if std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!(
                "vci init: note: the pytest adapter runs tests with `uv run --locked`; install uv"
            );
        }
    }
    if specs.iter().any(|s| s.adapter == "go")
        && std::process::Command::new(
            std::env::var_os(vci_adapter::GO_BIN_ENV)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "go".into()),
        )
        .arg("version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!(
            "vci init: note: the go adapter runs `go test`; install Go or set {} to the go binary",
            vci_adapter::GO_BIN_ENV
        );
    }
    if specs.iter().any(|s| s.adapter == "cargo")
        && std::process::Command::new(
            std::env::var_os(vci_adapter::CARGO_BIN_ENV)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "cargo".into()),
        )
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!(
            "vci init: note: the cargo adapter runs `cargo test`; install Rust or set {} to the cargo binary",
            vci_adapter::CARGO_BIN_ENV
        );
    }
    if specs.iter().any(|s| s.adapter == "rails") {
        for s in specs.iter().filter(|s| s.adapter == "rails") {
            let dir = root.join(&s.rel);
            if let Err(e) = vci_adapter::find_ruby_collector(&dir) {
                eprintln!("vci init: note: {e}");
            }
            if !dir.join("bin/rails").is_file() && !dir.join("spec").is_dir() {
                eprintln!(
                    "vci init: note: {} has no bin/rails; the rails adapter's project must be the Rails application root (or a Ruby project with RSpec and a spec/ directory)",
                    dir
                );
            }
            // Which runner: the setting, else detected (see the template).
            let opts = s.adapter_options();
            let adapter = vci_adapter::RailsAdapter::new(&dir).with_runner(opts.rails_runner);
            let has = |p: &str| adapter.runner_of(p);
            let runners = match (has("test/x_test.rb"), has("spec/x_spec.rb")) {
                (
                    Some(vci_adapter::RailsRunner::Minitest),
                    Some(vci_adapter::RailsRunner::Rspec),
                ) => "Minitest (test/**/*_test.rb) and RSpec (every other file RSpec lists)",
                (_, Some(vci_adapter::RailsRunner::Rspec)) => "RSpec",
                _ => "Minitest",
            };
            eprintln!(
                "vci init: {}: the rails adapter will run {runners} (set runner = \"minitest\" or \"rspec\" in vci.toml to choose)",
                s.rel
            );
        }
        if std::process::Command::new(
            std::env::var_os(vci_adapter::RUBY_BIN_ENV)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "ruby".into()),
        )
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
        {
            eprintln!(
                "vci init: note: the rails adapter runs `ruby bin/rails test` and RSpec with Ruby; install the Ruby in .ruby-version or set {} to the ruby binary",
                vci_adapter::RUBY_BIN_ENV
            );
        }
    }
    for s in specs.iter().filter(|s| s.adapter == "node-test") {
        let dir = root.join(&s.rel);
        if let Err(e) = vci_adapter::find_node_test_collector(&dir) {
            eprintln!("vci init: note: {e} (needed by `vci run`, not by `vci ci`)");
        }
        let adapter = vci_adapter::NodeTestAdapter::new(&dir).with_options(s.node_test.clone());
        match adapter.invocation() {
            Ok(inv) => eprintln!(
                "vci init: {}: tests from {}: {}{}",
                s.rel,
                inv.source,
                inv.command_line(),
                if inv.patterns.is_empty() {
                    " (node:test's default patterns)"
                } else {
                    ""
                }
            ),
            Err(e) => eprintln!(
                "vci init: warning: {}: {e}; set test_script, or test_globs and node_args, in vci.toml",
                s.rel
            ),
        }
    }
    let vitest: Vec<_> = specs.iter().filter(|s| s.adapter == "vitest").collect();
    if vitest.is_empty() {
        let snippet = if specs.iter().all(|s| s.adapter == "node-test") {
            CI_SNIPPET_NODE_TEST
        } else if specs.iter().all(|s| s.adapter == "go") {
            CI_SNIPPET_GO
        } else if specs.iter().all(|s| s.adapter == "cargo") {
            CI_SNIPPET_CARGO
        } else if specs.iter().all(|s| s.adapter == "rails") {
            CI_SNIPPET_RAILS
        } else {
            CI_SNIPPET_PYTEST
        };
        println!("{COMMIT_HINT} GitHub Actions example:\n");
        println!("{snippet}");
        return Ok(0);
    }
    let project_dir = root.join(&vitest[0].rel);
    if install {
        let spec = std::env::var(vci_adapter::JS_PLUGIN_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|p| format!("file:{p}"))
            .unwrap_or_else(|| "@vci/vitest".into());
        eprintln!("vci init: npm install --save-dev {spec} (in {project_dir})");
        match std::process::Command::new("npm")
            .args(["install", "--save-dev", &spec])
            .current_dir(&project_dir)
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("vci init: warning: npm install failed ({s}); install {spec} yourself")
            }
            Err(e) => {
                eprintln!("vci init: warning: could not run npm ({e}); install {spec} yourself")
            }
        }
    }
    if vci_adapter::find_js_plugin(&project_dir).is_err() {
        eprintln!(
            "vci init: note: @vci/vitest not found; set {} or install it",
            vci_adapter::JS_PLUGIN_ENV
        );
    }
    println!("{COMMIT_HINT} GitHub Actions example:\n");
    println!("{CI_SNIPPET}");
    Ok(0)
}

const COMMIT_HINT: &str = "Commit vci.toml, .vci/allowed_signers and .git-meta.";

/// Point git-meta at the metadata remote: write `.git-meta` (the file
/// `git meta setup` reads) if there is none, and configure the local
/// metadata remote. Attestations are exchanged there on `refs/meta/main`.
fn setup_git_meta(repo: &vci_git::Repo, root: &Utf8Path, meta_url: Option<&str>) -> Result<()> {
    let file = root.join(SETUP_FILE);
    let existing = vci_git::meta::read_setup_url(&file)?;
    let origin = std::process::Command::new("git")
        .args(["-C", root.as_str(), "config", "--get", "remote.origin.url"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty());
    match (
        &existing,
        meta_url.map(str::to_owned).or_else(|| origin.clone()),
    ) {
        (Some(u), _) => eprintln!("vci init: {file} exists (url: {u}), leaving it alone"),
        (None, Some(u)) => {
            std::fs::write(&file, format!("url: {u}\n"))?;
            eprintln!("vci init: wrote {file} (git-meta metadata remote: {u})");
        }
        (None, None) => {
            eprintln!(
                "vci init: note: no origin remote and no --meta-url; attestations stay local until a git-meta remote is configured (`git meta remote add <url>`)"
            );
            return Ok(());
        }
    }
    let store = AttestStore::new(repo);
    let before = store.remote_names().unwrap_or_default();
    match store.ensure_remote(meta_url) {
        Ok(name) => {
            eprintln!(
                "vci init: git-meta remote {name:?} configured; `vci push` / `vci fetch` (or `git meta push` / `git meta pull`) exchange attestations on refs/meta/main"
            );
            if !before.contains(&name)
                && let Some(note) = shared_config_note(repo, &name)
            {
                eprintln!("{note}");
            }
        }
        Err(e) => eprintln!("vci init: note: could not configure a git-meta remote: {e}"),
    }
    Ok(())
}

/// In a linked git worktree, a remote is written to the repository's shared
/// config (git keeps one `config` for all worktrees of a repository unless
/// `extensions.worktreeConfig` is used, and remotes are never per-worktree).
/// That is git's behaviour, but `vci init` run in a worktree then changes
/// the main checkout too: say so.
fn shared_config_note(repo: &vci_git::Repo, name: &str) -> Option<String> {
    let common = repo.linked_worktree_common_dir()?;
    Some(format!(
        "vci init: note: this is a linked git worktree: the remote {name:?} was added to the repository's shared config ({}), so every worktree of this repository (the main checkout included) now has it",
        common.join("config")
    ))
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn git_email(root: &Utf8Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C", root.as_str(), "config", "--get", "user.email"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn print_exchange_messages(warnings: &[String], notes: &[String]) {
    for n in notes {
        eprintln!("vci: note: {n}");
    }
    for w in warnings {
        eprintln!("vci: warning: {w}");
    }
}

/// Say which URL a metadata remote resolved without `--remote` points at:
/// it may come from `.git-meta` in the checkout.
fn print_default_remote(kind: &str, ex: &dyn Exchange, remote: Option<&str>, name: &str) {
    if remote.is_none()
        && let Some(location) = ex.remote_location(name)
    {
        eprintln!("vci: {kind} remote {name} is {location}");
    }
}

/// "local" or "shared", for the messages of a store without an exchange.
fn sharing(store: &dyn AttestationStore) -> &'static str {
    if store.caps().shared_writes {
        "shared"
    } else {
        "local"
    }
}

/// `scheme://user:secret@host/...` without the credentials.
pub(crate) fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let host_end = rest.find('/').unwrap_or(rest.len());
    match rest[..host_end].rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

/// What `vci push` and `vci ci --push` do with `--remote` on a store that
/// has no remote ([`AttestationStore::exchange`] is `None`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnRemote {
    /// Refuse it (`vci push`, exit 2).
    Refuse,
    /// Warn and go on (`vci ci --push`: a workflow that changes store keeps
    /// working).
    Ignore,
}

pub fn push(remote: Option<&str>, rewrite_history: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = crate::store::for_repo(&repo);
    push_with(&*store, remote, rewrite_history, OnRemote::Refuse)
}

/// `vci push`'s work (also `vci ci --push`): publish the store's local
/// writes through its exchange; a store without one says that there is
/// nothing to push.
fn push_with(
    store: &dyn AttestationStore,
    remote: Option<&str>,
    rewrite_history: bool,
    on_remote: OnRemote,
) -> Result<i32> {
    let kind = store.kind();
    let Some(ex) = store.exchange() else {
        // A store that cannot be used (it could not be selected or opened,
        // or is unreachable) has not stored anything either: say so.
        store.status()?;
        if let Some(r) = remote {
            if on_remote == OnRemote::Refuse {
                return Err(StoreError::Unsupported {
                    backend: kind,
                    operation: "a remote",
                }
                .into());
            }
            eprintln!(
                "vci: warning: the {kind} store has no remote: --remote {} is ignored",
                redact_userinfo(r)
            );
        }
        if rewrite_history {
            return Err(StoreError::Unsupported {
                backend: kind,
                operation: "rewriting history",
            }
            .into());
        }
        eprintln!(
            "vci: nothing to push: the {kind} store is {}; attestations were stored when vci run made them",
            sharing(store)
        );
        return Ok(0);
    };
    let mode = if rewrite_history {
        PushMode::RewriteHistory
    } else {
        PushMode::Merge
    };
    let out = ex.push(remote, mode)?;
    let point = ex.exchange_point();
    print_default_remote(kind, ex, remote, &out.remote);
    print_exchange_messages(&out.warnings, &out.notes);
    match out.status {
        PushStatus::Pushed => {
            eprintln!("vci: pushed {kind} metadata ({point}) to {}", out.remote)
        }
        PushStatus::UpToDate => eprintln!(
            "vci: nothing to push: {}'s {point} already has every local attestation",
            out.remote
        ),
        PushStatus::NothingStored => eprintln!(
            "vci: nothing to push: no attestations are stored locally (run `vci run` first)"
        ),
        // The status is vci-store's, non-exhaustive: git-meta's push never
        // ends otherwise.
        _ => eprintln!("vci: push to {} finished", out.remote),
    }
    Ok(0)
}

pub fn fetch(remote: Option<&str>) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = crate::store::for_repo(&repo);
    for l in fetch_messages(&*store, remote)? {
        eprintln!("{l}");
    }
    Ok(0)
}

/// `vci fetch`'s work (also `vci plan --fetch` and `vci ci --fetch`): fetch
/// and materialize the remote's attestations; what `vci fetch` prints, as
/// lines for stderr. A store without an exchange has nothing to fetch: it
/// says so (a `--remote` is refused).
pub fn fetch_messages(store: &dyn AttestationStore, remote: Option<&str>) -> Result<Vec<String>> {
    let kind = store.kind();
    let Some(ex) = store.exchange() else {
        store.status()?;
        if remote.is_some() {
            return Err(StoreError::Unsupported {
                backend: kind,
                operation: "a remote",
            }
            .into());
        }
        let n = store.count()?;
        return Ok(vec![format!(
            "vci: the {kind} store at {} is {}: nothing to fetch ({n} attestations stored)",
            store.location(),
            sharing(store)
        )]);
    };
    let out = ex.fetch(remote)?;
    let mut lines = Vec::new();
    if remote.is_none()
        && let Some(location) = ex.remote_location(&out.remote)
    {
        lines.push(format!("vci: {kind} remote {} is {location}", out.remote));
    }
    lines.extend(out.notes.iter().map(|n| format!("vci: note: {n}")));
    lines.extend(out.warnings.iter().map(|w| format!("vci: warning: {w}")));
    let n = store.count()?;
    if out.found {
        lines.push(format!(
            "vci: fetched {kind} metadata from {} ({n} attestations stored locally)",
            out.remote
        ));
    } else {
        lines.push(format!(
            "vci: {} has no {kind} metadata yet ({}); {n} attestations stored locally",
            out.remote,
            ex.exchange_point()
        ));
    }
    Ok(lines)
}

/// `vci store info`: which store this repository uses, each setting with
/// where it came from (secrets redacted), what the store can do, whether it
/// exists and how many attestations it holds, as text or JSON on stdout.
/// Exits 0 when the store can be read (also when nothing is stored yet);
/// otherwise prints what it knows and fails (exit 2) with the reason.
pub fn store_info(json_out: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = crate::store::for_repo(&repo);
    let sel = crate::store::selection_of(&repo);
    let settings = sel
        .as_ref()
        .map(vci_store::select::Selection::describe)
        .unwrap_or_default();
    let caps = store.caps();
    let exchange = store.exchange().map(|e| e.exchange_point().to_owned());
    let status = store.status();
    let (count, count_error) = match status.as_ref().map(|_| store.count()) {
        Ok(Ok(n)) => (Some(n), None),
        Ok(Err(e)) => (None, Some(e)),
        Err(_) => (None, None),
    };
    let error = status.as_ref().err().or(count_error.as_ref());
    let yes = |b: bool| if b { "yes" } else { "no" };
    if json_out {
        let (state, advice, version) = match &status {
            Ok(StoreStatus::Ready { schema_version }) => ("ready", None, *schema_version),
            Ok(StoreStatus::Absent { advice }) => ("absent", Some(advice.clone()), None),
            Err(_) => ("unavailable", None, None),
        };
        let doc = json!({
            "kind": store.kind(),
            "location": store.location(),
            "settings": settings.iter().map(|l| json!({
                "name": l.name,
                "value": l.value,
                "source": l.source.to_string(),
            })).collect::<Vec<_>>(),
            "caps": {
                "sharedWrites": caps.shared_writes,
                "lazyValues": caps.lazy_values,
                "keepsHints": caps.keeps_hints,
            },
            "exchange": exchange,
            "status": state,
            "advice": advice,
            "schemaVersion": version,
            "count": count,
            "error": error.map(|e| json!({
                "code": e.code(),
                "transient": e.is_transient(),
                "message": e.to_string(),
            })),
            "warnings": sel.as_ref().map(|s| s.warnings.clone()).unwrap_or_default(),
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else {
        println!("store: {}", store.kind());
        println!("location: {}", store.location());
        if settings.is_empty() {
            println!("settings: not resolved (see the error)");
        } else {
            println!("settings:");
            for l in &settings {
                println!("  {}: {} ({})", l.name, l.value, l.source);
            }
        }
        println!(
            "capabilities: shared writes {}, lazy values {}, keeps hints {}",
            yes(caps.shared_writes),
            yes(caps.lazy_values),
            yes(caps.keeps_hints)
        );
        match &exchange {
            Some(point) => println!("exchange: vci fetch and vci push, on {point}"),
            None => println!("exchange: none (vci fetch and vci push have nothing to do)"),
        }
        match &status {
            Ok(StoreStatus::Ready {
                schema_version: Some(v),
            }) => println!("status: ready (schema version {v})"),
            Ok(StoreStatus::Ready { .. }) => println!("status: ready"),
            Ok(StoreStatus::Absent { advice }) => {
                println!("status: absent: nothing is stored yet ({advice})")
            }
            Err(_) => println!("status: unavailable"),
        }
        if let Some(n) = count {
            println!("attestations: {n}");
        }
    }
    match error {
        Some(e) => Err(anyhow::anyhow!("{e}")),
        None => Ok(0),
    }
}

/// `vci prune`'s options.
pub struct PruneArgs {
    pub dry_run: bool,
    pub superseded: bool,
    pub keep: usize,
    /// `--objects`: only the object passes, leaving every attestation and
    /// input manifest alone.
    pub objects_only: bool,
    /// `--older-than DAYS`: the state-object age for this run (default
    /// `[store] explain_hashes_days`).
    pub older_than: Option<u32>,
}

/// What a prune of the attestations found and did.
#[derive(Default)]
struct Pruned {
    expired: usize,
    kept: usize,
    unreadable: usize,
    /// Candidates the columns or the key hints named whose signed
    /// statement did not confirm them (left alone; a store with columns
    /// only).
    unconfirmed: usize,
    older: usize,
    /// Manifests the remaining attestations reference; `None` once one of
    /// them cannot be read.
    referenced: Option<BTreeSet<String>>,
}

/// `vci prune`: delete attestations that have expired (git-meta tombstones,
/// published by the next `vci push`). Only the claimed expiry is read; an
/// envelope that cannot be parsed is left alone. Then delete the stored input
/// manifests no remaining attestation references (`manifestRef`; one with
/// its manifest inline references none), unless an attestation's value, or
/// the `manifestRef` of one left alone, cannot be read (what it references
/// is then unknown).
///
/// Since 2.9 (store format 3): on a store that keeps listing columns
/// (SQLite, PostgreSQL, libSQL) the listing's columns and key hints say
/// which records are expired or beyond `--keep` without a value read, and
/// those candidates (and, for `--keep`, the rest of their unit's records)
/// alone are read, their signed statement deciding before a delete
/// ([`prune_by_columns`]); a format-1 row, or one without columns, is read
/// as before, and so is every row while the store holds an input manifest
/// (a vci 2.8 may have written a format-1 value under a frame's columns).
/// Then the objects no attestation references and the state objects older
/// than `explain_hashes_days` (or `--older-than`) go; `--objects` does
/// only that.
pub fn prune(args: PruneArgs) -> Result<i32> {
    let PruneArgs {
        dry_run,
        superseded,
        keep,
        objects_only,
        older_than,
    } = args;
    let (repo, _) = open_repo()?;
    let store = crate::store::for_repo(&repo);
    // A store that cannot be used fails here, before anything is read.
    store.status()?;
    // What to say about a value the store does not hold here yet.
    let fetch_hint = if store.caps().lazy_values {
        " (run `vci fetch`)"
    } else {
        ""
    };
    let now = now_unix();
    // Of a unit's attestations by one signer, the `keep` issued last are
    // kept (`--superseded`: one), and any made on a tree some ref still has
    // at its tip (2.1.12); an older one vouches for inputs the tree no
    // longer has (or soon will not), and every stored attestation costs
    // each plan a download (vci 2.2: vex kept five per file).
    // `--superseded` keeps the documented meaning: only the newest, whatever
    // the branch; `--keep` also keeps one made on a tree some ref still has
    // at its tip, as `vci run`'s supersession does (2.1.12).
    let keep = if superseded { 1 } else { keep.max(1) };
    let live_trees = if superseded {
        BTreeSet::new()
    } else {
        repo.live_trees().unwrap_or_default()
    };
    let mut removed = 0usize;
    if !objects_only {
        let p = if store.caps().columns {
            prune_by_columns(&*store, dry_run, keep, &live_trees, now)?
        } else {
            prune_by_values(&*store, dry_run, keep, &live_trees, now)?
        };
        let manifests = prune_manifests(&*store, dry_run, p.referenced, fetch_hint)?;
        eprintln!(
            "vci prune: {} expired{}{}, {} current, {} unreadable (left alone){}",
            p.expired,
            if superseded {
                format!(", {} superseded", p.older)
            } else {
                String::new()
            },
            if dry_run { " (dry run)" } else { "" },
            p.kept,
            p.unreadable,
            if p.unconfirmed > 0 {
                format!(", {} unconfirmed (left alone)", p.unconfirmed)
            } else {
                String::new()
            }
        );
        eprintln!(
            "vci prune: {manifests} unreferenced input manifest(s){}",
            if dry_run { " (dry run)" } else { " removed" }
        );
        removed += p.expired + p.older + manifests;
    }
    if store.caps().objects {
        let days = older_than.unwrap_or_else(|| {
            crate::store::selection_of(&repo)
                .map(|s| s.explain_hashes_days.value)
                .unwrap_or(vci_store::select::DEFAULT_EXPLAIN_HASHES_DAYS)
        });
        removed += prune_objects(&*store, dry_run, days)?;
    } else if objects_only {
        eprintln!(
            "vci prune: the {} store keeps no objects of store format 3; nothing to do",
            store.kind()
        );
    }
    // A store with an exchange (git-meta) publishes its deletions on push;
    // SQLite, PostgreSQL and libSQL removed theirs at once, and their `vci
    // push` has nothing to do.
    if removed > 0 && !dry_run && store.exchange().is_some() {
        eprintln!(
            "vci prune: run `vci push` to publish the deletions (`vci push --rewrite-history` also drops the deleted values from what a fetch downloads)"
        );
    }
    Ok(0)
}

/// The attestations pass over every value (a store without listing
/// columns, git-meta): every value is read, as vci 2.0 to 2.8 did.
fn prune_by_values(
    store: &dyn AttestationStore,
    dry_run: bool,
    keep: usize,
    live_trees: &BTreeSet<String>,
    now: i64,
) -> Result<Pruned> {
    let mut p = Pruned {
        referenced: Some(BTreeSet::new()),
        ..Pruned::default()
    };
    let mut by_unit: BTreeMap<(String, String), Vec<(i64, String)>> = BTreeMap::new();
    let mut current = Vec::new();
    // Every attestation's payload is read: fetch the ones not fetched yet
    // (on a large store, what a fetch downloaded before vci 2.0). One that
    // cannot be fetched is unreadable, and left alone.
    match store.prefetch(Prefetch::Attestations) {
        Ok(h) if h.unresolved > 0 => eprintln!(
            "vci prune: warning: {} attestation value(s) could not be fetched{}",
            h.unresolved,
            h.error.map(|e| format!(": {e}")).unwrap_or_default()
        ),
        Ok(_) => {}
        Err(e) => eprintln!("vci prune: warning: could not fetch the attestations' values: {e:#}"),
    }
    for e in store.read_all()? {
        if e.error.is_some() {
            p.referenced = None;
        }
        match record_meta(&e.bytes) {
            Some(m) if m.expires_at <= now => {
                p.expired += 1;
                if dry_run {
                    println!("would remove {} {}", e.target, e.key);
                } else {
                    store.remove(vec![e.clone()])?;
                    println!("removed {} {}", e.target, e.key);
                }
            }
            Some(m) => {
                p.kept += 1;
                by_unit
                    .entry((m.test_id.clone(), e.signer.clone()))
                    .or_default()
                    .push((m.issued_at, e.key.clone()));
                current.push((m, e));
            }
            None => {
                p.unreadable += 1;
                // Left alone, so whatever it references stays: the
                // manifest it names when that much can be read, else none
                // is removed.
                let r = unreadable_manifest_ref(&e.bytes);
                match (r, p.referenced.as_mut()) {
                    (Some(r), Some(set)) => {
                        set.insert(r);
                    }
                    (Some(_), None) => {}
                    (None, _) => p.referenced = None,
                }
            }
        }
    }
    // The keys kept per unit and signer: the `keep` newest.
    let keep_keys = keep_newest(&mut by_unit, keep);
    for (m, e) in current {
        let live = m.tree.as_deref().is_some_and(|t| live_trees.contains(t));
        if keep_keys.contains(&e.key) || live {
            if let (Some(r), Some(set)) = (&m.manifest_ref, p.referenced.as_mut()) {
                set.insert(r.clone());
            }
            continue;
        }
        p.older += 1;
        p.kept -= 1;
        if dry_run {
            println!("would remove {} {} (superseded)", e.target, e.key);
        } else {
            store.remove(vec![e.clone()])?;
            println!("removed {} {} (superseded)", e.target, e.key);
        }
    }
    Ok(p)
}

/// What a listed record is read for on a store with columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The columns do not describe it (a format-1 row, which has none; a
    /// record without a hint; a frame put without columns), or the store
    /// is in the migration window: read and treated as before.
    Read,
    /// The `expires` column says it has expired: a candidate the signed
    /// statement must confirm.
    Expired,
    /// Its unit and signer have a row beyond `keep` by the hints (or a row
    /// read whole): the signed statements order the group.
    Contested,
}

/// The attestations pass on a store with listing columns (STORE-V2 section
/// 2.1 "Prune"): `list_all` with the columns gives every record's expiry
/// (the `expires` column, from the statement the writer signed) and, from
/// the key hint, its issue time and tree, without a value read. A record
/// the columns do not describe (a format-1 row, which has none; a record
/// without a hint; a frame put without columns) is read and treated as
/// before, and so is every record while the store holds an input manifest
/// (the migration window of section 5: a vci 2.8 that reuses a frame's
/// slot leaves the frame's columns beside its format-1 value, and only the
/// value says what the row is and which manifest it references). The
/// expired candidates are then read and deleted only when the signed
/// statement agrees ([`confirm_expired`]); a unit and signer with a record
/// beyond `keep` by the hints has every described record read, and the
/// signed `issuedAt`, `expiresAt` and tree order the group as they do on a
/// store without columns. The columns pre-filter and order, the value
/// decides (`decode_record` by its first byte), so a store writer who
/// edits a column or a key's hint can cause extra value reads (the row's,
/// or its unit's), never a wrong deletion.
fn prune_by_columns(
    store: &dyn AttestationStore,
    dry_run: bool,
    keep: usize,
    live_trees: &BTreeSet<String>,
    now: i64,
) -> Result<Pruned> {
    let all = store.list_all()?;
    let refs: Vec<&StoredEnvelope> = all.iter().collect();
    let columns = store.columns(&refs)?;
    let window = !store.manifest_roots()?.is_empty();
    let mut described: Vec<(StoredEnvelope, i64)> = Vec::new();
    let mut rows: Vec<(StoredEnvelope, Role)> = Vec::new();
    // The units and signers whose records the signed statements order.
    let mut contested: BTreeSet<(String, String)> = BTreeSet::new();
    for (e, c) in all.into_iter().zip(columns) {
        match (c.format, c.expires, e.issued) {
            (Some(3), Some(expires), Some(_)) if !window => described.push((e, expires)),
            _ => {
                contested.insert((e.test_key.clone(), e.signer.clone()));
                rows.push((e, Role::Read));
            }
        }
    }
    let mut p = Pruned {
        referenced: Some(BTreeSet::new()),
        ..Pruned::default()
    };
    // The described records: expired by the column, to confirm; the rest
    // ordered by the hints, and the groups with a record beyond `keep`
    // (not on a tree at some ref's tip) read whole.
    let mut by_hint: BTreeMap<(String, String), Vec<(i64, String)>> = BTreeMap::new();
    let mut hinted: Vec<StoredEnvelope> = Vec::new();
    for (e, expires) in described {
        if expires <= now {
            rows.push((e, Role::Expired));
        } else {
            by_hint
                .entry((e.test_key.clone(), e.signer.clone()))
                .or_default()
                .push((e.issued.expect("described"), e.key.clone()));
            hinted.push(e);
        }
    }
    let keep_by_hint = keep_newest(&mut by_hint, keep);
    let mut hint_doomed: BTreeSet<String> = BTreeSet::new();
    for e in &hinted {
        let live = e
            .tree
            .as_deref()
            .is_some_and(|t16| live_trees.iter().any(|t| t.starts_with(t16)));
        if !keep_by_hint.contains(&e.key) && !live {
            hint_doomed.insert(e.key.clone());
            contested.insert((e.test_key.clone(), e.signer.clone()));
        }
    }
    for e in hinted {
        if contested.contains(&(e.test_key.clone(), e.signer.clone())) {
            rows.push((e, Role::Contested));
        } else {
            // Current without a read: outside the window no manifest
            // exists for it to reference.
            p.kept += 1;
        }
    }
    // One read of everything the statements must decide.
    if !rows.is_empty() {
        let mut refs: Vec<&mut StoredEnvelope> = rows.iter_mut().map(|(e, _)| e).collect();
        store.read_values(&mut refs)?;
    }
    let mut by_unit: BTreeMap<(String, String), Vec<(i64, String)>> = BTreeMap::new();
    let mut current: Vec<(EnvelopeMeta, StoredEnvelope)> = Vec::new();
    let unreadable = |p: &mut Pruned, e: &StoredEnvelope| {
        p.unreadable += 1;
        // Left alone, so whatever it references stays: the manifest it
        // names when that much can be read, else none is removed.
        let r = unreadable_manifest_ref(&e.bytes);
        match (r, p.referenced.as_mut()) {
            (Some(r), Some(set)) => {
                set.insert(r);
            }
            (Some(_), None) => {}
            (None, _) => p.referenced = None,
        }
    };
    for (e, role) in rows {
        if e.error.is_some() {
            p.referenced = None;
        }
        if role == Role::Expired {
            match confirm_expired(&e, now) {
                Ok(()) => {
                    p.expired += 1;
                    delete(store, dry_run, &e, "")?;
                }
                Err(Left::Unreadable) => unreadable(&mut p, &e),
                Err(Left::Unconfirmed(m)) => {
                    p.unconfirmed += 1;
                    p.kept += 1;
                    eprintln!(
                        "vci prune: {} {}: left alone: its signed statement does not confirm the store's columns",
                        e.target, e.key
                    );
                    if let (Some(r), Some(set)) = (&m.manifest_ref, p.referenced.as_mut()) {
                        set.insert(r.clone());
                    }
                }
            }
            continue;
        }
        match record_meta(&e.bytes) {
            Some(m) if m.expires_at <= now => {
                p.expired += 1;
                delete(store, dry_run, &e, "")?;
            }
            Some(m) => {
                p.kept += 1;
                by_unit
                    .entry((e.test_key.clone(), e.signer.clone()))
                    .or_default()
                    .push((m.issued_at, e.key.clone()));
                current.push((m, e));
            }
            None => unreadable(&mut p, &e),
        }
    }
    // The keys kept per unit and signer: the `keep` newest by the signed
    // issue time.
    let keep_keys = keep_newest(&mut by_unit, keep);
    for (m, e) in current {
        let live = m.tree.as_deref().is_some_and(|t| live_trees.contains(t));
        if keep_keys.contains(&e.key) || live {
            if let (Some(r), Some(set)) = (&m.manifest_ref, p.referenced.as_mut()) {
                set.insert(r.clone());
            }
            if hint_doomed.contains(&e.key) {
                p.unconfirmed += 1;
                eprintln!(
                    "vci prune: {} {}: left alone: its signed statement does not confirm the store's columns",
                    e.target, e.key
                );
            }
            continue;
        }
        p.older += 1;
        p.kept -= 1;
        delete(store, dry_run, &e, " (superseded)")?;
    }
    Ok(p)
}

/// Why a candidate was left alone ([`confirm_expired`]).
enum Left {
    /// Its value could not be read or is no record.
    Unreadable,
    /// Its signed statement does not say what the columns said; what it
    /// says, for the manifest it references.
    Unconfirmed(Box<EnvelopeMeta>),
}

/// Whether the signed statement of a read candidate agrees with the
/// `expires` column that named it: its `expiresAt` has passed. A format-1
/// value in the slot (a vci 2.8 wrote it over a frame during the migration
/// window, leaving the frame's columns) is read through today's envelope
/// path: the columns never choose the parser.
fn confirm_expired(e: &StoredEnvelope, now: i64) -> Result<(), Left> {
    let Some(m) = record_meta(&e.bytes) else {
        return Err(Left::Unreadable);
    };
    if m.expires_at <= now {
        Ok(())
    } else {
        Err(Left::Unconfirmed(Box::new(m)))
    }
}

/// The keys kept per unit and signer: the `keep` newest of each list.
fn keep_newest(
    by_unit: &mut BTreeMap<(String, String), Vec<(i64, String)>>,
    keep: usize,
) -> BTreeSet<String> {
    let mut keep_keys: BTreeSet<String> = BTreeSet::new();
    for list in by_unit.values_mut() {
        list.sort_by(|a, b| b.cmp(a));
        keep_keys.extend(list.iter().take(keep).map(|(_, k)| k.clone()));
    }
    keep_keys
}

/// Remove `e` (or say so on a dry run), `note` after the key.
fn delete(
    store: &dyn AttestationStore,
    dry_run: bool,
    e: &StoredEnvelope,
    note: &str,
) -> Result<()> {
    if dry_run {
        println!("would remove {} {}{note}", e.target, e.key);
    } else {
        store.remove(vec![e.clone()])?;
        println!("removed {} {}{note}", e.target, e.key);
    }
    Ok(())
}

/// The stored manifest an unreadable value names when that much of it can
/// be read (`manifestRef` of its statement), else `None`: whatever it
/// references must stay.
fn unreadable_manifest_ref(bytes: &[u8]) -> Option<String> {
    envelope_statement(bytes).and_then(|v| {
        v["predicate"]["manifestRef"]
            .as_str()
            .filter(|r| vci_git::parse_manifest_key(&vci_git::manifest_key(r)).is_some())
            .map(str::to_owned)
    })
}

/// The manifests pass: the base manifests the referenced ones list their
/// entries on top of (vci 2.1.8) are referenced too; then every stored
/// manifest nothing references goes. Returns how many went (on a dry run,
/// how many would): one the backend kept by its own rule is said so and
/// not counted.
fn prune_manifests(
    store: &dyn AttestationStore,
    dry_run: bool,
    mut referenced: Option<BTreeSet<String>>,
    fetch_hint: &str,
) -> Result<usize> {
    // One that cannot be read keeps every manifest (its base is unknown).
    if let Some(set) = referenced.as_mut() {
        let roots: Vec<&str> = set.iter().map(String::as_str).collect();
        let _ = store.prefetch(Prefetch::Manifests { roots: &roots });
        let mut bases = BTreeSet::new();
        for r in set.iter() {
            let base = store
                .manifest(r)?
                .filter(|m| m.error.is_none())
                .map(|m| vci_core::InputManifest::compact_base(&m.bytes));
            match base {
                Some(Ok(Some(b))) => {
                    bases.insert(b);
                }
                Some(Ok(None)) => {}
                _ => {
                    eprintln!(
                        "vci prune: input manifest {r} could not be read{fetch_hint}, so no input manifest is removed"
                    );
                    referenced = None;
                    break;
                }
            }
        }
        if let Some(set) = referenced.as_mut() {
            set.extend(bases);
        }
    }
    let mut manifests = 0usize;
    match &referenced {
        Some(set) => {
            for root in store.manifest_roots()? {
                if set.contains(&root) {
                    continue;
                }
                let key = vci_git::manifest_key(&root);
                if dry_run {
                    manifests += 1;
                    println!("would remove project {key} (unreferenced manifest)");
                } else if store.remove_manifests(&[root.as_str()])? == 1 {
                    manifests += 1;
                    println!("removed project {key} (unreferenced manifest)");
                } else {
                    // The backend's own rule kept it: a referrer it knows
                    // of (a writer that stored one since the listing), or
                    // its grace period on a shared store.
                    eprintln!(
                        "vci prune: project {key}: kept by the {} store (referenced, or put within its grace period)",
                        store.kind()
                    );
                }
            }
        }
        None => eprintln!(
            "vci prune: an attestation could not be read{fetch_hint}, so no input manifest is removed"
        ),
    }
    Ok(manifests)
}

/// The objects pass (STORE-V2 sections 1.3 and 2.1): the objects no
/// attestation references and put more than an hour ago (the store's
/// orphan rule, applied again at the delete), then every state object put
/// more than `days` days ago, referenced or not (the records stay valid;
/// `vci explain` then prints the observed value without the attested
/// hash). On git-meta both scans read every value, once each. Returns how
/// many objects went.
fn prune_objects(store: &dyn AttestationStore, dry_run: bool, days: u32) -> Result<usize> {
    let orphans = match store.orphan_objects() {
        Ok(ids) => ids,
        Err(StoreError::Unsupported { .. }) => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    for id in &orphans {
        println!(
            "{} project object {id} (unreferenced object)",
            if dry_run { "would remove" } else { "removed" }
        );
    }
    let removed = if dry_run || orphans.is_empty() {
        0
    } else {
        let ids: Vec<&str> = orphans.iter().map(String::as_str).collect();
        store.remove_objects(&ids)?
    };
    eprintln!(
        "vci prune: {} unreferenced object(s){}",
        if dry_run { orphans.len() } else { removed },
        if dry_run { " (dry run)" } else { " removed" }
    );
    let state = if dry_run {
        eprintln!(
            "vci prune: state objects older than {days} day(s): removed on a run without --dry-run"
        );
        0
    } else {
        let n = store.prune_state_objects(std::time::Duration::from_secs(
            u64::from(days) * 24 * 60 * 60,
        ))?;
        eprintln!("vci prune: {n} state object(s) older than {days} day(s) removed");
        n
    };
    Ok(removed + state)
}

/// What `prune` (and supersession on store) reads from an envelope's
/// payload (unverified).
pub(crate) struct EnvelopeMeta {
    pub test_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    /// `commit` (empty when absent).
    pub commit: String,
    /// `toolchain.os` / `toolchain.arch` (empty when absent).
    pub os: String,
    pub arch: String,
    /// The input manifest it references (`manifestRef`; `None` for an
    /// attestation with its manifest inline, made before vci 1.9.0).
    pub manifest_ref: Option<String>,
    /// How long the unit's tests took (`result.durationMs`), when recorded.
    pub duration_ms: Option<u64>,
    /// The checkout's git tree (`tree`, since 2.1.12), when recorded.
    pub tree: Option<String>,
}

/// An envelope's statement (unverified).
fn envelope_statement(bytes: &[u8]) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let env = Envelope::from_json(bytes).ok()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&env.payload)
        .ok()?;
    serde_json::from_slice(&payload).ok()
}

/// The inline input manifest of an envelope made before vci 1.9.0
/// (unverified).
pub(crate) fn envelope_inline_manifest(bytes: &[u8]) -> Option<vci_core::InputManifest> {
    let mut v = envelope_statement(bytes)?;
    serde_json::from_value(v["predicate"]["manifest"].take()).ok()
}

pub(crate) fn envelope_meta(bytes: &[u8]) -> Option<EnvelopeMeta> {
    let v = envelope_statement(bytes)?;
    let p = &v["predicate"];
    let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned();
    Some(EnvelopeMeta {
        test_id: p["testId"].as_str()?.to_owned(),
        issued_at: parse_rfc3339(p["issuedAt"].as_str()?).ok()?,
        expires_at: parse_rfc3339(p["expiresAt"].as_str()?).ok()?,
        commit: s(&p["commit"]),
        os: s(&p["toolchain"]["os"]),
        arch: s(&p["toolchain"]["arch"]),
        manifest_ref: p["manifestRef"].as_str().map(str::to_owned),
        duration_ms: p["result"]["durationMs"].as_u64(),
        tree: p["tree"].as_str().map(str::to_owned),
    })
}

/// [`envelope_meta`] of a stored record of either format, told apart by
/// its first byte ([`decode_record`]): a format-1 value as before; a
/// format-3 frame from its signed statement, whose toolchain is in the hdr
/// object (`os` and `arch` are empty here) and which names no stored
/// manifest (`manifest_ref` is `None`). Unverified, as before: prune
/// decides what to delete on it, never what to trust.
pub(crate) fn record_meta(bytes: &[u8]) -> Option<EnvelopeMeta> {
    match decode_record(bytes) {
        Ok(Record::FormatOne(bytes)) => envelope_meta(bytes),
        Ok(Record::FormatThree(frame)) => frame_meta(&frame),
        Err(_) => None,
    }
}

fn frame_meta(frame: &vci_core::Frame) -> Option<EnvelopeMeta> {
    let v: serde_json::Value = serde_json::from_slice(&frame.statement).ok()?;
    let p = &v["predicate"];
    Some(EnvelopeMeta {
        test_id: p["testId"].as_str()?.to_owned(),
        issued_at: parse_rfc3339(p["issuedAt"].as_str()?).ok()?,
        expires_at: parse_rfc3339(p["expiresAt"].as_str()?).ok()?,
        commit: p["commit"].as_str().unwrap_or_default().to_owned(),
        os: String::new(),
        arch: String::new(),
        manifest_ref: None,
        duration_ms: p["result"]["durationMs"].as_u64(),
        tree: p["tree"].as_str().map(str::to_owned),
    })
}

/// What a backend's `upgrade_finish` came to ([`store_upgrade`]), in one
/// shape over the backends' own.
enum Done {
    Finished,
    Already,
    FormatOneRows(usize),
}

#[cfg(any(feature = "sqlite", feature = "libsql"))]
impl From<vci_store_sqlite::Finish> for Done {
    fn from(f: vci_store_sqlite::Finish) -> Done {
        match f {
            vci_store_sqlite::Finish::Finished => Done::Finished,
            vci_store_sqlite::Finish::AlreadyFinished => Done::Already,
            vci_store_sqlite::Finish::FormatOneRows(n) => Done::FormatOneRows(n),
        }
    }
}

/// `vci store upgrade --begin` (`begin`) and `--finish` (STORE-V2 section
/// 5, steps 2 and 4), on the store the repository's settings select, opened
/// as the concrete backend: the upgrade steps are the backends' own
/// methods, not the trait's, since a 2.8 schema is brought forward once by
/// an operator and never by a reader. `--begin` adds the format-3 columns
/// and tables in a request of its own (idempotent). `--finish` is refused
/// with the count (exit 1) while an attestation that is not a format-3
/// record remains, counted by the value's first byte on every backend,
/// never by the `format` column; at zero it drops the input manifests and
/// sets schema version 2. git-meta has no schema: nothing to do, exit 0.
pub fn store_upgrade(begin: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let Some(sel) = crate::store::selection_of(&repo) else {
        bail!("the store's settings could not be resolved (`vci store info` says why)");
    };
    let cx = crate::store::open_context(&repo, "store");
    let kind = sel.kind.value.as_str();
    let finished = |f: Done, location: &str| -> i32 {
        match f {
            Done::Finished => {
                println!(
                    "store: {kind} {location}: upgraded to schema version 2: the input manifests are dropped, and a vci before 2.9 reads this store as too new and fails open"
                );
                0
            }
            Done::Already => {
                println!("store: {kind} {location}: at schema version 2 already");
                0
            }
            Done::FormatOneRows(n) => {
                println!(
                    "store: {kind} {location}: not finished: {n} attestation(s) are not format-3 records, and a reader of them needs the input manifests; once they have expired (`vci prune`) or were attested again with `record_format = 3`, run `vci store upgrade --finish` again"
                );
                1
            }
        }
    };
    match kind {
        "git-meta" => {
            println!("store: git-meta has no schema: nothing to upgrade");
            Ok(0)
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            use vci_store_sqlite::{SqliteFactory, SqliteOptions, SqliteStore};
            let path = SqliteFactory::path(&sel, &cx);
            let store = SqliteStore::open_path(
                &path,
                SqliteOptions {
                    busy_timeout: sel.timeout.value,
                    ..SqliteOptions::default()
                },
            );
            let location = path.display().to_string();
            if begin {
                let added = store.upgrade_begin()?;
                println!(
                    "store: sqlite {location}: the format-3 columns and tables are {}",
                    if added { "added" } else { "present" }
                );
                Ok(0)
            } else {
                Ok(finished(Done::from(store.upgrade_finish()?), &location))
            }
        }
        #[cfg(feature = "postgres")]
        "postgres" => {
            let store = vci_store_postgres::PgStore::open(&sel, &cx)?;
            let location = store.location();
            if begin {
                store.upgrade_begin()?;
                println!("store: postgres {location}: the format-3 columns and tables are present");
                Ok(0)
            } else {
                let f = match store.upgrade_finish()? {
                    vci_store_postgres::Finish::Done => Done::Finished,
                    vci_store_postgres::Finish::Already => Done::Already,
                    vci_store_postgres::Finish::FormatOneRows(n) => {
                        Done::FormatOneRows(usize::try_from(n).unwrap_or(usize::MAX))
                    }
                };
                Ok(finished(f, &location))
            }
        }
        #[cfg(feature = "libsql")]
        "libsql" => {
            let store = vci_store_libsql::LibsqlStore::open(&sel, &cx)?;
            let location = store.location();
            if begin {
                let sent = store.upgrade_begin()?;
                println!(
                    "store: libsql {location}: the format-3 columns and tables are {}",
                    if sent { "added" } else { "present" }
                );
                Ok(0)
            } else {
                Ok(finished(Done::from(store.upgrade_finish()?), &location))
            }
        }
        other => bail!(
            "this vci cannot upgrade a {other:?} store (from {}): it was built without that backend, or no such backend exists",
            sel.kind.source
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The publication gate: only a shared store without --push signs
    /// without storing.
    #[test]
    fn vci_ci_stores_on_a_shared_store_only_with_push() {
        assert_eq!(store_mode(true, false), StoreMode::SignOnly);
        assert_eq!(store_mode(true, true), StoreMode::Write);
        assert_eq!(store_mode(false, false), StoreMode::Write);
        assert_eq!(store_mode(false, true), StoreMode::Write);
    }

    /// `vci ci --push` on a store without an exchange succeeds without
    /// sending anything (its writes were stored when they were made); a
    /// remote is ignored there and refused by `vci push`.
    #[test]
    fn pushing_a_store_without_an_exchange_sends_nothing() {
        let s = crate::store::mem::MemStore::new();
        assert_eq!(push_with(&s, None, false, OnRemote::Ignore).unwrap(), 0);
        assert_eq!(
            push_with(&s, Some("origin"), false, OnRemote::Ignore).unwrap(),
            0
        );
        let e = push_with(&s, Some("origin"), false, OnRemote::Refuse).unwrap_err();
        assert_eq!(e.to_string(), "the memory store does not support a remote");
        let e = push_with(&s, None, true, OnRemote::Ignore).unwrap_err();
        assert_eq!(
            e.to_string(),
            "the memory store does not support rewriting history"
        );
        assert_eq!(s.writes(), 0);
    }

    #[test]
    fn verify_trust_pinned_on_the_command_line_is_the_only_trust() {
        let p = |s: &'static str| Some(Utf8Path::new(s));
        let t = |a, i, r| VerifyTrust {
            allowed_signers: a,
            identities: i,
            trusted_root: r,
        };
        // Nothing pinned: the repository's files, for either kind.
        assert!(t(None, None, None).unpinned(true).is_none());
        assert!(t(None, None, None).unpinned(false).is_none());
        // What each kind needs, given.
        assert!(t(None, p("i"), p("r")).unpinned(true).is_none());
        assert!(t(p("a"), p("i"), p("r")).unpinned(true).is_none());
        assert!(t(p("a"), None, None).unpinned(false).is_none());
        assert!(t(p("a"), p("i"), None).unpinned(false).is_none());
        // Pinned, but not what this envelope needs.
        let (why, source) = t(p("a"), None, None).unpinned(true).unwrap();
        assert!(
            why.contains("without --identities and --trusted-root"),
            "{why}"
        );
        assert_eq!(source, "--allowed-signers a");
        let (why, _) = t(None, p("i"), None).unpinned(true).unwrap();
        assert!(why.contains("without --trusted-root ("), "{why}");
        let (why, source) = t(None, p("i"), p("r")).unpinned(false).unwrap();
        assert!(why.contains("SSH-signed") && why.contains("without --allowed-signers"));
        assert_eq!(source, "--identities i, --trusted-root r");
    }

    /// A statement as `vci run` signs it, in the fields prune reads, with
    /// these times (RFC 3339) and tree.
    fn statement(issued: i64, expires: i64, tree: Option<&str>) -> Vec<u8> {
        let mut p = json!({
            "testId": "src/a.test.ts",
            "issuedAt": rfc3339(issued),
            "expiresAt": rfc3339(expires),
            "commit": "c".repeat(40),
            "toolchain": {"os": "linux", "arch": "x86_64"},
            "manifestRef": "ab".repeat(32),
            "result": {"state": "passed", "tests": 1, "failed": 0, "skipped": 0, "durationMs": 7},
        });
        if let Some(t) = tree {
            p["tree"] = json!(t);
        }
        serde_json::to_vec(&json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "src/a.test.ts", "digest": {"blake3": "0".repeat(64)}}],
            "predicateType": vci_core::PREDICATE_TYPE,
            "predicate": p,
        }))
        .unwrap()
    }

    /// The statement as a format-1 value (an unsigned envelope: prune
    /// never verifies) and as a format-3 frame.
    fn both_formats(statement: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use base64::Engine as _;
        let envelope = serde_json::to_vec(&json!({
            "payloadType": vci_attest::PAYLOAD_TYPE,
            "payload": base64::engine::general_purpose::STANDARD.encode(statement),
            "signatures": [{"keyid": "", "sig": "AA=="}],
        }))
        .unwrap();
        let frame = vci_core::Frame {
            statement: statement.to_vec(),
            keyid: "SHA256:test".into(),
            sig: vci_core::FrameSig::SshSig(vec![1, 2, 3]),
            descriptor: vec![0; 33],
        }
        .encode()
        .unwrap()
        .into_bytes();
        (envelope, frame)
    }

    /// `record_meta` reads the same signed facts from a value of either
    /// format, told apart by its first byte; a frame's toolchain is in its
    /// hdr object (empty here) and it names no stored manifest.
    #[test]
    fn record_meta_reads_either_format() {
        let (envelope, frame) = both_formats(&statement(1_000, 2_000, Some("t")));
        let one = record_meta(&envelope).expect("a format-1 record");
        let three = record_meta(&frame).expect("a format-3 record");
        assert_eq!(
            (one.test_id.as_str(), one.issued_at, one.expires_at),
            ("src/a.test.ts", 1_000, 2_000)
        );
        assert_eq!(
            (three.test_id, three.issued_at, three.expires_at),
            (one.test_id.clone(), one.issued_at, one.expires_at)
        );
        assert_eq!((three.commit, three.tree), (one.commit, one.tree));
        assert_eq!(three.duration_ms, Some(7));
        assert_eq!((one.os.as_str(), one.arch.as_str()), ("linux", "x86_64"));
        assert_eq!((three.os.as_str(), three.arch.as_str()), ("", ""));
        assert_eq!(one.manifest_ref.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(three.manifest_ref, None);
        // Byte for byte what `envelope_meta` read before 2.9.
        let before = envelope_meta(&envelope).unwrap();
        assert_eq!(
            (
                before.test_id,
                before.issued_at,
                before.expires_at,
                before.manifest_ref
            ),
            (one.test_id, one.issued_at, one.expires_at, one.manifest_ref)
        );
        assert!(record_meta(b"vci3\n{}\nAA==\nAA==\n").is_none());
        assert!(record_meta(b"").is_none());
        assert!(
            envelope_meta(&frame).is_none(),
            "the format-1 parser alone refuses a frame"
        );
    }

    /// A listed record with this key hint and value, as the columns path
    /// reads it.
    fn candidate(issued: i64, tree16: Option<&str>, value: Vec<u8>) -> StoredEnvelope {
        let hint = vci_store::KeyHint {
            issued,
            tree: tree16.map(str::to_owned),
        };
        let key =
            vci_store::key::attestation_key_hinted(&"1".repeat(64), &"2".repeat(16), "ab", &hint);
        let mut e = StoredEnvelope::from_key("path:src/a.test.ts", &key).unwrap();
        e.set_value(value);
        e
    }

    /// The `expires` column only names a candidate: the signed statement
    /// decides. It is confirmed by a signed `expiresAt` that has passed, in
    /// either format (a 2.8 writer's format-1 value under a frame's
    /// columns included); a statement that says otherwise leaves the
    /// record alone with what it references, and a value that is no record
    /// is unreadable.
    #[test]
    fn confirm_deletes_only_what_the_signed_statement_says() {
        let now = 5_000;
        for (what, bytes) in [
            ("format 1", both_formats(&statement(1_000, 2_000, None)).0),
            ("format 3", both_formats(&statement(1_000, 2_000, None)).1),
        ] {
            let e = candidate(1_000, None, bytes);
            assert!(confirm_expired(&e, now).is_ok(), "{what}");
        }
        // The column said expired; the statement says not.
        let e = candidate(1_000, None, both_formats(&statement(1_000, 9_000, None)).1);
        assert!(matches!(
            confirm_expired(&e, now),
            Err(Left::Unconfirmed(m)) if m.issued_at == 1_000
        ));
        // No record at all.
        let e = candidate(1_000, None, b"vci3z\n{}\nAA==\nAA==\n".to_vec());
        assert!(matches!(confirm_expired(&e, now), Err(Left::Unreadable)));
        let mut e = candidate(1_000, None, Vec::new());
        e.set_error("gone");
        assert!(matches!(confirm_expired(&e, now), Err(Left::Unreadable)));
    }

    /// Of each unit and signer, the `keep` newest by issue time are kept.
    #[test]
    fn keep_newest_keeps_the_latest_issued() {
        let mut by_unit: BTreeMap<(String, String), Vec<(i64, String)>> = BTreeMap::new();
        by_unit.insert(
            ("u".into(), "s".into()),
            vec![(1, "k1".into()), (3, "k3".into()), (2, "k2".into())],
        );
        by_unit.insert(("v".into(), "s".into()), vec![(5, "k5".into())]);
        let kept = keep_newest(&mut by_unit, 2);
        assert_eq!(
            kept,
            ["k2", "k3", "k5"].into_iter().map(String::from).collect()
        );
        assert_eq!(
            keep_newest(&mut by_unit, 1),
            ["k3", "k5"].into_iter().map(String::from).collect()
        );
    }

    #[test]
    fn urls_are_printed_without_credentials() {
        assert_eq!(
            redact_userinfo("https://x-access-token:ghs_secret@github.com/o/r.git"),
            "https://***@github.com/o/r.git"
        );
        assert_eq!(
            redact_userinfo("https://github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            redact_userinfo("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );
    }

    /// Every CI snippet `vci init` prints installs a vci pinned to a release tag
    /// (the verifier must not move under a workflow), never a branch head.
    #[test]
    fn ci_snippets_pin_vci_to_a_release() {
        for (name, s) in [
            ("vitest", CI_SNIPPET),
            ("pytest", CI_SNIPPET_PYTEST),
            ("go", CI_SNIPPET_GO),
            ("cargo", CI_SNIPPET_CARGO),
            ("rails", CI_SNIPPET_RAILS),
            ("node-test", CI_SNIPPET_NODE_TEST),
        ] {
            let install: Vec<&str> = s
                .lines()
                .filter(|l| {
                    l.contains("cryptographically-verifiable-ci-runner")
                        && !l.trim_start().starts_with('#')
                })
                .collect();
            assert!(!install.is_empty(), "{name}: no vci install step");
            for l in &install {
                assert!(
                    !l.contains("--depth"),
                    "{name}: shallow clone of a branch: {l}"
                );
                if l.contains("cargo install") {
                    assert!(l.contains("--tag v1.0.0"), "{name}: {l}");
                } else if l.contains("git clone") {
                    // A release tag: `v2` (moved only by scripts/publish-release.sh,
                    // to a commit whose manifest names its own binaries) or `v2.x.y`.
                    assert!(
                        s.contains("--detach v2"),
                        "{name}: clone without a pinned checkout"
                    );
                } else if l.contains("uses:") {
                    assert!(l.contains("@v2"), "{name}: {l}");
                }
            }
        }
    }
}
