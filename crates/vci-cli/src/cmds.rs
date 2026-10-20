//! `ci`, `verify`, `init`, `push`, `fetch`, `prune`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::json;
use vci_adapter::Adapter;
use vci_attest::{AllowedSigners, Envelope, verify_envelope};
use vci_git::{AttestStore, SETUP_FILE};

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, template_for};
use crate::ctx::{VciPredicate, open_repo};
use crate::partition::{Partition, Share, Split};
use crate::plan::{PlanOptions, plan, print};
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
    let code = match how {
        None => run_plain(&res, &root, None, run_split)?,
        Some(how) => match run_attested(&res, how, &args.ttl, run_split) {
            Ok(Attempt::Ran(out)) => {
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
        eprintln!(
            "vci ci: {} unit(s) attested{}",
            attested.len(),
            if push_wanted {
                ""
            } else if args.push {
                " (nothing to push)"
            } else {
                " (stored locally; publish with `vci push`)"
            }
        );
    }
    let pushed = if push_wanted {
        // Best effort: CI's result is the tests', never the publication's.
        match push(args.remote.as_deref(), false) {
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
        "attested": attested.iter().map(|a| json!({"testId": a.test_id, "project": a.project})).collect::<Vec<_>>(),
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
    )
    .map(Attempt::Ran)
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
) -> Result<i32> {
    let bytes = if envelope_path == "-" {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut v)?;
        v
    } else {
        std::fs::read(envelope_path).with_context(|| format!("reading {envelope_path}"))?
    };
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
        Ok(v) => verified_details(v, &source, note, manifest_file, now),
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

/// `vci verify`'s report of a verified envelope; the exit code.
fn verified_details(
    v: vci_attest::Verified,
    source: &str,
    note: Option<String>,
    manifest_file: Option<&Utf8Path>,
    now: i64,
) -> Result<i32> {
    println!("VALID signature by {} ({})", v.principal, v.fingerprint);
    println!("  trust root: {source}");
    if let Some(n) = note {
        println!("{n}");
    }
    println!("  predicateType: {}", v.statement.predicate_type);
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
                    let store = AttestStore::new(&repo);
                    let _ = store.hydrate_manifests([b]);
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
                let store = AttestStore::new(&repo);
                // Fetched lazily (see `vci fetch`); a failure reads as not fetched.
                let _ = store.hydrate_manifests([r.as_str()]);
                let stored = store.manifest(r);
                let m = crate::plan::load_manifest(r, stored, |b| store.manifest(b))
                    .map_err(|(what, actual)| format!("{what} ({actual})"))?;
                (m, format!("git-meta project {}", vci_git::manifest_key(r)))
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
    setup_git_meta(&repo, &root, meta_url.as_deref())?;
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
fn print_default_remote(store: &AttestStore, remote: Option<&str>, name: &str) {
    if remote.is_none()
        && let Ok(Some(url)) = store.remote_url(name)
    {
        eprintln!("vci: git-meta remote {name} is {}", redact_userinfo(&url));
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

pub fn push(remote: Option<&str>, rewrite_history: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = AttestStore::new(&repo);
    let out = if rewrite_history {
        store.push_rewriting_history(remote)?
    } else {
        store.push(remote)?
    };
    print_default_remote(&store, remote, &out.remote);
    print_exchange_messages(&out.warnings, &out.notes);
    match out.status {
        vci_git::PushStatus::Pushed => {
            eprintln!(
                "vci: pushed git-meta metadata (refs/meta/main) to {}",
                out.remote
            )
        }
        vci_git::PushStatus::UpToDate => eprintln!(
            "vci: nothing to push: {}'s refs/meta/main already has every local attestation",
            out.remote
        ),
        vci_git::PushStatus::NothingStored => eprintln!(
            "vci: nothing to push: no attestations are stored locally (run `vci run` first)"
        ),
    }
    Ok(0)
}

pub fn fetch(remote: Option<&str>) -> Result<i32> {
    let (repo, _) = open_repo()?;
    for l in fetch_messages(&repo, remote)? {
        eprintln!("{l}");
    }
    Ok(0)
}

/// `vci fetch`'s work (also `vci plan --fetch` and `vci ci --fetch`): fetch
/// and materialize the remote's attestations; what `vci fetch` prints, as
/// lines for stderr.
pub fn fetch_messages(repo: &vci_git::Repo, remote: Option<&str>) -> Result<Vec<String>> {
    let store = AttestStore::new(repo);
    let out = store.fetch(remote)?;
    let mut lines = Vec::new();
    if remote.is_none()
        && let Ok(Some(url)) = store.remote_url(&out.remote)
    {
        lines.push(format!(
            "vci: git-meta remote {} is {}",
            out.remote,
            redact_userinfo(&url)
        ));
    }
    lines.extend(out.notes.iter().map(|n| format!("vci: note: {n}")));
    lines.extend(out.warnings.iter().map(|w| format!("vci: warning: {w}")));
    let n = store.count()?;
    if out.found {
        lines.push(format!(
            "vci: fetched git-meta metadata from {} ({n} attestations stored locally)",
            out.remote
        ));
    } else {
        lines.push(format!(
            "vci: {} has no git-meta metadata yet (refs/meta/main); {n} attestations stored locally",
            out.remote
        ));
    }
    Ok(lines)
}

/// `vci prune`: delete attestations that have expired (git-meta tombstones,
/// published by the next `vci push`). Only the claimed expiry is read; an
/// envelope that cannot be parsed is left alone. Then delete the stored input
/// manifests no remaining attestation references (`manifestRef`; one with
/// its manifest inline references none), unless an attestation's value, or
/// the `manifestRef` of one left alone, cannot be read (what it references
/// is then unknown).
pub fn prune(dry_run: bool, superseded: bool, keep: usize) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = AttestStore::new(&repo);
    let now = now_unix();
    let (mut expired, mut kept, mut unreadable, mut older) = (0usize, 0usize, 0usize, 0usize);
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
    let mut by_unit: BTreeMap<(String, String), Vec<(i64, String)>> = BTreeMap::new();
    let mut current = Vec::new();
    // Manifests the remaining attestations reference; `None` once one of
    // them cannot be read.
    let mut referenced: Option<BTreeSet<String>> = Some(BTreeSet::new());
    // Every attestation's payload is read: fetch the ones not fetched yet
    // (on a large store, what a fetch downloaded before vci 2.0). One that
    // cannot be fetched is unreadable, and left alone.
    match store.hydrate_attestations() {
        Ok(h) if h.unresolved > 0 => eprintln!(
            "vci prune: warning: {} attestation value(s) could not be fetched{}",
            h.unresolved,
            h.error.map(|e| format!(": {e}")).unwrap_or_default()
        ),
        Ok(_) => {}
        Err(e) => eprintln!("vci prune: warning: could not fetch the attestations' values: {e:#}"),
    }
    for e in store.list(None)? {
        if e.error.is_some() {
            referenced = None;
        }
        match envelope_meta(&e.bytes) {
            Some(m) if m.expires_at <= now => {
                expired += 1;
                if dry_run {
                    println!("would remove {} {}", e.target, e.key);
                } else {
                    store.remove(&e)?;
                    println!("removed {} {}", e.target, e.key);
                }
            }
            Some(m) => {
                kept += 1;
                by_unit
                    .entry((m.test_id.clone(), e.signer.clone()))
                    .or_default()
                    .push((m.issued_at, e.key.clone()));
                current.push((m, e));
            }
            None => {
                unreadable += 1;
                // Left alone, so whatever it references stays: the
                // manifest it names when that much can be read, else none
                // is removed.
                let r = envelope_statement(&e.bytes).and_then(|v| {
                    v["predicate"]["manifestRef"]
                        .as_str()
                        .filter(|r| {
                            vci_git::parse_manifest_key(&vci_git::manifest_key(r)).is_some()
                        })
                        .map(str::to_owned)
                });
                match (r, referenced.as_mut()) {
                    (Some(r), Some(set)) => {
                        set.insert(r);
                    }
                    (Some(_), None) => {}
                    (None, _) => referenced = None,
                }
            }
        }
    }
    // The keys kept per unit and signer: the `keep` newest.
    let mut keep_keys: BTreeSet<String> = BTreeSet::new();
    for list in by_unit.values_mut() {
        list.sort_by(|a, b| b.cmp(a));
        keep_keys.extend(list.iter().take(keep).map(|(_, k)| k.clone()));
    }
    for (m, e) in current {
        let live = m.tree.as_deref().is_some_and(|t| live_trees.contains(t));
        if keep_keys.contains(&e.key) || live {
            if let (Some(r), Some(set)) = (&m.manifest_ref, referenced.as_mut()) {
                set.insert(r.clone());
            }
            continue;
        }
        older += 1;
        kept -= 1;
        if dry_run {
            println!("would remove {} {} (superseded)", e.target, e.key);
        } else {
            store.remove(&e)?;
            println!("removed {} {} (superseded)", e.target, e.key);
        }
    }
    // The base manifests the referenced ones list their entries on top of
    // (vci 2.1.8) are referenced too; one that cannot be read keeps every
    // manifest (its base is unknown).
    if let Some(set) = referenced.as_mut() {
        let _ = store.hydrate_manifests(set.iter().map(String::as_str));
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
                        "vci prune: input manifest {r} could not be read (run `vci fetch`), so no input manifest is removed"
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
            for root in store.manifests()? {
                if set.contains(&root) {
                    continue;
                }
                manifests += 1;
                let key = vci_git::manifest_key(&root);
                if dry_run {
                    println!("would remove project {key} (unreferenced manifest)");
                } else {
                    store.remove_manifest(&root)?;
                    println!("removed project {key} (unreferenced manifest)");
                }
            }
        }
        None => eprintln!(
            "vci prune: an attestation could not be read (run `vci fetch`), so no input manifest is removed"
        ),
    }
    eprintln!(
        "vci prune: {expired} expired{}{}, {kept} current, {unreadable} unreadable (left alone)",
        if superseded {
            format!(", {older} superseded")
        } else {
            String::new()
        },
        if dry_run { " (dry run)" } else { "" }
    );
    eprintln!(
        "vci prune: {manifests} unreferenced input manifest(s){}",
        if dry_run { " (dry run)" } else { " removed" }
    );
    if expired + older + manifests > 0 && !dry_run {
        eprintln!(
            "vci prune: run `vci push` to publish the deletions (`vci push --rewrite-history` also drops the deleted values from what a fetch downloads)"
        );
    }
    Ok(0)
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

#[cfg(test)]
mod tests {
    use super::*;

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
