//! `vci`: cryptographically verifiable CI test selection.

mod cmds;
mod config;
mod ctx;
mod envcmd;
mod envpolicy;
mod externals;
mod global;
mod keys;
mod plan;
mod run;
mod treestat;
mod util;

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "vci",
    version,
    about = "Skip CI tests that a trusted signer already ran against identical inputs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Github,
}

#[derive(Clone, Copy, ValueEnum)]
enum EnvFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write vci.toml, .vci/allowed_signers and .git-meta, configure the git-meta remote, install @vci/vitest (Vitest), print a CI snippet (node-test: no install).
    Init {
        /// Add this public key (or private key with a .pub next to it) to allowed_signers.
        #[arg(long)]
        key: Option<Utf8PathBuf>,
        /// Principal for the key (default: git user.email).
        #[arg(long)]
        principal: Option<String>,
        /// Project directory relative to the repo root.
        #[arg(long)]
        project: Option<String>,
        /// Test runner adapter: vitest (default), pytest, go, cargo, rails or node-test.
        #[arg(long)]
        adapter: Option<String>,
        /// Do not run npm install.
        #[arg(long)]
        no_install: bool,
        /// git-meta metadata remote URL for .git-meta (default: origin's URL).
        #[arg(long)]
        meta_url: Option<String>,
        /// Also trust this repository's GitHub Actions workflows signing keylessly (`vci ci --oidc`): write .vci/identities.toml for origin's repository and the Sigstore trust root (.vci/sigstore-trusted-root.json, from `gh attestation trusted-root`).
        #[arg(long)]
        oidc: bool,
    },
    /// Run tests, collect their inputs, sign and store attestations.
    Run {
        /// Test files, package directories for Go, `<package dir>#<target>` units or package directories for Cargo (default: all).
        files: Vec<String>,
        /// SSH key for `ssh-keygen -Y sign` (private key, or .pub with the key in ssh-agent).
        #[arg(long, conflicts_with = "oidc")]
        key: Option<Utf8PathBuf>,
        /// Sign keylessly with the CI job's OIDC token (GitHub Actions with `permissions: id-token: write`) through Sigstore: `github` (default: fulcio.githubapp.com, timestamp.githubapp.com) or `public-good` (fulcio.sigstore.dev, timestamp.sigstore.dev).
        #[arg(long, value_name = "INSTANCE", num_args = 0..=1, default_missing_value = "github")]
        oidc: Option<String>,
        /// Attestation lifetime.
        #[arg(long, default_value = "14d")]
        ttl: String,
        /// Write a JSON summary of every unit (attested or not, with its reason keys) to this file.
        #[arg(long)]
        summary: Option<Utf8PathBuf>,
    },
    /// Decide which test files can be skipped.
    Plan {
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
        /// Fetch attestations first, as `vci fetch` does, while the projects are probed (a failure is a warning: only attestations already stored locally are used). REMOTE as in `vci fetch --remote`.
        #[arg(long, value_name = "REMOTE", num_args = 0..=1, default_missing_value = "")]
        fetch: Option<String>,
        /// Only this `[[projects]]` entry (by name; repeatable): the other projects are not listed, probed or verified. Not for the single-project form.
        #[arg(long = "project", value_name = "NAME")]
        project: Vec<String>,
    },
    /// Plan, run the remaining tests, and write an audit log of the skips (with --key or --oidc: attest what runs).
    #[command(group(clap::ArgGroup::new("signing").args(["key", "oidc"])))]
    Ci {
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        audit_log: Option<Utf8PathBuf>,
        /// Run the remaining tests as `vci run --key` does and attest them with this SSH key (private key, or .pub with the key in ssh-agent); with run-all (e.g. policy.no_skip_refs), every unit is attested.
        #[arg(long)]
        key: Option<Utf8PathBuf>,
        /// Run the remaining tests as `vci run --oidc` does and attest them keylessly with the job's OIDC token (GitHub Actions, `permissions: id-token: write`); INSTANCE as in `vci run --oidc`.
        #[arg(long, value_name = "INSTANCE", num_args = 0..=1, default_missing_value = "github")]
        oidc: Option<String>,
        /// Attestation lifetime (with --key or --oidc).
        #[arg(long, default_value = "14d", requires = "signing")]
        ttl: String,
        /// Afterwards publish the attestations as `vci push` does (best effort: a failure is a warning, never the exit code).
        #[arg(long, requires = "signing")]
        push: bool,
        /// git-meta remote, or a git remote / URL, to push to (as `vci push --remote`).
        #[arg(long, requires = "push")]
        remote: Option<String>,
        /// Fetch attestations first, as `vci fetch` does, while the projects are probed (a failure is a warning: only attestations already stored locally are used). REMOTE as in `vci fetch --remote`.
        #[arg(long, value_name = "REMOTE", num_args = 0..=1, default_missing_value = "")]
        fetch: Option<String>,
        /// Only this `[[projects]]` entry (by name; repeatable): the other projects are not listed, probed, verified or run. Not for the single-project form.
        #[arg(long = "project", value_name = "NAME")]
        project: Vec<String>,
    },
    /// Verify one attestation envelope (file path or `-`).
    Verify {
        envelope: Utf8PathBuf,
        /// Trust root (default: .vci/allowed_signers at --base-ref, or HEAD).
        #[arg(long)]
        allowed_signers: Option<Utf8PathBuf>,
        /// For a keyless envelope: the identities (default: .vci/identities.toml at --base-ref, or HEAD).
        #[arg(long)]
        identities: Option<Utf8PathBuf>,
        /// For a keyless envelope: the Sigstore trust root (default: .vci/sigstore-trusted-root.json at --base-ref, or HEAD).
        #[arg(long)]
        trusted_root: Option<Utf8PathBuf>,
        #[arg(long)]
        base_ref: Option<String>,
        /// The input manifest the attestation references (its compact encoding, as `git meta get project vci:manifest:<root>` prints it). Default: read from the local git-meta store when run inside the repository.
        #[arg(long, value_name = "FILE")]
        manifest: Option<Utf8PathBuf>,
    },
    /// Publish local attestations: git-meta push (refs/meta/main) with merge and retry.
    Push {
        /// git-meta remote, or a git remote / URL to exchange metadata with (default: the configured git-meta remote, else .git-meta's url, else origin).
        #[arg(long)]
        remote: Option<String>,
        /// Publish the metadata as one commit without history (after `vci prune`: what a fetch downloads is then the current attestations, not every version ever published). Other clones merge onto it at their next fetch.
        #[arg(long)]
        rewrite_history: bool,
    },
    /// Fetch attestations: git-meta pull (fetch refs/meta/main and materialize it locally).
    Fetch {
        /// git-meta remote, or a git remote / URL to exchange metadata with (default: the configured git-meta remote, else .git-meta's url, else origin).
        #[arg(long)]
        remote: Option<String>,
    },
    /// Delete expired attestations from the local git-meta store (publish with `vci push`).
    Prune {
        /// Only list what would be deleted.
        #[arg(long)]
        dry_run: bool,
        /// Also delete attestations superseded by a newer one of the same unit by the same signer (their inputs no longer match the current tree, or soon will not).
        #[arg(long)]
        superseded: bool,
    },
    /// Print the effective environment policy of each project: what vci sets, hashes, ignores and removes (docs/ENV.md).
    Env {
        /// Also compare with the policy in vci.toml at this ref.
        #[arg(long)]
        base_ref: Option<String>,
        /// Only this project (`[[projects]]` name).
        #[arg(long)]
        project: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        format: EnvFormat,
    },
    /// Show each candidate attestation for a test file (Go: package directory; Cargo: `<package dir>#<target>`) and the first check it failed.
    Explain {
        test_file: String,
        #[arg(long)]
        base_ref: Option<String>,
    },
}

fn explain_id(arg: &str) -> Result<String> {
    // Accept a path relative to cwd (if it exists) or a repo-relative test id.
    let (_, root) = ctx::open_repo()?;
    let cwd = ctx::cwd()?;
    // A Cargo unit: `<package dir>#<target>`, the dir relative to cwd.
    if cwd.join(arg).canonicalize_utf8().is_err()
        && let Some((dir, target)) = arg.rsplit_once('#')
        && let Ok(abs) = cwd
            .join(if dir.is_empty() { "." } else { dir })
            .canonicalize_utf8()
        && let Ok(rel) = abs.strip_prefix(&root)
    {
        let dir = if rel.as_str().is_empty() {
            "."
        } else {
            rel.as_str()
        };
        return Ok(vci_core::RepoPath::new(&format!("{dir}#{target}"))?
            .as_str()
            .to_owned());
    }
    if let Ok(abs) = cwd.join(arg).canonicalize_utf8()
        && let Ok(rel) = abs.strip_prefix(&root)
    {
        // The repository root (a Go module's root package) is spelled `.`.
        return Ok(vci_core::RepoPath::new(if rel.as_str().is_empty() {
            "."
        } else {
            rel.as_str()
        })?
        .as_str()
        .to_owned());
    }
    Ok(vci_core::RepoPath::new(arg)?.as_str().to_owned())
}

/// `--fetch [REMOTE]`: `Some(None)` (bare `--fetch`) fetches from the
/// default remote, as `vci fetch` without `--remote` does.
fn fetch_remote(arg: Option<String>) -> Option<Option<String>> {
    arg.map(|r| Some(r).filter(|r| !r.is_empty()))
}

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Init {
            key,
            principal,
            project,
            adapter,
            no_install,
            meta_url,
            oidc,
        } => cmds::init(
            key.as_deref(),
            principal,
            project,
            adapter,
            !no_install,
            meta_url,
            oidc,
        ),
        Cmd::Run {
            files,
            key,
            oidc,
            ttl,
            summary,
        } => run::run(run::RunArgs {
            files,
            key,
            oidc,
            ttl,
            summary,
        }),
        Cmd::Plan {
            base_ref,
            format,
            fetch,
            project,
        } => plan::plan(&plan::PlanOptions {
            base_ref,
            only: None,
            fetch: fetch_remote(fetch),
            projects: project,
        })
        .and_then(|res| {
            let format = match format {
                Format::Text => "text",
                Format::Json => "json",
                Format::Github => "github",
            };
            // A workflow annotation, except where stdout is JSON.
            if let Some(w) = &res.fetch_failed
                && format != "json"
            {
                println!("::warning title=vci::{}", w.replace(['\r', '\n'], " "));
            }
            plan::print(&res, format)
        })
        .map(|()| 0),
        Cmd::Ci {
            base_ref,
            audit_log,
            key,
            oidc,
            ttl,
            push,
            remote,
            fetch,
            project,
        } => cmds::ci(cmds::CiArgs {
            base_ref,
            audit_log,
            key,
            oidc,
            ttl,
            push,
            remote,
            fetch: fetch_remote(fetch),
            projects: project,
        }),
        Cmd::Verify {
            envelope,
            allowed_signers,
            identities,
            trusted_root,
            base_ref,
            manifest,
        } => cmds::verify(
            &envelope,
            cmds::VerifyTrust {
                allowed_signers: allowed_signers.as_deref(),
                identities: identities.as_deref(),
                trusted_root: trusted_root.as_deref(),
            },
            base_ref.as_deref(),
            manifest.as_deref(),
        ),
        Cmd::Push {
            remote,
            rewrite_history,
        } => cmds::push(remote.as_deref(), rewrite_history),
        Cmd::Fetch { remote } => cmds::fetch(remote.as_deref()),
        Cmd::Prune {
            dry_run,
            superseded,
        } => cmds::prune(dry_run, superseded),
        Cmd::Env {
            base_ref,
            project,
            format,
        } => envcmd::env(envcmd::EnvArgs {
            base_ref,
            project,
            json: matches!(format, EnvFormat::Json),
        }),
        Cmd::Explain {
            test_file,
            base_ref,
        } => explain_id(&test_file).and_then(|id| {
            let res = plan::plan(&plan::PlanOptions {
                base_ref,
                only: Some(id.clone()),
                fetch: None,
                projects: vec![],
            })?;
            plan::explain(&res, &id)
        }),
    };
    match r {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("vci: error: {e:#}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--project NAME` is repeatable on `vci ci` and `vci plan`; without it
    /// every project is selected (an empty list).
    #[test]
    fn project_flag_is_repeatable_on_ci_and_plan() {
        let cli = Cli::try_parse_from([
            "vci",
            "ci",
            "--fetch",
            "origin",
            "--base-ref",
            "abc",
            "--project",
            "vex-web",
            "--project=rails",
        ])
        .unwrap();
        let Cmd::Ci {
            project,
            fetch,
            base_ref,
            ..
        } = cli.cmd
        else {
            panic!("not ci")
        };
        assert_eq!(project, ["vex-web", "rails"]);
        assert_eq!(fetch.as_deref(), Some("origin"));
        assert_eq!(base_ref.as_deref(), Some("abc"));

        let cli = Cli::try_parse_from(["vci", "plan", "--project", "b"]).unwrap();
        let Cmd::Plan { project, .. } = cli.cmd else {
            panic!("not plan")
        };
        assert_eq!(project, ["b"]);

        let cli = Cli::try_parse_from(["vci", "ci"]).unwrap();
        let Cmd::Ci { project, .. } = cli.cmd else {
            panic!("not ci")
        };
        assert!(project.is_empty());

        // A name is required; `vci run` has no --project.
        assert!(Cli::try_parse_from(["vci", "ci", "--project"]).is_err());
        assert!(Cli::try_parse_from(["vci", "run", "--project", "b"]).is_err());
        // `vci env --project` is unchanged (one name).
        let cli = Cli::try_parse_from(["vci", "env", "--project", "b"]).unwrap();
        let Cmd::Env { project, .. } = cli.cmd else {
            panic!("not env")
        };
        assert_eq!(project.as_deref(), Some("b"));
    }
}
