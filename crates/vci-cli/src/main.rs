//! `vci`: cryptographically verifiable CI test selection.

mod cmds;
mod config;
mod ctx;
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
    },
    /// Run tests, collect their inputs, sign and store attestations.
    Run {
        /// Test files, package directories for Go, `<package dir>#<target>` units or package directories for Cargo (default: all).
        files: Vec<String>,
        /// SSH key for `ssh-keygen -Y sign` (private key, or .pub with the key in ssh-agent).
        #[arg(long)]
        key: Option<Utf8PathBuf>,
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
    },
    /// Plan, run the remaining tests, and write an audit log of the skips (with --key: attest what runs).
    Ci {
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        audit_log: Option<Utf8PathBuf>,
        /// Run the remaining tests as `vci run --key` does and attest them with this SSH key (private key, or .pub with the key in ssh-agent); with run-all (e.g. policy.no_skip_refs), every unit is attested.
        #[arg(long)]
        key: Option<Utf8PathBuf>,
        /// Attestation lifetime (with --key).
        #[arg(long, default_value = "14d", requires = "key")]
        ttl: String,
        /// Afterwards publish the attestations as `vci push` does (best effort: a failure is a warning, never the exit code).
        #[arg(long, requires = "key")]
        push: bool,
        /// git-meta remote, or a git remote / URL, to push to (as `vci push --remote`).
        #[arg(long, requires = "push")]
        remote: Option<String>,
        /// Fetch attestations first, as `vci fetch` does, while the projects are probed (a failure is a warning: only attestations already stored locally are used). REMOTE as in `vci fetch --remote`.
        #[arg(long, value_name = "REMOTE", num_args = 0..=1, default_missing_value = "")]
        fetch: Option<String>,
    },
    /// Verify one attestation envelope (file path or `-`).
    Verify {
        envelope: Utf8PathBuf,
        /// Trust root (default: .vci/allowed_signers at --base-ref, or HEAD).
        #[arg(long)]
        allowed_signers: Option<Utf8PathBuf>,
        #[arg(long)]
        base_ref: Option<String>,
    },
    /// Publish local attestations: git-meta push (refs/meta/main) with merge and retry.
    Push {
        /// git-meta remote, or a git remote / URL to exchange metadata with (default: the configured git-meta remote, else .git-meta's url, else origin).
        #[arg(long)]
        remote: Option<String>,
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
        } => cmds::init(
            key.as_deref(),
            principal,
            project,
            adapter,
            !no_install,
            meta_url,
        ),
        Cmd::Run {
            files,
            key,
            ttl,
            summary,
        } => run::run(run::RunArgs {
            files,
            key,
            ttl,
            summary,
        }),
        Cmd::Plan {
            base_ref,
            format,
            fetch,
        } => plan::plan(&plan::PlanOptions {
            base_ref,
            only: None,
            fetch: fetch_remote(fetch),
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
            ttl,
            push,
            remote,
            fetch,
        } => cmds::ci(cmds::CiArgs {
            base_ref,
            audit_log,
            key,
            ttl,
            push,
            remote,
            fetch: fetch_remote(fetch),
        }),
        Cmd::Verify {
            envelope,
            allowed_signers,
            base_ref,
        } => cmds::verify(&envelope, allowed_signers.as_deref(), base_ref.as_deref()),
        Cmd::Push { remote } => cmds::push(remote.as_deref()),
        Cmd::Fetch { remote } => cmds::fetch(remote.as_deref()),
        Cmd::Prune { dry_run } => cmds::prune(dry_run),
        Cmd::Explain {
            test_file,
            base_ref,
        } => explain_id(&test_file).and_then(|id| {
            let res = plan::plan(&plan::PlanOptions {
                base_ref,
                only: Some(id.clone()),
                fetch: None,
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
