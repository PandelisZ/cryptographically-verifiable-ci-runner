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
    /// Write vci.toml, .vci/allowed_signers and .git-meta, configure the git-meta remote, install @vci/vitest (Vitest), print a CI snippet.
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
        /// Test runner adapter: vitest (default), pytest, go, cargo or rails.
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
    },
    /// Decide which test files can be skipped.
    Plan {
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Plan, run the remaining tests, and write an audit log of the skips.
    Ci {
        #[arg(long)]
        base_ref: Option<String>,
        #[arg(long)]
        audit_log: Option<Utf8PathBuf>,
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
        Cmd::Run { files, key, ttl } => run::run(run::RunArgs { files, key, ttl }),
        Cmd::Plan { base_ref, format } => plan::plan(&plan::PlanOptions {
            base_ref,
            only: None,
        })
        .and_then(|res| {
            plan::print(
                &res,
                match format {
                    Format::Text => "text",
                    Format::Json => "json",
                    Format::Github => "github",
                },
            )
        })
        .map(|()| 0),
        Cmd::Ci {
            base_ref,
            audit_log,
        } => cmds::ci(base_ref, audit_log),
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
