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
    /// Write vci.toml and .vci/allowed_signers, install @vci/vitest (Vitest), print a CI snippet.
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
        /// Test runner adapter: vitest (default) or pytest.
        #[arg(long)]
        adapter: Option<String>,
        /// Do not run npm install.
        #[arg(long)]
        no_install: bool,
    },
    /// Run tests, collect their inputs, sign and store attestations.
    Run {
        /// Test files (default: all).
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
    /// Push attestation refs.
    Push {
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Fetch attestation refs and merge them into the local ones.
    Fetch {
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Show each candidate attestation for a test file and the first check it failed.
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
    if let Ok(abs) = cwd.join(arg).canonicalize_utf8()
        && let Ok(rel) = abs.strip_prefix(&root)
    {
        return Ok(rel.as_str().to_owned());
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
        } => cmds::init(key.as_deref(), principal, project, adapter, !no_install),
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
        Cmd::Push { remote } => cmds::push(&remote),
        Cmd::Fetch { remote } => cmds::fetch(&remote),
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
