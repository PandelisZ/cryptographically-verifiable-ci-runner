//! Running `git` with a controlled environment.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};

use camino::Utf8Path;

use crate::GitError;

/// Environment variables that would redirect git away from the repository we
/// point it at with `-C`, or change which index it uses.
const SCRUBBED_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_QUARANTINE_PATH",
];

/// Identity used for attestation-ref commits, so storage works where no git
/// user is configured.
pub(crate) const IDENTITY: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "vci"),
    ("GIT_AUTHOR_EMAIL", "vci@localhost"),
    ("GIT_COMMITTER_NAME", "vci"),
    ("GIT_COMMITTER_EMAIL", "vci@localhost"),
];

pub(crate) struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A git invocation under construction.
pub(crate) struct Git {
    cmd: Command,
    display: Vec<String>,
    stdin: Option<Vec<u8>>,
}

impl Git {
    /// `git -C <dir> ...` with a scrubbed, locale-neutral environment.
    pub fn at(dir: &Utf8Path) -> Self {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(dir.as_std_path());
        for var in SCRUBBED_ENV {
            cmd.env_remove(var);
        }
        cmd.env("LC_ALL", "C")
            .env("LANGUAGE", "C")
            // Never let `git status` and friends rewrite the user's index.
            .env("GIT_OPTIONAL_LOCKS", "0")
            // Paths we pass are literal paths, never globs or magic.
            .env("GIT_LITERAL_PATHSPECS", "1")
            // Read objects as they are, not as replace refs say.
            .env("GIT_NO_REPLACE_OBJECTS", "1");
        Git {
            cmd,
            display: Vec::new(),
            stdin: None,
        }
    }

    pub fn arg(mut self, a: impl AsRef<str>) -> Self {
        let a = a.as_ref();
        self.cmd.arg(a);
        self.display.push(a.to_owned());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for a in args {
            self = self.arg(a);
        }
        self
    }

    pub fn env(mut self, k: &str, v: impl AsRef<std::ffi::OsStr>) -> Self {
        self.cmd.env(k, v);
        self
    }

    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }

    fn describe(&self) -> String {
        self.display.join(" ")
    }

    /// Run and return the raw output whatever the exit status.
    pub fn output(mut self) -> Result<Output, GitError> {
        self.cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if self.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let mut child = self.cmd.spawn()?;
        let writer = match (self.stdin.take(), child.stdin.take()) {
            (Some(bytes), Some(mut pipe)) => Some(std::thread::spawn(move || {
                // A broken pipe here means git exited early; its status says why.
                let _ = pipe.write_all(&bytes);
            })),
            _ => None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out_pipe = child.stdout.take().expect("stdout piped");
        let mut err_pipe = child.stderr.take().expect("stderr piped");
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err_pipe.read_to_end(&mut buf);
            buf
        });
        out_pipe.read_to_end(&mut stdout)?;
        stderr.extend(err_reader.join().unwrap_or_default());
        if let Some(w) = writer {
            let _ = w.join();
        }
        let status = child.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    /// Run and require success; returns stdout bytes.
    pub fn run(self) -> Result<Vec<u8>, GitError> {
        let describe = self.describe();
        let out = self.output()?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(command_error(&describe, &out))
        }
    }

    /// Run, require success, and return stdout as trimmed UTF-8.
    pub fn run_str(self) -> Result<String, GitError> {
        let bytes = self.run()?;
        let s = String::from_utf8(bytes).map_err(|_| GitError::NonUtf8)?;
        Ok(s.trim_end_matches(['\n', '\r']).to_owned())
    }

    /// Like `output`, but also returns the command description for errors.
    pub fn output_described(self) -> Result<(String, Output), GitError> {
        let describe = self.describe();
        Ok((describe, self.output()?))
    }
}

pub(crate) fn command_error(describe: &str, out: &Output) -> GitError {
    GitError::Command {
        args: describe.to_owned(),
        status: out.status.to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    }
}
