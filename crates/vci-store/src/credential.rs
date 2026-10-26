//! A store's credential: from the environment, or printed by `[store]
//! token_command` the first time the store needs it
//! (`docs/STORE-BACKENDS.md` section 9).
//!
//! `vci.toml` may say how to fetch the credential, never what it is:
//!
//! ```toml
//! [store]
//! backend = "libsql"
//! url = "libsql://vci-acme.aws-eu-west-1.turso.io"
//! token_command = ["com", "secrets", "get", "vci-store-token", "--org", "acme"]
//! ```
//!
//! * **When.** Only when a store that needs a server's credential first
//!   connects (a libSQL server's token, a PostgreSQL password the URL does
//!   not carry), never when the store is selected or opened, nor by a
//!   backend's `warm` ([`Credential::pending`]): a command that does not
//!   read the store never runs it, and it always runs on a thread that
//!   waits for it to end. At most once per process for a command and
//!   working directory: the result, a failure too, is kept in memory
//!   ([`Credential::command`]), never on disk.
//! * **Whose.** The checkout's. The command and the URL its output is
//!   sent to both come from the working tree's `vci.toml`, so any vci
//!   command that reads the store (`vci plan` included) runs that
//!   checkout's command, with the user's privileges, and sends what it
//!   prints to that checkout's `[store] url`: a change to either needs the
//!   same review, and in a checkout not yet reviewed `VCI_STORE=git-meta`
//!   keeps both from being used.
//! * **How.** An array is the program and its arguments, run directly; a
//!   string is run with `sh -c` (a pipeline). The working directory is the
//!   repository's top level (a program path holding a `/` is relative to
//!   it), stdin is `/dev/null`, and the environment is vci's own without
//!   [`crate::select::NEVER_TO_CHILDREN`] (`VCI_STORE_URL`,
//!   `VCI_STORE_TOKEN`, `VCI_STORE`): a credential from the environment is
//!   never handed to the command.
//! * **What it prints.** Standard output, at most [`MAX_OUTPUT`] bytes:
//!   UTF-8, one line once surrounding whitespace is trimmed, not empty.
//!   It becomes a [`Secret::opaque`], redacted wherever it could be
//!   printed. Standard error is captured (its last [`MAX_OUTPUT`] bytes),
//!   shown only when the command fails: an excerpt, scrubbed of whatever
//!   standard output held however it was framed (quoted, beside an escape
//!   sequence or a byte that is not UTF-8), and not shown at all when
//!   standard output went past its limit, since what it held is not known.
//! * **Bounded.** On unix the command leads a process group of its own.
//!   After [`TIMEOUT`] (or the store's connect timeout, when longer) the
//!   whole group is killed, so a pipeline or a wrapper script leaves
//!   nothing running, and the command is waited for. Being outside the
//!   terminal's foreground group, it cannot prompt there (the system stops
//!   a process that reads the terminal, until the timeout), and a Ctrl-C
//!   that stops vci does not reach it: it is left to end on its own.
//! * **Failure** (not found, a non-zero exit, a timeout, nothing printed, more
//!   than one line) is [`StoreError::Unavailable`] for the backend: the
//!   store cannot be used, so `vci plan` runs everything with a warning
//!   saying why, and `vci fetch`, `vci push`, `vci prune` and `vci store
//!   info` exit 2. Nothing the command printed on standard output is ever
//!   shown.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::select::{NEVER_TO_CHILDREN, Secret};

/// How long a token command may take, at least (a store's longer connect
/// timeout raises it).
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// The most a token command may print on standard output (or keep of its
/// standard error).
pub const MAX_OUTPUT: usize = 64 * 1024;

/// The longest excerpt of standard error a failure shows, in characters.
const EXCERPT: usize = 400;

/// The longest command a message shows, in characters.
const SHOWN: usize = 200;

/// `[store] token_command`: a command that prints the store's credential
/// on standard output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(untagged)]
pub enum TokenCommand {
    /// `["program", "arg", ...]`: run directly, with no shell.
    Argv(Vec<String>),
    /// `"a | b"`: run with `sh -c`, for a pipeline.
    Shell(String),
}

impl<'de> Deserialize<'de> for TokenCommand {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = TokenCommand;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a command: an array of strings (run directly) or a string (run with sh -c)",
                )
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<TokenCommand, E> {
                Ok(TokenCommand::Shell(v.to_owned()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<TokenCommand, A::Error> {
                let mut argv = Vec::new();
                while let Some(arg) = seq.next_element::<String>()? {
                    argv.push(arg);
                }
                Ok(TokenCommand::Argv(argv))
            }
        }
        d.deserialize_any(Visit)
    }
}

impl TokenCommand {
    /// Refuse an empty command, or one holding a NUL byte.
    pub fn check(&self) -> Result<(), StoreError> {
        let refuse = |why: &str| {
            Err(StoreError::Config(format!(
                "vci.toml [store] token_command {why}: expected [\"program\", \"argument\", ...] (run directly) or a string (run with sh -c)"
            )))
        };
        let (empty, nul) = match self {
            TokenCommand::Argv(argv) => (
                argv.first().is_none_or(|p| p.trim().is_empty()),
                argv.iter().any(|a| a.contains('\0')),
            ),
            TokenCommand::Shell(s) => (s.trim().is_empty(), s.contains('\0')),
        };
        if empty {
            return refuse("is empty");
        }
        if nul {
            return refuse("holds a NUL byte");
        }
        Ok(())
    }

    /// The command as messages and `vci store info` show it: the program
    /// and its arguments joined by spaces (one holding a space or a quote
    /// is quoted), or `sh -c '<script>'`; at most 200 characters. It comes
    /// from `vci.toml`, which every checkout carries: it is not a secret.
    pub fn display(&self) -> String {
        let quoted = |a: &str| {
            if !a.is_empty()
                && !a
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || "'\"\\$`".contains(c))
            {
                a.to_owned()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        };
        let s = match self {
            TokenCommand::Argv(argv) => {
                argv.iter().map(|a| quoted(a)).collect::<Vec<_>>().join(" ")
            }
            TokenCommand::Shell(s) => format!("sh -c {}", quoted(s)),
        };
        let s: String = s
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if s.chars().count() <= SHOWN {
            s
        } else {
            let head: String = s.chars().take(SHOWN - 1).collect();
            format!("{head}…")
        }
    }

    /// The process to start, in `cwd`: no shell for an array, `sh -c` for
    /// a string; stdin `/dev/null`, stdout and stderr captured; vci's
    /// environment without [`NEVER_TO_CHILDREN`]; on unix, the leader of a
    /// process group of its own, which a timeout kills whole ([`stop`]).
    pub(crate) fn command(&self, cwd: &Path) -> Command {
        let mut c = match self {
            TokenCommand::Argv(argv) => {
                let program = &argv[0];
                // A relative path with a `/` is the checkout's
                // (`scripts/vci-token`), wherever vci was started; a bare
                // name is looked up on PATH.
                let mut c = if program.contains('/') && Path::new(program).is_relative() {
                    Command::new(cwd.join(program))
                } else {
                    Command::new(program)
                };
                c.args(&argv[1..]);
                c
            }
            TokenCommand::Shell(s) => {
                let mut c = Command::new("sh");
                c.arg("-c").arg(s);
                c
            }
        };
        c.current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in NEVER_TO_CHILDREN {
            c.env_remove(name);
        }
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut c, 0);
        c
    }
}

/// What a token command printed, or why it could not be used.
type Fetched = Result<Secret, String>;

/// The result of each command run in this process, by command and working
/// directory.
type Cells = BTreeMap<(TokenCommand, PathBuf), Arc<OnceLock<Fetched>>>;

static FETCHED: Mutex<Cells> = Mutex::new(BTreeMap::new());

/// A store's credential, as a backend uses it: given (from the environment
/// or the URL), or printed by `[store] token_command` when first asked for.
/// `Debug` never shows it.
#[derive(Clone)]
pub struct Credential(Inner);

#[derive(Clone)]
enum Inner {
    Given {
        secret: Secret,
        origin: String,
    },
    Command {
        command: TokenCommand,
        cwd: PathBuf,
        timeout: Duration,
        cell: Arc<OnceLock<Fetched>>,
    },
}

impl Credential {
    /// A credential already known, and where it came from (`$VCI_STORE_TOKEN`,
    /// `the URL's authToken`), for messages.
    pub fn given(secret: Secret, origin: impl Into<String>) -> Credential {
        Credential(Inner::Given {
            secret,
            origin: origin.into(),
        })
    }

    /// The credential `command` prints when run in `cwd` (the repository's
    /// top level), killed after `timeout`. Nothing runs here: it runs the
    /// first time [`Credential::get`] is called, and only once per process
    /// for the same command and directory, whichever credential asks.
    pub fn command(command: TokenCommand, cwd: impl Into<PathBuf>, timeout: Duration) -> Self {
        let cwd = cwd.into();
        let cell = FETCHED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((command.clone(), cwd.clone()))
            .or_default()
            .clone();
        Credential(Inner::Command {
            command,
            cwd,
            timeout,
            cell,
        })
    }

    /// The credential, running the command the first time it is asked for
    /// in this process (other threads wait for that run). A command that
    /// failed is [`StoreError::Unavailable`] for `backend`, at once on
    /// every later call.
    pub fn get(&self, backend: &'static str) -> Result<Secret, StoreError> {
        match &self.0 {
            Inner::Given { secret, .. } => Ok(secret.clone()),
            Inner::Command {
                command,
                cwd,
                timeout,
                cell,
            } => cell
                .get_or_init(|| run(command, cwd, *timeout))
                .clone()
                .map_err(|why| StoreError::unavailable(backend, why)),
        }
    }

    /// Whether it comes from `[store] token_command`.
    pub fn from_command(&self) -> bool {
        matches!(self.0, Inner::Command { .. })
    }

    /// Whether asking for it now would run the command: it comes from
    /// `[store] token_command` and no run of it in this process has ended.
    /// A backend's `warm` does nothing then, so that the command runs only
    /// on a thread that waits for it (a warm-up thread is never joined: a
    /// command it started would outlive vci and its timeout), and only for
    /// a command that reads the store.
    pub fn pending(&self) -> bool {
        match &self.0 {
            Inner::Given { .. } => false,
            Inner::Command { cell, .. } => cell.get().is_none(),
        }
    }

    /// How long the command may run before it is stopped; `None` for a
    /// credential given.
    pub fn timeout(&self) -> Option<Duration> {
        match &self.0 {
            Inner::Given { .. } => None,
            Inner::Command { timeout, .. } => Some(*timeout),
        }
    }

    /// Where it comes from, for messages: `$VCI_STORE_TOKEN`, `the URL's
    /// authToken`, or `[store] token_command (<command>)`.
    pub fn origin(&self) -> String {
        match &self.0 {
            Inner::Given { origin, .. } => origin.clone(),
            Inner::Command { command, .. } => {
                format!("[store] token_command ({})", command.display())
            }
        }
    }

    /// `text` without the credential ([`Secret::scrub`]), once it is known.
    pub fn scrub(&self, text: &str) -> String {
        let known = match &self.0 {
            Inner::Given { secret, .. } => Some(secret),
            Inner::Command { cell, .. } => cell.get().and_then(|r| r.as_ref().ok()),
        };
        match known {
            Some(s) => s.scrub(text),
            None => text.to_owned(),
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential({})", self.origin())
    }
}

/// What one pipe of the command carried: at most [`MAX_OUTPUT`] bytes (the
/// first, or the last: [`drain`]), and whether there was more.
#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    overflow: bool,
}

/// A pipe of the command, read on a thread of its own.
struct Drained {
    /// What it carried so far.
    so_far: Arc<Mutex<Captured>>,
    /// Closed (or sent to) once the pipe is at its end.
    end: mpsc::Receiver<()>,
}

/// Read `pipe` to its end on a thread of its own, keeping [`MAX_OUTPUT`]
/// bytes (its first, or with `tail` its last) and discarding the rest, so
/// the command never blocks on a full pipe.
fn drain(pipe: Option<impl Read + Send + 'static>, tail: bool) -> Drained {
    let (tx, end) = mpsc::channel();
    let so_far = Arc::new(Mutex::new(Captured::default()));
    let c = Arc::clone(&so_far);
    if let Some(mut pipe) = pipe {
        // A thread that cannot start drops `tx`: nothing is captured.
        let _ = std::thread::Builder::new()
            .name("vci-token-command".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
                            if tail {
                                c.bytes.extend_from_slice(&buf[..n]);
                                let over = c.bytes.len().saturating_sub(MAX_OUTPUT);
                                if over > 0 {
                                    c.bytes.drain(..over);
                                    c.overflow = true;
                                }
                            } else {
                                let room = MAX_OUTPUT.saturating_sub(c.bytes.len());
                                c.overflow |= n > room;
                                c.bytes.extend_from_slice(&buf[..n.min(room)]);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let _ = tx.send(());
            });
    }
    Drained { so_far, end }
}

impl Drained {
    /// What the pipe carried, once it is at its end or `until` comes (a
    /// process the command started may hold it open: what the command
    /// wrote before it exited is read by then).
    fn take(self, until: Instant) -> Captured {
        let _ = self
            .end
            .recv_timeout(until.saturating_duration_since(Instant::now()));
        std::mem::take(&mut *self.so_far.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The most pieces of standard output [`excerpt`] scrubs standard error
/// of; with more, standard error is not shown.
const PIECES: usize = 256;

/// Every piece of what the command printed on standard output that could
/// be (or hold) the credential, longest first: the whole and each line
/// (trimmed, of three bytes or more); each piece of six bytes or more
/// between separators of five kinds, each finer than the last (whitespace,
/// control characters and the replacement of a byte that is not UTF-8, as
/// in `<token>\x1b[0m`; those, quotes and brackets, as in
/// `{"value":"<token>"}`; those and `,:;=`, as in `token=<token>`; any
/// character a token is not made of, `[A-Za-z0-9._~+/=-]`; those and `/`
/// and `.`, as in `https://vault/v1/<token>/`); and what follows the first
/// `=` or `:` of a piece between quotes (`token=<base64 token>==`,
/// `"t":"<a:b>"`). Each piece is kept as it is and also without the
/// characters a token may hold but rarely ends with (`._~+/-`) at its ends,
/// as in `Fetched <token>.` or `--<token>--`. The same again once terminal
/// escape sequences are taken out (`\x1b[1m<token>`). `None` when there
/// are more than [`PIECES`] of them.
fn printed_pieces(out: &str) -> Option<Vec<String>> {
    let space = |c: char| c.is_whitespace() || c.is_control() || c == char::REPLACEMENT_CHARACTER;
    let quote = |c: char| space(c) || "\"'`{}[]()<>".contains(c);
    let punct = |c: char| quote(c) || ",:;=".contains(c);
    let other = |c: char| !(c.is_ascii_alphanumeric() || "._~+/=-".contains(c));
    let path = |c: char| other(c) || "/.".contains(c);
    let mut pieces = std::collections::BTreeSet::new();
    let mut add = |p: &str, min: usize| {
        let p = p.trim();
        for p in [p, p.trim_matches(|c: char| "._~+/-".contains(c))] {
            if p.len() >= min {
                pieces.insert(p.to_owned());
            }
        }
    };
    let plain = strip_escapes(out);
    for text in [out, plain.as_str()] {
        add(text, 3);
        text.lines().for_each(|l| add(l, 3));
        for sep in [
            &space as &dyn Fn(char) -> bool,
            &quote,
            &punct,
            &other,
            &path,
        ] {
            text.split(sep).for_each(|p| add(p, 6));
        }
        // A value after its key (`token=<token>==`, `token:<a:b>`).
        for p in text.split(quote) {
            if let Some((_, v)) = p.split_once(['=', ':']) {
                add(v, 6);
            }
        }
    }
    if pieces.len() > PIECES {
        return None;
    }
    let mut pieces: Vec<String> = pieces.into_iter().collect();
    pieces.sort_by_key(|p| std::cmp::Reverse(p.len()));
    Some(pieces)
}

/// `s` with each terminal escape sequence (`ESC [ ... <final>`, `ESC ] ...
/// BEL` or `ESC ] ... ESC \`, `ESC <one character>`) replaced by a space.
fn strip_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // Parameters and intermediates, then one final byte.
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
        out.push(' ');
    }
    out
}

/// The end of `stderr` as one line of at most [`EXCERPT`] characters, with
/// whatever `stdout` printed removed first ([`printed_pieces`]: a command
/// that failed may have printed a credential, and echoed it on standard
/// error). Empty when standard output went past [`MAX_OUTPUT`] (what it
/// held is not all known) or held too many pieces to scrub. When standard
/// error went past it, its first word, which may be the end of one cut in
/// two, is dropped.
fn excerpt(stderr: &Captured, stdout: &Captured) -> String {
    if stdout.overflow {
        return String::new();
    }
    let out = String::from_utf8_lossy(&stdout.bytes);
    let Some(printed) = printed_pieces(&out) else {
        return String::new();
    };
    let mut text = String::from_utf8_lossy(&stderr.bytes).into_owned();
    if stderr.overflow {
        text = text
            .split_once(char::is_whitespace)
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default();
    }
    for p in printed {
        text = Secret::opaque(p).scrub(&text);
    }
    let flat: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let n = flat.chars().count();
    if n <= EXCERPT {
        return flat;
    }
    let tail: String = flat.chars().skip(n - (EXCERPT - 1)).collect();
    format!("…{tail}")
}

/// Kill `child` and every process of its group (it leads one:
/// [`TokenCommand::command`]), so that a pipeline's stages or what a
/// wrapper script started do not outlive it, then reap it. The group is
/// killed (with the `kill` utility: this crate has no unsafe code to call
/// `kill(2)`) before the child is reaped, so its number cannot have been
/// taken by another group yet.
fn stop(child: &mut Child) {
    #[cfg(unix)]
    {
        let mut kill = Command::new("kill");
        kill.args(["-KILL", &format!("-{}", child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in NEVER_TO_CHILDREN {
            kill.env_remove(name);
        }
        let _ = kill.status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// How the command ended, in words.
fn ended(status: ExitStatus) -> String {
    if let Some(n) = status.code() {
        return format!("exited {n}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(sig) = status.signal() {
            return format!("was killed by signal {sig}");
        }
    }
    format!("ended ({status})")
}

/// Run `cmd` in `cwd`, for at most `timeout`, and take the credential it
/// printed. The error says what went wrong, never what it printed on
/// standard output.
fn run(cmd: &TokenCommand, cwd: &Path, timeout: Duration) -> Fetched {
    let what = format!("the token_command ({})", cmd.display());
    let mut child = cmd.command(cwd).spawn().map_err(|e| {
        if !cwd.is_dir() {
            format!(
                "{what} could not be started in {}, which is not a directory ({e})",
                cwd.display()
            )
        } else if e.kind() == std::io::ErrorKind::NotFound {
            format!("{what} was not found ({e})")
        } else {
            format!("{what} could not be started ({e})")
        }
    })?;
    let out = drain(child.stdout.take(), false);
    let err = drain(child.stderr.take(), true);
    let deadline = Instant::now() + timeout;
    let mut pause = Duration::from_millis(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if Instant::now() >= deadline => {
                stop(&mut child);
                break Err(format!(
                    "{what} did not finish within {} (it was stopped)",
                    seconds(timeout)
                ));
            }
            Ok(None) => {
                std::thread::sleep(pause.min(deadline.saturating_duration_since(Instant::now())));
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            Err(e) => {
                stop(&mut child);
                break Err(format!("{what}: cannot wait for it ({e})"));
            }
        }
    };
    // Its pipes close as it exits, unless a process it started (a daemon
    // a secrets tool leaves running) keeps them open: what it wrote is
    // read within a second.
    let until = Instant::now() + Duration::from_secs(1);
    let stdout = out.take(until);
    let stderr = err.take(until);
    let shown = excerpt(&stderr, &stdout);
    let with = |msg: String| {
        if shown.is_empty() {
            msg
        } else {
            format!("{msg}: {shown}")
        }
    };
    let status = status.map_err(with)?;
    if !status.success() {
        return Err(with(format!("{what} {}", ended(status))));
    }
    if stdout.overflow {
        return Err(with(format!(
            "{what} printed more than {} KiB on standard output (not printed)",
            MAX_OUTPUT / 1024
        )));
    }
    let Ok(text) = std::str::from_utf8(&stdout.bytes) else {
        return Err(with(format!(
            "{what} printed something that is not UTF-8 text on standard output (not printed)"
        )));
    };
    let token = text.trim();
    if token.is_empty() {
        return Err(with(format!("{what} printed nothing on standard output")));
    }
    if token.contains(['\n', '\r']) {
        return Err(with(format!(
            "{what} printed more than one line on standard output (not printed): it must print the credential alone"
        )));
    }
    if token.chars().any(char::is_control) {
        return Err(with(format!(
            "{what} printed a control character on standard output (not printed)"
        )));
    }
    Ok(Secret::opaque(token))
}

fn seconds(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s.fract() == 0.0 {
        format!("{s:.0} s")
    } else {
        format!("{s} s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command's process never receives the variables vci keeps from
    /// children, whatever vci's own environment holds; it runs in the
    /// directory given (its stdin: `tests/credential.rs`,
    /// `the_command_never_reads_vcis_stdin`).
    #[test]
    fn the_command_gets_no_store_secret() {
        for cmd in [
            TokenCommand::Argv(vec!["printenv".into()]),
            TokenCommand::Shell("printenv".into()),
        ] {
            let c = cmd.command(Path::new("/repo"));
            let removed: Vec<String> = c
                .get_envs()
                .filter(|(_, v)| v.is_none())
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .collect();
            for name in NEVER_TO_CHILDREN {
                assert!(removed.iter().any(|r| r == name), "{name}: {removed:?}");
            }
            assert_eq!(c.get_current_dir(), Some(Path::new("/repo")));
        }
        let c = TokenCommand::Shell("a | b".into()).command(Path::new("/repo"));
        assert_eq!(c.get_program(), "sh");
        let args: Vec<_> = c.get_args().collect();
        assert_eq!(args, ["-c", "a | b"]);
        // A relative program path with a `/` is the checkout's.
        let c = TokenCommand::Argv(vec!["scripts/token".into(), "x".into()])
            .command(Path::new("/repo"));
        assert_eq!(c.get_program(), "/repo/scripts/token");
        let c = TokenCommand::Argv(vec!["com".into()]).command(Path::new("/repo"));
        assert_eq!(c.get_program(), "com");
    }

    #[test]
    fn the_command_is_shown_quoted_and_bounded() {
        let argv = |a: &[&str]| TokenCommand::Argv(a.iter().map(|s| (*s).to_owned()).collect());
        assert_eq!(
            argv(&["com", "secrets", "get", "vci-store-token", "--org", "vex"]).display(),
            "com secrets get vci-store-token --org vex"
        );
        assert_eq!(
            argv(&["op", "read", "op://ci vault/vci/token"]).display(),
            "op read 'op://ci vault/vci/token'"
        );
        assert_eq!(
            TokenCommand::Shell("pass show vci | head -1".into()).display(),
            "sh -c 'pass show vci | head -1'"
        );
        let long = TokenCommand::Shell("x".repeat(500)).display();
        assert_eq!(long.chars().count(), SHOWN);
        assert!(long.ends_with('…'));
    }

    fn cap(bytes: &[u8]) -> Captured {
        Captured {
            bytes: bytes.to_vec(),
            overflow: false,
        }
    }

    /// Standard error is shown as one bounded line, without anything
    /// standard output held.
    #[test]
    fn the_excerpt_hides_what_stdout_printed() {
        let e = excerpt(
            &cap(b"error: token tok3nS3cretVal is expired\nretry later\n"),
            &cap(b"  tok3nS3cretVal\n"),
        );
        assert_eq!(e, "error: token *** is expired retry later");
        let e = excerpt(
            &cap(b"partial: abcdefghij\n"),
            &cap(b"abcdefghij klm\nsecond line\n"),
        );
        assert!(!e.contains("abcdefghij"), "{e}");
        let long = excerpt(
            &cap(format!("{}END", "x".repeat(5000)).as_bytes()),
            &cap(b""),
        );
        assert_eq!(long.chars().count(), EXCERPT);
        assert!(long.starts_with('…') && long.ends_with("END"), "{long}");
    }

    /// The credential is found in standard output however it was framed,
    /// and removed from standard error wherever it stands there.
    #[test]
    fn the_excerpt_finds_the_credential_in_any_frame() {
        const T: &str = "tok3n.S3cret_Val-9+/x==";
        let err = format!("debug: fetched {T} (23 bytes)\nsee also x{T}y and \"{T}\"\n");
        for out in [
            format!("{{\n  \"value\": \"{T}\"\n}}\n"),
            format!("{{\"value\":\"{T}\",\"version\":3}}"),
            format!("{T}\x1b[0m\n"),
            format!("\x1b[1m{T}"),
            format!("token={T}\n"),
            format!("token: {T};"),
            format!("<{T}>"),
            format!("({T})"),
            format!("'{T}'"),
            format!("`{T}`"),
            format!("Your token: {T}.\nIt expires in 1h.\n"),
            format!("--{T}--"),
            format!("+{T}+\n"),
            format!("~{T}~"),
        ] {
            let e = excerpt(&cap(err.as_bytes()), &cap(out.as_bytes()));
            assert!(!e.contains("S3cret"), "{out:?}: {e}");
            assert!(
                e.starts_with("debug: fetched *** (23 bytes) see also x***y and "),
                "{out:?}: {e}"
            );
        }
        // A byte that is not UTF-8 beside it.
        let mut out = T.as_bytes().to_vec();
        out.extend_from_slice(b"\xff\n");
        let e = excerpt(&cap(err.as_bytes()), &cap(&out));
        assert!(
            !e.contains(T) && e.starts_with("debug: fetched *** "),
            "{e}"
        );
        // A token holding punctuation, inside JSON.
        let e = excerpt(
            &cap(b"bad: abc:defghi:jklmno\n"),
            &cap(b"{\"t\":\"abc:defghi:jklmno\"}"),
        );
        assert_eq!(e, "bad: ***");
    }

    /// The credential is found when standard output put a character a token
    /// may hold right beside it: a sentence's period, dashes, a path's
    /// slashes.
    #[test]
    fn the_excerpt_finds_the_credential_beside_token_punctuation() {
        const T: &str = "tok3nS3cretVal";
        let err = cap(format!("debug: fetched {T} from vault\n").as_bytes());
        for out in [
            format!("Your token: {T}.\nIt expires in 1h.\n"),
            format!("Fetched {T}.\n"),
            format!("--{T}--\n"),
            format!("https://v/x/{T}/\n"),
            format!("https://vault.example/v1/{T}/\n"),
            format!("_{T}_ ~{T}~ +{T}+\n"),
            format!("{T}.{T}\n"),
        ] {
            let e = excerpt(&err, &cap(out.as_bytes()));
            assert_eq!(e, "debug: fetched *** from vault", "{out:?}");
        }
    }

    /// Standard output past its limit is not all known: standard error is
    /// not shown. So it is when standard output holds too many pieces to
    /// scrub.
    #[test]
    fn the_excerpt_is_empty_when_stdout_is_not_all_known() {
        let err = cap(b"debug: fetched tok3nS3cretVal\n");
        let mut out = cap(&vec![b'a'; MAX_OUTPUT]);
        out.overflow = true;
        assert_eq!(excerpt(&err, &out), "");
        let words: String = (0..=PIECES).map(|i| format!("word{i:04} ")).collect();
        assert_eq!(excerpt(&err, &cap(words.as_bytes())), "");
        assert_eq!(excerpt(&err, &cap(b"tok3nS3cretVal")), "debug: fetched ***");
    }

    /// Standard error past its limit keeps its end, without its first word,
    /// which may be what is left of one cut in two.
    #[test]
    fn standard_error_keeps_its_end_without_a_cut_word() {
        let mut err = cap(b"S3cretVal and the end of it\n");
        err.overflow = true;
        assert_eq!(excerpt(&err, &cap(b"tok3nS3cretVal")), "and the end of it");
        let mut big = vec![b'x'; MAX_OUTPUT + 10];
        big.extend_from_slice(b" END");
        let c = drain(Some(std::io::Cursor::new(big)), true)
            .take(Instant::now() + Duration::from_secs(10));
        assert!(c.overflow);
        assert_eq!(c.bytes.len(), MAX_OUTPUT);
        assert!(c.bytes.ends_with(b"x END"));
    }
}
