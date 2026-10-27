//! `[store] token_command`: the command runs where and when it should, at
//! most once per process, within its time, and its credential (or anything
//! it printed, on standard output or standard error) never reaches a
//! message.

#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use vci_store::credential::{Credential, HINT, MAX_OUTPUT, TokenCommand};
use vci_store::select::{Secret, Selection, resolve};
use vci_store::{OpenContext, StoreError};

/// A made-up token.
const TOKEN: &str = "credT0kenS3cretX9";

/// A directory of its own, removed when dropped.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

mod tempfile {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    pub fn tempdir() -> std::io::Result<super::TempDir> {
        let p = std::env::temp_dir().join(format!(
            "vci-credential-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p)?;
        Ok(super::TempDir(p))
    }
}

fn script(dir: &Path, name: &str, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt as _;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_str().unwrap().to_owned()
}

fn argv(a: &[&str]) -> TokenCommand {
    TokenCommand::Argv(a.iter().map(|s| (*s).to_owned()).collect())
}

fn fetch(cmd: TokenCommand, dir: &Path, timeout: Duration) -> Result<Secret, StoreError> {
    Credential::command(cmd, dir, timeout).get("libsql")
}

fn runs(counter: &Path) -> usize {
    std::fs::read_to_string(counter)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// What it prints, trimmed, is the credential: opaque, redacted
/// everywhere, scrubbed from text once known. It runs in the directory
/// given, and at most once per process for a command and directory,
/// whichever credential asks, from however many threads.
#[test]
fn the_credential_is_what_it_prints_fetched_once() {
    let dir = tempfile::tempdir().unwrap();
    let counter = dir.path().join("runs");
    let helper = script(
        dir.path(),
        "helper",
        &format!(
            "pwd >> {counter:?}\nprintf '  {TOKEN}\\n\\n'",
            counter = counter.to_str().unwrap()
        ),
    );
    let cmd = argv(&[&helper, "--org", "vex"]);
    let a = Credential::command(cmd.clone(), dir.path(), Duration::from_secs(30));
    assert!(a.from_command());
    assert_eq!(runs(&counter), 0, "nothing runs before it is asked for");
    assert_eq!(a.scrub(&format!("x {TOKEN}")), format!("x {TOKEN}"));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let c = Credential::command(cmd.clone(), dir.path(), Duration::from_secs(30));
            std::thread::spawn(move || c.get("libsql").unwrap())
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap().expose(), TOKEN);
    }
    let got = a.get("libsql").unwrap();
    assert_eq!(got.expose(), TOKEN);
    assert_eq!(got.redacted(), "***");
    assert_eq!(
        format!("{got:?} {a:?}"),
        format!("Secret(***) Credential([store] token_command ({helper} --org vex))")
    );
    assert_eq!(runs(&counter), 1, "one run per process");
    let pwd = std::fs::read_to_string(&counter).unwrap();
    assert_eq!(
        Path::new(pwd.trim()).canonicalize().unwrap(),
        dir.path().canonicalize().unwrap()
    );
    assert_eq!(a.scrub(&format!("401 for {TOKEN}")), "401 for ***");
    // Another directory is another run.
    let other = tempfile::tempdir().unwrap();
    assert_eq!(
        fetch(cmd, other.path(), Duration::from_secs(30))
            .unwrap()
            .expose(),
        TOKEN
    );
    assert_eq!(runs(&counter), 2);
}

/// A string runs with `sh -c` (a pipeline); a relative program path with
/// a `/` is the directory's.
#[test]
fn a_string_runs_in_a_shell_and_a_relative_program_in_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("scripts")).unwrap();
    script(dir.path(), "scripts/token", &format!("echo {TOKEN}"));
    let t = fetch(
        TokenCommand::Shell(format!("echo 'x {TOKEN} y' | cut -d ' ' -f 2")),
        dir.path(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(t.expose(), TOKEN);
    let t = fetch(
        argv(&["scripts/token"]),
        dir.path(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(t.expose(), TOKEN);
}

/// A command that cannot give a credential is the store's failure
/// (unavailable), saying what went wrong, naming the command and ending
/// with the hint to run it, never showing anything it printed, on standard
/// output or standard error.
#[test]
fn a_command_that_fails_says_why_and_shows_nothing_it_printed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let t = Duration::from_secs(30);
    let cases: Vec<(TokenCommand, &str)> = vec![
        (
            argv(&[&script(
                d,
                "exit3",
                &format!("echo {TOKEN}\necho \"not allowed: {TOKEN} is a member's\" >&2\nexit 3"),
            )]),
            "exited 3",
        ),
        (
            argv(&[d.join("no-such-helper").to_str().unwrap()]),
            "was not found (",
        ),
        (
            TokenCommand::Shell("no-such-helper-anywhere --org vex".into()),
            "exited 127",
        ),
        (
            argv(&[&script(d, "empty", "printf '  \\n'")]),
            "printed nothing on standard output",
        ),
        (
            argv(&[&script(
                d,
                "lines",
                &format!("echo {TOKEN}\necho second-{TOKEN}"),
            )]),
            "printed more than one line on standard output: it must print the credential alone",
        ),
        (
            argv(&[&script(d, "binary", "printf 'tok\\377en'")]),
            "printed something that is not UTF-8 text on standard output",
        ),
        (
            argv(&[&script(d, "control", &format!("printf '{TOKEN}\\033[0m'"))]),
            "printed a control character on standard output",
        ),
        (
            argv(&[&script(
                d,
                "big",
                &format!(
                    "i=0; while [ $i -lt 20 ]; do head -c 4096 /dev/zero | tr '\\0' 'a'; i=$((i+1)); done; echo {TOKEN}"
                ),
            )]),
            "printed more than 64 KiB on standard output",
        ),
        (
            argv(&[&script(d, "killed", &format!("echo {TOKEN}\nkill -9 $$"))]),
            "was killed by signal 9",
        ),
    ];
    assert_eq!(MAX_OUTPUT, 64 * 1024);
    for (cmd, says) in cases {
        let e = fetch(cmd.clone(), d, t).unwrap_err();
        let m = e.to_string();
        assert!(
            matches!(
                e,
                StoreError::Unavailable {
                    backend: "libsql",
                    ..
                }
            ),
            "{m}"
        );
        let head = format!(
            "libsql store unavailable: the token_command ({}) {says}",
            cmd.display()
        );
        assert!(m.starts_with(&head), "{cmd:?}: {m}");
        assert!(m.ends_with(&format!("; {HINT}")), "{cmd:?}: {m}");
        if !says.ends_with('(') {
            assert_eq!(m, format!("{head}; {HINT}"));
        }
        assert!(!m.contains(TOKEN) && !m.contains("allowed"), "{cmd:?}: {m}");
        // The failure is kept: asked again, nothing runs again.
        assert_eq!(fetch(cmd, d, t).unwrap_err().to_string(), m);
    }
    // A directory that is not there is named, not taken for the program.
    let gone = d.join("gone");
    let m = fetch(argv(&["true"]), &gone, t).unwrap_err().to_string();
    assert!(
        m.contains(&format!(
            "could not be started in {}, which is not a directory",
            gone.display()
        )),
        "{m}"
    );
}

/// The hint says to run the command with its standard output discarded,
/// not plainly: a command that works prints the credential on standard
/// output, which would put it in a terminal's scrollback or an agent's
/// transcript. Run that way, a helper that prints a token and fails shows
/// its error and not the token.
#[test]
fn the_hint_says_to_discard_standard_output() {
    assert!(
        HINT.ends_with(
            "run the command yourself with its standard output discarded (> /dev/null) to see why"
        ),
        "{HINT}"
    );
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let helper = script(
        d,
        "half-signed-in",
        &format!("echo {TOKEN}\necho 'session expired: sign in again' >&2\nexit 3"),
    );
    let m = fetch(argv(&[&helper]), d, Duration::from_secs(30))
        .unwrap_err()
        .to_string();
    assert!(m.ends_with(&format!("exited 3; {HINT}")), "{m}");
    // What the hint says to do, as a person or an agent would type it.
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("'{helper}' > /dev/null"))
        .output()
        .unwrap();
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(3), "{shown}");
    assert!(shown.contains("session expired: sign in again"), "{shown}");
    assert!(!shown.contains(TOKEN), "{shown}");
}

/// What a command that fails wrote on standard error is never shown,
/// whatever it held: the credential in any frame, which no scrubbing of
/// standard output could find. Each helper puts a canary on standard error
/// beside the credential, as a real tool would: a pipeline whose last stage
/// echoes its input on failure, printing nothing (`jq: error … (while
/// parsing '<token>')`), a wrapper that logs the token there and prints
/// nothing, standard output framed as `key=<token>&…` or `k=<token>!`, and
/// a passphrase with spaces. The message is exactly what happened, the
/// command, and the hint.
#[test]
fn standard_error_is_never_shown() {
    const CANARY: &str = "stderrC4nary";
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let t = Duration::from_secs(30);
    let phrase = "quill zephyr mango tundra";
    let print = script(d, "print-token", &format!("printf '%s\\n' '{TOKEN}'"));
    let jq = script(
        d,
        "jq-like",
        &format!(
            "IFS= read -r line\necho \"jq: error (at <stdin>:1): Cannot index string with string \\\"value\\\" (while parsing '$line') {CANARY}\" >&2\nexit 5"
        ),
    );
    let cases = [
        (
            TokenCommand::Shell(format!("{print} | {jq} .value")),
            "exited 5",
        ),
        (
            argv(&[&script(
                d,
                "wrapper-logs",
                &format!("echo \"wrapper: fetched {TOKEN} for vex {CANARY}\" >&2"),
            )]),
            "printed nothing on standard output",
        ),
        (
            argv(&[&script(
                d,
                "key-value",
                &format!(
                    "printf 'token={TOKEN}&expires_in=3600\\n'\necho \"debug: response token={TOKEN}&expires_in=3600 {CANARY}\" >&2\nexit 2"
                ),
            )]),
            "exited 2",
        ),
        (
            argv(&[&script(
                d,
                "bang",
                &format!(
                    "printf 'k={TOKEN}!\\nexpires: 1h\\n'\necho \"k={TOKEN}! {CANARY}\" >&2\necho \"{TOKEN}\" >&2"
                ),
            )]),
            "printed more than one line on standard output: it must print the credential alone",
        ),
        (
            argv(&[&script(
                d,
                "passphrase",
                &format!(
                    "printf '{phrase}\\n'\necho \"unlocking with  quill  zephyr\nmango tundra {CANARY}\" >&2\nexit 1"
                ),
            )]),
            "exited 1",
        ),
    ];
    for (cmd, says) in cases {
        let m = fetch(cmd.clone(), d, t).unwrap_err().to_string();
        assert_eq!(
            m,
            format!(
                "libsql store unavailable: the token_command ({}) {says}; {HINT}",
                cmd.display()
            ),
            "{cmd:?}"
        );
        for leaked in [
            CANARY, TOKEN, "quill", "zephyr", "tundra", "jq:", "wrapper:", "debug",
        ] {
            assert!(!m.contains(leaked), "{leaked} in {m}");
        }
    }
}

/// Standard error is read as the command writes it, so a command that
/// writes more there than a pipe holds never blocks on it.
#[test]
fn a_command_that_writes_much_on_standard_error_does_not_block() {
    let dir = tempfile::tempdir().unwrap();
    let helper = script(
        dir.path(),
        "noisy",
        &format!("head -c 1048576 /dev/zero | tr '\\0' 'e' >&2\necho {TOKEN}"),
    );
    let started = Instant::now();
    let t = fetch(argv(&[&helper]), dir.path(), Duration::from_secs(20)).unwrap();
    assert_eq!(t.expose(), TOKEN);
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// A command that does not finish in time is killed and waited for.
#[test]
fn a_command_that_hangs_is_stopped_after_its_time() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let hang = script(
        dir.path(),
        "hang",
        &format!(
            "echo $$ > {:?}\necho {TOKEN}\nexec sleep 300",
            pid_file.to_str().unwrap()
        ),
    );
    let started = Instant::now();
    let e = fetch(argv(&[&hang]), dir.path(), Duration::from_millis(700)).unwrap_err();
    let took = started.elapsed();
    let m = e.to_string();
    assert!(
        m.contains(&format!(
            "did not finish within 0.7 s (it was stopped); {HINT}"
        )),
        "{m}"
    );
    assert!(!m.contains(TOKEN), "{m}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    // The process is gone (killed and reaped, not left behind).
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    let alive = std::process::Command::new("kill")
        .args(["-0", pid.trim()])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(!alive, "pid {} still runs", pid.trim());
}

/// Whether the process `pid` ends within `within` (killed, it is reaped by
/// whoever adopted it).
fn ends_within(pid: &str, within: Duration) -> bool {
    let until = Instant::now() + within;
    loop {
        let alive = std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A command that does not finish in time is stopped with every process it
/// started: a wrapper script that runs its program without `exec`, and
/// each stage of a pipeline run with `sh -c`, leave nothing running.
#[test]
fn a_command_that_hangs_is_stopped_with_what_it_started() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pid = |name: &str| d.join(name).to_str().unwrap().to_owned();
    let wrapper = script(
        d,
        "wrapper",
        &format!(
            "echo {TOKEN}\nsh -c 'echo $$ > {:?}; exec sleep 300'\necho done",
            pid("wrapped.pid")
        ),
    );
    let pipeline = TokenCommand::Shell(format!(
        "sh -c 'echo $$ > {:?}; exec sleep 301' | sh -c 'echo $$ > {:?}; exec head -n 1'",
        pid("left.pid"),
        pid("right.pid")
    ));
    for (cmd, files) in [
        (argv(&[&wrapper]), &["wrapped.pid"][..]),
        (pipeline, &["left.pid", "right.pid"]),
    ] {
        let m = fetch(cmd.clone(), d, Duration::from_secs(2))
            .unwrap_err()
            .to_string();
        assert!(
            m.contains("did not finish within 2 s (it was stopped)"),
            "{m}"
        );
        let mut left = Vec::new();
        for f in files {
            let p = std::fs::read_to_string(d.join(f)).unwrap();
            let p = p.trim().to_owned();
            if !ends_within(&p, Duration::from_secs(10)) {
                // Not left behind by this test either: the process it
                // started, by its own pid.
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", &p])
                    .status();
                left.push(format!("{f} ({p})"));
            }
        }
        assert!(left.is_empty(), "{cmd:?} left {left:?} running");
    }
}

/// A command that leaves a process behind holding its output (a secrets
/// tool's daemon) is read as soon as it exits, not at its deadline.
#[test]
fn a_command_that_leaves_a_daemon_behind_is_read_when_it_exits() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("daemon.pid");
    let helper = script(
        dir.path(),
        "daemon",
        &format!(
            "sleep 30 &\necho $! > {:?}\necho {TOKEN}",
            pid_file.to_str().unwrap()
        ),
    );
    let started = Instant::now();
    let t = fetch(argv(&[&helper]), dir.path(), Duration::from_secs(20)).unwrap();
    let took = started.elapsed();
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    // The daemon this test started, by its own pid.
    let _ = std::process::Command::new("kill")
        .arg(pid.trim())
        .stderr(std::process::Stdio::null())
        .status();
    assert_eq!(t.expose(), TOKEN);
    assert!(took < Duration::from_secs(10), "{took:?}");
}

/// A selection's command runs in the repository's top level, when first
/// asked for (its time: [`the_command_gets_a_minute_or_the_connect_timeout`]).
#[test]
fn a_selection_gives_the_command_the_repository_and_a_minute() {
    let dir = tempfile::tempdir().unwrap();
    let counter = dir.path().join("runs");
    let helper = script(
        dir.path(),
        "helper",
        &format!("pwd >> {:?}\necho {TOKEN}", counter.to_str().unwrap()),
    );
    #[derive(serde::Deserialize)]
    struct OnlyStore {
        store: vci_store::select::StoreSettings,
    }
    let f = toml::from_str::<OnlyStore>(&format!(
        "[store]\nurl = \"libsql://db.turso.io\"\ntoken_command = [{helper:?}]\n"
    ))
    .unwrap()
    .store;
    let s = resolve(&|_: &str| None, Some(&f)).unwrap();
    let cx = OpenContext {
        repo_root: dir.path().to_owned(),
        git_dir: dir.path().join(".git"),
        git_common_dir: dir.path().join(".git"),
        repo_id: std::sync::Arc::new(|| Ok("r".into())),
        jobs: 1,
        command: "plan".into(),
        long_running: false,
    };
    let c = s.token_credential(&cx).unwrap();
    assert_eq!(runs(&counter), 0, "opening runs nothing");
    assert_eq!(c.get("libsql").unwrap().expose(), TOKEN);
    assert_eq!(runs(&counter), 1);
    assert!(
        format!("{c:?}").contains(&format!("[store] token_command ({helper})")),
        "{c:?}"
    );
    assert!(
        Selection::for_backend("libsql")
            .token_credential(&cx)
            .is_none()
    );
}

/// Set, to a directory, in the copy of this test binary that
/// [`the_command_never_reads_vcis_stdin`] starts.
const STDIN_INNER: &str = "VCI_CREDENTIAL_TEST_STDIN_DIR";

/// The command's stdin is `/dev/null`, whatever vci's own is: in a copy of
/// this test binary whose stdin is a pipe holding a line and kept open, a
/// helper that reads its stdin gets nothing (with vci's stdin, it would
/// read the line, and fail).
#[test]
fn the_command_never_reads_vcis_stdin() {
    use std::io::Write as _;
    use std::process::Stdio;
    if let Some(dir) = std::env::var_os(STDIN_INNER) {
        let dir = Path::new(&dir);
        let helper = script(
            dir,
            "reads-stdin",
            &format!(
                "if IFS= read -r line; then echo \"read from stdin: $line\" >&2; exit 9; fi\necho {TOKEN}"
            ),
        );
        let t = fetch(argv(&[&helper]), dir, Duration::from_secs(20)).unwrap();
        assert_eq!(t.expose(), TOKEN);
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "the_command_never_reads_vcis_stdin",
            "--nocapture",
        ])
        .env(STDIN_INNER, dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"a line on vci's stdin\n").unwrap();
    stdin.flush().unwrap();
    // Kept open until the copy has finished.
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "{text}");
}

/// The time the command gets: [`vci_store::credential::TIMEOUT`] (a
/// minute), or the store's connect timeout when that is longer.
#[test]
fn the_command_gets_a_minute_or_the_connect_timeout() {
    #[derive(serde::Deserialize)]
    struct OnlyStore {
        store: vci_store::select::StoreSettings,
    }
    let f = toml::from_str::<OnlyStore>(
        "[store]\nurl = \"libsql://db.turso.io\"\ntoken_command = [\"com\"]\n",
    )
    .unwrap()
    .store;
    let mut s = resolve(&|_: &str| None, Some(&f)).unwrap();
    let cx = OpenContext {
        repo_root: "/repo".into(),
        git_dir: "/repo/.git".into(),
        git_common_dir: "/repo/.git".into(),
        repo_id: std::sync::Arc::new(|| Ok("r".into())),
        jobs: 1,
        command: "plan".into(),
        long_running: false,
    };
    assert_eq!(vci_store::credential::TIMEOUT, Duration::from_secs(60));
    for (connect, given) in [(5, 60), (60, 60), (90, 90)] {
        s.connect_timeout.value = Duration::from_secs(connect);
        let c = s.token_credential(&cx).unwrap();
        assert_eq!(c.timeout(), Some(Duration::from_secs(given)), "{connect}");
    }
    assert_eq!(
        Credential::given(Secret::opaque(TOKEN), "$VCI_STORE_TOKEN").timeout(),
        None
    );
}
