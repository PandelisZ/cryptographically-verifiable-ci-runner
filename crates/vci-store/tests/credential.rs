//! `[store] token_command`: the command runs where and when it should, at
//! most once per process, within its time, and its credential (or anything
//! it printed on standard output) never reaches a message.

#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use vci_store::credential::{Credential, MAX_OUTPUT, TokenCommand};
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
/// (unavailable), saying what went wrong, never what it printed on
/// standard output; standard error is shown, scrubbed of it.
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
            "exited 3: not allowed: *** is a member's",
        ),
        (
            argv(&[d.join("no-such-helper").to_str().unwrap()]),
            "was not found",
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
            "printed more than one line on standard output (not printed)",
        ),
        (
            argv(&[&script(d, "binary", "printf 'tok\\377en'")]),
            "not UTF-8 text on standard output (not printed)",
        ),
        (
            argv(&[&script(d, "control", &format!("printf '{TOKEN}\\033[0m'"))]),
            "printed a control character on standard output (not printed)",
        ),
        (
            argv(&[&script(
                d,
                "big",
                &format!(
                    "i=0; while [ $i -lt 20 ]; do head -c 4096 /dev/zero | tr '\\0' 'a'; i=$((i+1)); done; echo {TOKEN}"
                ),
            )]),
            "printed more than 64 KiB on standard output (not printed)",
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
        assert!(
            m.starts_with(&format!(
                "libsql store unavailable: the token_command ({})",
                cmd.display()
            )),
            "{m}"
        );
        assert!(m.contains(says), "{cmd:?}: {m}");
        assert!(!m.contains(TOKEN), "{cmd:?}: {m}");
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

/// A command that does not finish in time is killed through its handle
/// and waited for; so is one that leaves a process holding its output.
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
        m.contains("did not finish within 0.7 s (it was stopped)"),
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

/// The time a backend gives it is a minute, or the connect timeout when
/// longer; its directory is the repository's top level.
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
