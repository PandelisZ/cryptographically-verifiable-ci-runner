//! The per-file processes of a node:test recording run: at most `jobs` at a
//! time, each stopped with its whole process group when it runs past its
//! deadline, started again with fewer at once when the system cannot start
//! another process (`EAGAIN`), and never waited for longer than that.
//!
//! vci 2.10.3 ran each file with `Command::output()`: it waited for the
//! process to exit and for its output pipes to close, without a limit. On
//! vex's benchmark runner (a container limited to 1,024 processes and
//! threads) eight of vex-web's heaviest files started at once; native addons
//! in them (rolldown's and @napi-rs/canvas's thread pools, sized to the 64
//! processors the container shows) could not start their threads, four
//! failed in a second, and one never finished: `vci run` waited for it for
//! 57 minutes, until the job's timeout. A process a test leaves behind that
//! holds the output open (a `git` or `sleep` it started) kept vci reading
//! until that process ended on its own.
//!
//! Now each process writes to a file, not a pipe (what a test leaves behind
//! never keeps vci waiting); a process that runs past its deadline
//! ([`FILE_TIMEOUT_ENV`], default 600 s) is killed with its process group
//! (the `node --test` process, the file's process and what they started) and
//! its file fails, unattested; a process that cannot be started for want of
//! resources is retried with fewer files at once, and reported as its file
//! failing when it still cannot; a thread vci cannot start runs its share
//! of the files on another. While the files run, `SIGINT`, `SIGTERM` and
//! `SIGHUP` kill every running process group before vci goes, as they would
//! have reached the processes had they stayed in vci's own group.

use std::collections::HashMap;
use std::io::{Read as _, Seek as _};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Seconds a test file's processes may run before they are stopped (0: no
/// limit; default [`DEFAULT_FILE_TIMEOUT_SECS`]). A stopped file fails and
/// is not attested.
pub const FILE_TIMEOUT_ENV: &str = "VCI_NODE_TEST_FILE_TIMEOUT";

/// The default of [`FILE_TIMEOUT_ENV`] (as the Rails adapter's
/// `VCI_RAILS_FILE_TIMEOUT`).
pub const DEFAULT_FILE_TIMEOUT_SECS: u64 = 600;

/// Processes and threads one test file's processes are assumed to need, for
/// the default number of files at once in a container that limits them
/// (cgroup `pids.max`): `node --test` and the file's process (about a dozen
/// threads each), and the thread pools of native addons, sized to the
/// processors the container shows (64 on vex's runners) and not to its
/// share of them: tokio's workers and rayon's pool in rolldown's binding,
/// 128 and more.
pub const TASKS_PER_FILE: u64 = 256;

/// How many times a process that cannot be started for want of resources is
/// tried, waiting longer each time (50 ms doubling to 2 s: about 7 s in all,
/// while the other files' processes end and free what they held).
const SPAWN_ATTEMPTS: u32 = 8;

/// [`FILE_TIMEOUT_ENV`], read now.
pub fn file_timeout() -> Option<Duration> {
    let secs = std::env::var(FILE_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_FILE_TIMEOUT_SECS);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// The default number of node:test files at once: the processors vci may use
/// (8 at most), and, in a container that limits its processes and threads,
/// no more than [`TASKS_PER_FILE`] each of what is left of them. `VCI_JOBS`
/// (any adapter) and a script's `--test-concurrency` decide it instead.
pub fn default_jobs() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .min(8);
    jobs_within(cpus, task_headroom())
}

/// `cpus`, or fewer when `headroom` (processes and threads this process may
/// still start) leaves less than [`TASKS_PER_FILE`] for each; at least 1.
pub fn jobs_within(cpus: usize, headroom: Option<u64>) -> usize {
    let by_tasks = headroom
        .map(|h| usize::try_from(h / TASKS_PER_FILE).unwrap_or(usize::MAX))
        .unwrap_or(usize::MAX);
    cpus.min(by_tasks).max(1)
}

/// How many more processes and threads the cgroups of this process allow
/// (the least `pids.max - pids.current` from its cgroup up to the root of
/// the hierarchy, cgroup v2 or v1's `pids` controller); `None` when none
/// limits them or they cannot be read (not Linux).
pub fn task_headroom() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    headroom_in(&cgroup, std::path::Path::new("/sys/fs/cgroup"))
}

/// [`task_headroom`] with `/proc/self/cgroup` read as `cgroup` and the
/// cgroup file systems mounted at `mount`.
pub(crate) fn headroom_in(cgroup: &str, mount: &std::path::Path) -> Option<u64> {
    let mut best: Option<u64> = None;
    for line in cgroup.lines() {
        let mut f = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let base = if controllers.is_empty() {
            mount.to_owned()
        } else if controllers.split(',').any(|c| c == "pids") {
            mount.join("pids")
        } else {
            continue;
        };
        let rel = path.trim_start_matches('/');
        let mut dir = if rel.is_empty() {
            base.clone()
        } else {
            base.join(rel)
        };
        loop {
            let read = |n: &str| std::fs::read_to_string(dir.join(n)).ok();
            if let (Some(max), Some(cur)) = (read("pids.max"), read("pids.current"))
                && let (Ok(max), Ok(cur)) = (max.trim().parse::<u64>(), cur.trim().parse::<u64>())
            {
                let h = max.saturating_sub(cur);
                best = Some(best.map_or(h, |b| b.min(h)));
            }
            if dir == base || !dir.pop() {
                break;
            }
        }
    }
    best
}

/// How a file's process ended.
#[derive(Debug)]
pub enum Ended {
    /// It exited (or was killed by a signal vci did not send).
    Exited(ExitStatus),
    /// It ran past its deadline and was killed with its process group.
    Stopped(Duration),
    /// It could not be started (the error, after the retries).
    NotStarted(String),
    /// It was not started: vci was asked to stop (`SIGINT`, `SIGTERM`,
    /// `SIGHUP`).
    Cancelled,
}

/// One file's process: how it ended and what it wrote (stdout and stderr,
/// interleaved).
#[derive(Debug)]
pub struct FileRun {
    pub ended: Ended,
    pub output: Vec<u8>,
}

/// Whether `e` is a failure to start a process for want of resources
/// (`EAGAIN`: a process or thread limit; `ENOMEM`), which another attempt
/// with fewer processes running may not meet.
pub fn is_transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::OutOfMemory
    ) || e.raw_os_error() == Some(libc::EAGAIN)
}

/// At most `allowed` processes at once; fewer after a failure to start one.
struct Gate {
    state: Mutex<(usize, usize)>,
    cv: Condvar,
}

impl Gate {
    fn new(allowed: usize) -> Self {
        Gate {
            state: Mutex::new((0, allowed.max(1))),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, usize)> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn acquire(&self) {
        let mut g = self.lock();
        while g.0 >= g.1 {
            g = self.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
        g.0 += 1;
    }

    fn release(&self) {
        let mut g = self.lock();
        g.0 = g.0.saturating_sub(1);
        self.cv.notify_all();
    }

    /// One fewer at once from now on (at least one); returns the new limit.
    fn shrink(&self) -> usize {
        let mut g = self.lock();
        g.1 = g.1.saturating_sub(1).max(1);
        g.1
    }
}

/// A process being waited for: its id (its process group's: it leads one),
/// its deadline, and whether vci killed it.
struct Running {
    pid: libc::pid_t,
    deadline: Option<Instant>,
    stopped: bool,
}

/// A signal that asked vci to stop while files ran (0: none).
static STOP_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn on_stop_signal(sig: libc::c_int) {
    STOP_SIGNAL.store(sig, Ordering::SeqCst);
}

const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The dispositions [`StopSignals`] replaced, and how many live: runs of
/// files may overlap (tests run them on several threads), and only the
/// last to end restores what the first found.
static INSTALLED: Mutex<(usize, Vec<(libc::c_int, libc::sigaction)>)> = Mutex::new((0, Vec::new()));

/// [`on_stop_signal`] for [`STOP_SIGNALS`] while one of these lives, the
/// previous dispositions after the last is dropped (the signal that came is
/// raised again then: see [`run_files`]).
struct StopSignals;

impl StopSignals {
    fn install() -> Self {
        let mut g = INSTALLED.lock().unwrap_or_else(|p| p.into_inner());
        g.0 += 1;
        if g.0 > 1 {
            return StopSignals;
        }
        STOP_SIGNAL.store(0, Ordering::SeqCst);
        for sig in STOP_SIGNALS {
            // SAFETY: plain sigaction calls; the handler only stores into an
            // atomic, which is async-signal-safe.
            unsafe {
                let mut prev: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &mut prev) != 0 {
                    continue;
                }
                // A signal vci ignores (`nohup`, a shell's background job)
                // stays ignored.
                if prev.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = on_stop_signal as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut act.sa_mask);
                if libc::sigaction(sig, &act, std::ptr::null_mut()) == 0 {
                    g.1.push((sig, prev));
                }
            }
        }
        StopSignals
    }
}

impl Drop for StopSignals {
    fn drop(&mut self) {
        let mut g = INSTALLED.lock().unwrap_or_else(|p| p.into_inner());
        g.0 = g.0.saturating_sub(1);
        if g.0 > 0 {
            return;
        }
        for (sig, prev) in std::mem::take(&mut g.1) {
            // SAFETY: restores the disposition read in `install`.
            unsafe {
                libc::sigaction(sig, &prev, std::ptr::null_mut());
            }
        }
    }
}

/// Kill process group `pgid` (SIGKILL). Only called for a process that has
/// not been reaped, so the id is still its group's.
fn kill_group(pgid: libc::pid_t) {
    if pgid > 1 {
        // SAFETY: kill(2) with a negative id: the group.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
}

/// Block until process `pid` (a child of this process) has ended, without
/// reaping it: its id, and its process group's, stay its own until
/// [`std::process::Child::wait`]. False when that cannot be done (the caller
/// then stops counting on the id).
fn wait_ended(pid: libc::pid_t) -> bool {
    loop {
        // SAFETY: waitid(2) on our own child, with WNOWAIT: nothing is reaped.
        let r = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if r == 0 {
            return true;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

/// Run `count` files' processes, at most `jobs` at a time: `make(i)` builds
/// file `i`'s command (its stdin, stdout and stderr are set here); each runs
/// in a process group of its own, for at most `timeout`. `spawn` starts a
/// command (`Command::spawn`, but for tests). `done(i, run)` is called for
/// each file as it ends, from the thread that waited for it.
pub fn run_files(
    count: usize,
    jobs: usize,
    timeout: Option<Duration>,
    make: &(dyn Fn(usize) -> std::io::Result<Command> + Sync),
    spawn: &(dyn Fn(&mut Command) -> std::io::Result<std::process::Child> + Sync),
    done: &(dyn Fn(usize, FileRun) + Sync),
) {
    let jobs = jobs.clamp(1, count.max(1));
    let files = Files {
        make,
        spawn,
        timeout,
        gate: Gate::new(jobs),
        running: Mutex::new(HashMap::new()),
    };
    let next = AtomicUsize::new(0);
    // `poll`: no watchdog thread (this one runs the files itself): each
    // process is polled, and stopped, by the thread that waits for it.
    let worker = |poll: bool| {
        loop {
            let i = next.fetch_add(1, Ordering::SeqCst);
            if i >= count {
                break;
            }
            files.gate.acquire();
            let run = files.one(i, poll);
            files.gate.release();
            done(i, run);
        }
    };
    let live = AtomicUsize::new(0);
    let wake = (Mutex::new(()), Condvar::new());
    let signals = StopSignals::install();
    std::thread::scope(|s| {
        let mut spawned = 0;
        for _ in 0..jobs {
            live.fetch_add(1, Ordering::SeqCst);
            let started = std::thread::Builder::new().spawn_scoped(s, || {
                let _exit = Exit(&live, &wake);
                worker(false);
            });
            match started {
                Ok(_) => spawned += 1,
                Err(e) => {
                    live.fetch_sub(1, Ordering::SeqCst);
                    // Its share goes to the others (to this thread when
                    // none could be started).
                    eprintln!(
                        "vci: cannot start another thread to run test files ({e}); {} at once",
                        spawned.max(1)
                    );
                    break;
                }
            }
        }
        if spawned == 0 {
            worker(true);
            return;
        }
        // This thread stops what runs past its deadline, and everything when
        // vci is asked to stop, until every worker is done.
        let (m, cv) = &wake;
        let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
        while live.load(Ordering::SeqCst) > 0 {
            files.watch();
            g = cv
                .wait_timeout(g, Duration::from_millis(100))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    });
    drop(signals);
    let sig = STOP_SIGNAL.swap(0, Ordering::SeqCst);
    if sig != 0 {
        // Every process group is gone: go as the signal would have taken vci.
        // SAFETY: raise(3), the signal's previous disposition restored above.
        unsafe {
            libc::raise(sig);
        }
    }
}

/// Counts a worker thread out when it ends (or unwinds), waking the watchdog.
struct Exit<'a>(&'a AtomicUsize, &'a (Mutex<()>, Condvar));

impl Drop for Exit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
        let _g = self.1.0.lock().unwrap_or_else(|p| p.into_inner());
        self.1.1.notify_all();
    }
}

/// What [`run_files`]'s threads share.
struct Files<'a> {
    make: &'a (dyn Fn(usize) -> std::io::Result<Command> + Sync),
    spawn: &'a (dyn Fn(&mut Command) -> std::io::Result<std::process::Child> + Sync),
    timeout: Option<Duration>,
    gate: Gate,
    /// The processes the watchdog may kill: started, not yet reaped.
    running: Mutex<HashMap<usize, Running>>,
}

fn not_started(why: String) -> FileRun {
    FileRun {
        ended: Ended::NotStarted(why),
        output: vec![],
    }
}

fn stop_asked() -> bool {
    STOP_SIGNAL.load(Ordering::SeqCst) != 0
}

impl Files<'_> {
    fn running(&self) -> std::sync::MutexGuard<'_, HashMap<usize, Running>> {
        self.running.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Kill every process past its deadline (every one, when vci was asked
    /// to stop): only processes not reaped yet are in the table.
    fn watch(&self) {
        let stop = stop_asked();
        let now = Instant::now();
        for r in self.running().values_mut() {
            if !r.stopped && (stop || r.deadline.is_some_and(|d| now >= d)) {
                r.stopped = true;
                kill_group(r.pid);
            }
        }
    }

    /// File `i`'s process, from start to end.
    fn one(&self, i: usize, poll: bool) -> FileRun {
        use std::os::unix::process::CommandExt as _;
        let mut out = match tempfile::tempfile() {
            Ok(f) => f,
            Err(e) => return not_started(format!("a file for its output: {e}")),
        };
        let mut cmd = match (self.make)(i) {
            Ok(c) => c,
            Err(e) => return not_started(e.to_string()),
        };
        let (Ok(o), Ok(e)) = (out.try_clone(), out.try_clone()) else {
            return not_started("a file for its output".into());
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(o))
            .stderr(Stdio::from(e))
            .process_group(0);
        let mut delay = Duration::from_millis(50);
        let mut attempt = 1;
        let mut child = loop {
            if stop_asked() {
                return FileRun {
                    ended: Ended::Cancelled,
                    output: vec![],
                };
            }
            match (self.spawn)(&mut cmd) {
                Ok(c) => break c,
                Err(e) if is_transient(&e) && attempt < SPAWN_ATTEMPTS => {
                    // Fewer at once, and this one again once the others have
                    // made room.
                    let now = self.gate.shrink();
                    eprintln!(
                        "vci: cannot start another test process ({e}); {now} at once from now on, trying again"
                    );
                    self.gate.release();
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(Duration::from_secs(2));
                    attempt += 1;
                    self.gate.acquire();
                }
                Err(e) => return not_started(e.to_string()),
            }
        };
        drop(cmd);
        let pid = libc::pid_t::try_from(child.id()).unwrap_or(0);
        let started = Instant::now();
        let deadline = self.timeout.map(|t| started + t);
        let mut stopped = false;
        let status = if !poll {
            self.running().insert(
                i,
                Running {
                    pid,
                    deadline,
                    stopped: false,
                },
            );
            let ended = wait_ended(pid);
            // Out of the table before it is reaped: from then on its id may
            // be another process's.
            stopped = self.running().remove(&i).is_some_and(|r| r.stopped);
            if ended {
                child.wait()
            } else {
                poll_until(&mut child, pid, deadline, &mut stopped)
            }
        } else {
            poll_until(&mut child, pid, deadline, &mut stopped)
        };
        let mut output = Vec::new();
        let _ = out.rewind();
        let _ = out.read_to_end(&mut output);
        let ended = match (stopped, status) {
            (true, _) => Ended::Stopped(started.elapsed()),
            (false, Ok(st)) => Ended::Exited(st),
            (false, Err(e)) => Ended::NotStarted(format!("waiting for it: {e}")),
        };
        FileRun { ended, output }
    }
}

/// Wait for `child` (leading process group `pid`) by polling, killing its
/// group at `deadline` or when vci is asked to stop (before it is reaped:
/// `try_wait` reaps only a process that has ended).
fn poll_until(
    child: &mut std::process::Child,
    pid: libc::pid_t,
    deadline: Option<Instant>,
    stopped: &mut bool,
) -> std::io::Result<ExitStatus> {
    let mut nap = Duration::from_millis(1);
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st);
        }
        if !*stopped && (stop_asked() || deadline.is_some_and(|d| Instant::now() >= d)) {
            *stopped = true;
            kill_group(pid);
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(script);
        c
    }

    fn collect(
        count: usize,
        jobs: usize,
        timeout: Option<Duration>,
        make: &(dyn Fn(usize) -> std::io::Result<Command> + Sync),
        spawn: &(dyn Fn(&mut Command) -> std::io::Result<std::process::Child> + Sync),
    ) -> Vec<FileRun> {
        let out: Mutex<Vec<(usize, FileRun)>> = Mutex::new(vec![]);
        run_files(count, jobs, timeout, make, spawn, &|i, r| {
            out.lock().unwrap().push((i, r))
        });
        let mut v = out.into_inner().unwrap();
        v.sort_by_key(|(i, _)| *i);
        assert_eq!(v.len(), count);
        v.into_iter().map(|(_, r)| r).collect()
    }

    /// A file that never ends is stopped at its deadline with what it
    /// started, and the others still run: `vci run` cannot wait forever.
    #[test]
    fn a_file_past_its_deadline_is_stopped_with_its_group() {
        let t = tempfile::tempdir().unwrap();
        let pid_file = t.path().join("grandchild.pid");
        let pf = pid_file.clone();
        let started = Instant::now();
        let runs = collect(
            3,
            2,
            Some(Duration::from_secs(2)),
            &move |i| {
                Ok(match i {
                    0 => sh(&format!(
                        "sleep 300 & echo $! > {:?}; echo started; wait",
                        pf.to_str().unwrap()
                    )),
                    _ => sh("echo ok"),
                })
            },
            &|c| c.spawn(),
        );
        let took = started.elapsed();
        assert!(took < Duration::from_secs(60), "{took:?}");
        assert!(matches!(runs[0].ended, Ended::Stopped(_)), "{:?}", runs[0]);
        assert_eq!(String::from_utf8_lossy(&runs[0].output), "started\n");
        for r in &runs[1..] {
            assert!(matches!(&r.ended, Ended::Exited(s) if s.success()), "{r:?}");
            assert_eq!(r.output, b"ok\n");
        }
        // The sleep it started went with it.
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: kill with signal 0 only checks that the process exists.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if alive {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(!alive, "the group's other process was left running");
    }

    /// A process a test leaves behind holding the output open does not keep
    /// vci waiting (2.10.3 read the output through pipes until they closed).
    #[test]
    fn what_a_file_leaves_running_does_not_hold_it() {
        let t = tempfile::tempdir().unwrap();
        let pid_file = t.path().join("left.pid");
        let pf = pid_file.clone();
        let started = Instant::now();
        let runs = collect(
            1,
            1,
            None,
            &move |_| {
                Ok(sh(&format!(
                    "sleep 300 & echo $! > {:?}; echo done",
                    pf.to_str().unwrap()
                )))
            },
            &|c| c.spawn(),
        );
        let took = started.elapsed();
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: the sleep this test started.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(took < Duration::from_secs(60), "{took:?}");
        assert!(matches!(&runs[0].ended, Ended::Exited(s) if s.success()));
        assert_eq!(runs[0].output, b"done\n");
    }

    /// A process that cannot be started for want of resources (EAGAIN) is
    /// tried again with fewer at once; one that never can be is its file
    /// failing, never a panic or a hang.
    #[test]
    fn eagain_is_retried_with_fewer_at_once_then_reported() {
        let calls = AtomicUsize::new(0);
        let fail_first = 3;
        let runs = collect(4, 4, None, &|_| Ok(sh("echo ok")), &|c| {
            if calls.fetch_add(1, Ordering::SeqCst) < fail_first {
                Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
            } else {
                c.spawn()
            }
        });
        for r in &runs {
            assert!(matches!(&r.ended, Ended::Exited(s) if s.success()), "{r:?}");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4 + fail_first);

        let runs = collect(2, 2, None, &|_| Ok(sh("echo ok")), &|_| {
            Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
        });
        for r in &runs {
            assert!(
                matches!(&r.ended, Ended::NotStarted(e) if e.contains("temporarily unavailable")),
                "{r:?}"
            );
        }
        // Any other error is not retried.
        let calls = AtomicUsize::new(0);
        let runs = collect(1, 1, None, &|_| Ok(sh("echo ok")), &|_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        });
        assert!(matches!(runs[0].ended, Ended::NotStarted(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_gate_never_goes_below_one() {
        let g = Gate::new(2);
        assert_eq!(g.shrink(), 1);
        assert_eq!(g.shrink(), 1);
        g.acquire();
        g.release();
    }

    /// A container's process limit bounds the default number of files at
    /// once (vex's runners: 1,024, 64 processors shown).
    #[test]
    fn a_container_process_limit_bounds_the_default_jobs() {
        assert_eq!(jobs_within(8, None), 8);
        assert_eq!(jobs_within(8, Some(1024 - 200)), 3);
        assert_eq!(jobs_within(8, Some(10)), 1);
        assert_eq!(jobs_within(2, Some(100_000)), 2);

        let t = tempfile::tempdir().unwrap();
        let m = t.path();
        // cgroup v2: the limit is set on a parent of the process's cgroup.
        std::fs::create_dir_all(m.join("ci/job")).unwrap();
        for (d, max, cur) in [
            ("", "max", "900"),
            ("ci", "1024", "300"),
            ("ci/job", "max", "120"),
        ] {
            std::fs::write(m.join(d).join("pids.max"), format!("{max}\n")).unwrap();
            std::fs::write(m.join(d).join("pids.current"), format!("{cur}\n")).unwrap();
        }
        assert_eq!(headroom_in("0::/ci/job\n", m), Some(724));
        // A container's own cgroup namespace: its cgroup is the root.
        assert_eq!(headroom_in("0::/\n", m), None);
        std::fs::write(m.join("pids.max"), "1024\n").unwrap();
        assert_eq!(headroom_in("0::/\n", m), Some(124));
        // cgroup v1's pids controller.
        std::fs::create_dir_all(m.join("pids/docker/x")).unwrap();
        std::fs::write(m.join("pids/docker/x/pids.max"), "1024\n").unwrap();
        std::fs::write(m.join("pids/docker/x/pids.current"), "24\n").unwrap();
        assert_eq!(
            headroom_in("12:pids:/docker/x\n3:cpu,cpuacct:/docker/x\n", m),
            Some(1000)
        );
        assert_eq!(headroom_in("3:cpu,cpuacct:/docker/x\n", m), None);
    }
}
