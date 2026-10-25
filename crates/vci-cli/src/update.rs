//! `vci update` (2.7.33): find the latest release and install it the way this
//! `vci` was installed.
//!
//! The latest release is where `https://github.com/<repo>/releases/latest`
//! redirects (`.../releases/tag/vX.Y.Z`): one request, no API call, no token.
//! `VCI_UPDATE_REPO` names another repository and `VCI_UPDATE_BASE_URL`
//! replaces `https://github.com/<repo>/releases` altogether (a local server or
//! a `file://` directory in tests); without a redirect, the body of `latest`
//! may be the API's JSON (`tag_name`) or the tag itself. Requests go through
//! `curl`, as vci's other HTTP does (keyless signing), so its proxy variables
//! (`https_proxy`, `ALL_PROXY`, `NO_PROXY`) apply.
//!
//! How it updates depends on where the running executable is:
//!
//! - Homebrew (`Cellar/vci/` in its real path, or `$HOMEBREW_PREFIX/opt/vci`):
//!   `brew update`, then `brew upgrade pandelisz/tap/vci`.
//! - built by cargo in a checkout (`.fingerprint` beside it): refuses; pull and
//!   build again there.
//! - `cargo install` from the install script's clone (in `$CARGO_HOME/bin`,
//!   or `VCI_HOME` is set, or `~/.local/share/vci/.git` exists): runs the
//!   clone's `scripts/install.sh` with `VCI_REF=vX.Y.Z`, or prints the command
//!   that clones and installs when there is no clone.
//! - anything else is a release binary: `vci-<target>.tar.gz` and
//!   `SHA256SUMS-<target>` are downloaded, the checksum checked, the binary
//!   unpacked, run once (`--version` must name the release) and renamed over
//!   the running executable from a temporary file in the same directory.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

const DEFAULT_REPO: &str = "PandelisZ/cryptographically-verifiable-ci-runner";
const FORMULA: &str = "pandelisz/tap/vci";
const CURRENT: &str = env!("CARGO_PKG_VERSION");

pub struct UpdateArgs {
    pub check: bool,
    pub version: Option<String>,
    pub keep_old: bool,
}

/// A release version: `MAJOR.MINOR.PATCH`, with an optional pre-release or
/// build suffix that comparisons ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: (u64, u64, u64),
    pre: Option<String>,
}

impl Version {
    /// `2.7.32`, `v2.7.32`, `2.8.0-rc1`, `2.7.32+build`.
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let (core, pre) = match s.find(['-', '+']) {
            Some(i) => (&s[..i], Some(&s[i + 1..])),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut num = || -> Option<u64> {
            let p = parts.next()?;
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let core = (num()?, num()?, num()?);
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            Some(p)
                if !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-.+".contains(&b)) =>
            {
                Some(p.to_owned())
            }
            Some(_) => return None,
            None => None,
        };
        Some(Version { core, pre })
    }

    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }

    /// The release tag: `v2.7.32`.
    pub fn tag(&self) -> String {
        format!("v{self}")
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (a, b, c) = self.core;
        write!(f, "{a}.{b}.{c}")?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        Ok(())
    }
}

/// Whether `latest` is an update for `current`: a newer version, never a
/// pre-release (their suffix is not compared).
pub fn is_newer(latest: &Version, current: &Version) -> bool {
    !latest.is_prerelease() && latest.core > current.core
}

/// Where releases are: `<base>/latest` and `<base>/download/<tag>/<asset>`.
#[derive(Debug, Clone)]
pub struct Source {
    base: String,
    repo: String,
    /// Set by VCI_UPDATE_BASE_URL: http and file URLs are allowed too.
    custom: bool,
}

impl Source {
    pub fn from_env() -> Result<Source> {
        let repo = match std::env::var("VCI_UPDATE_REPO") {
            Ok(r) if !r.is_empty() => {
                let ok = r.split('/').count() == 2
                    && r.split('/').all(|p| {
                        !p.is_empty()
                            && p.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    });
                if !ok {
                    bail!("VCI_UPDATE_REPO={r} is not an owner/name repository");
                }
                r
            }
            _ => DEFAULT_REPO.to_owned(),
        };
        match std::env::var("VCI_UPDATE_BASE_URL") {
            Ok(b) if !b.is_empty() => Ok(Source {
                base: b.trim_end_matches('/').to_owned(),
                repo,
                custom: true,
            }),
            _ => Ok(Source {
                base: format!("https://github.com/{repo}/releases"),
                repo,
                custom: false,
            }),
        }
    }

    #[cfg(test)]
    fn at(base: &str) -> Source {
        Source {
            base: base.trim_end_matches('/').to_owned(),
            repo: DEFAULT_REPO.to_owned(),
            custom: true,
        }
    }

    fn asset_url(&self, v: &Version, name: &str) -> String {
        format!("{}/download/{}/{name}", self.base, v.tag())
    }
}

/// A URL as messages show it: no user name or password, no query.
fn shown(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or(url);
    crate::cmds::redact_userinfo(url)
}

/// Quote a value for a curl config file.
fn curl_quote(s: &str) -> Result<String> {
    if s.contains(['\n', '\r']) {
        bail!("a URL with a line break");
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

struct Fetched {
    /// 0 for a file:// URL.
    status: u16,
    redirect: String,
    body: Vec<u8>,
}

/// One request through curl. The URL goes to curl's standard input (`-K -`),
/// never its command line. `to`: write the body there (following redirects,
/// as release downloads need) instead of returning it.
fn curl(src: &Source, url: &str, to: Option<&Path>) -> Result<Fetched> {
    let mut config = format!("url = {}\n", curl_quote(url)?);
    if let Some(p) = to {
        let p = p
            .to_str()
            .ok_or_else(|| anyhow!("a non-UTF-8 path {p:?}"))?;
        config.push_str(&format!("output = {}\n", curl_quote(p)?));
    }
    let proto = if src.custom {
        "=https,http,file"
    } else {
        "=https"
    };
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "-K",
        "-",
        "--proto",
        proto,
        "--proto-redir",
        "=https",
    ])
    .args(["--connect-timeout", "20", "--retry", "2"]);
    if to.is_some() {
        cmd.args(["-L", "--max-time", "600", "-w", "%{http_code} "]);
    } else {
        cmd.args([
            "--max-time",
            "60",
            "-o",
            "-",
            "-w",
            "\n%{http_code} %{redirect_url}",
        ]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running curl (vci update downloads with curl)")?;
    if let Some(mut stdin) = child.stdin.take() {
        // A few hundred bytes: fits in the pipe before curl reads anything.
        let _ = stdin.write_all(config.as_bytes());
    }
    let out = child.wait_with_output().context("running curl")?;
    if !out.status.success() {
        bail!(
            "could not fetch {}: {}",
            shown(url),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut body = out.stdout;
    let split = body.iter().rposition(|&b| b == b'\n');
    let tail = match (to, split) {
        (None, Some(i)) => {
            let t = String::from_utf8_lossy(&body[i + 1..]).into_owned();
            body.truncate(i);
            t
        }
        _ => {
            let t = String::from_utf8_lossy(&body).into_owned();
            body.clear();
            t
        }
    };
    let (code, redirect) = tail.trim_start().split_once(' ').unwrap_or((&tail, ""));
    let status = code
        .trim()
        .parse()
        .map_err(|_| anyhow!("curl printed no status for {}", shown(url)))?;
    Ok(Fetched {
        status,
        redirect: redirect.trim().to_owned(),
        body,
    })
}

fn ok_status(s: u16) -> bool {
    s == 0 || s == 200
}

/// The version a tag, a `.../tag/<tag>` URL or a `{"tag_name": ...}` names.
fn version_in(text: &str) -> Option<Version> {
    let text = text.trim();
    if text.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        return Version::parse(v.get("tag_name")?.as_str()?);
    }
    if let Some((_, tag)) = text.rsplit_once("/tag/") {
        return Version::parse(tag.split(['?', '#', '/']).next()?);
    }
    Version::parse(text.lines().next()?)
}

/// The latest release.
pub fn latest(src: &Source) -> Result<Version> {
    let url = format!("{}/latest", src.base);
    let r = curl(src, &url, None)?;
    let found = if (300..400).contains(&r.status) {
        version_in(&r.redirect)
    } else if ok_status(r.status) {
        version_in(&String::from_utf8_lossy(&r.body))
    } else {
        bail!(
            "looking up the latest release at {}: HTTP {}",
            shown(&url),
            r.status
        );
    };
    found.ok_or_else(|| {
        anyhow!(
            "could not tell the latest release from {} (no vX.Y.Z tag in its answer)",
            shown(&url)
        )
    })
}

/// The release asset name for this build's platform, if there is one.
pub fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallKind {
    /// `brew`: the prefix's own brew when it exists, else `None` (PATH's).
    Homebrew {
        brew: Option<PathBuf>,
    },
    /// Built by cargo in a source checkout: the target directory.
    Built {
        dir: PathBuf,
    },
    /// `cargo install` (the install script): the clone, if there is one.
    Cargo {
        clone: Option<PathBuf>,
    },
    Standalone,
}

/// What detection looks at, so tests can point it at temp dirs.
#[derive(Debug, Default)]
pub struct Probe {
    /// The executable as started (`current_exe`).
    pub exe: PathBuf,
    /// Its real path.
    pub real: PathBuf,
    pub home: Option<PathBuf>,
    pub cargo_home: Option<PathBuf>,
    pub homebrew_prefix: Option<PathBuf>,
    pub vci_home: Option<PathBuf>,
}

impl Probe {
    pub fn current() -> Result<Probe> {
        let exe = std::env::current_exe().context("finding the running vci")?;
        let real = exe.canonicalize().unwrap_or_else(|_| exe.clone());
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Ok(Probe {
            exe,
            real,
            home: var("HOME"),
            cargo_home: var("CARGO_HOME"),
            homebrew_prefix: var("HOMEBREW_PREFIX"),
            vci_home: var("VCI_HOME"),
        })
    }

    fn default_clone(&self) -> Option<PathBuf> {
        self.vci_home
            .clone()
            .or_else(|| self.home.as_ref().map(|h| h.join(".local/share/vci")))
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_owned());
    canon(a) == canon(b)
}

/// How the running vci was installed.
pub fn detect(p: &Probe) -> InstallKind {
    // Homebrew: <prefix>/Cellar/vci/<version>/libexec/bin/vci.
    let comps: Vec<_> = p.real.components().collect();
    if let Some(i) = comps
        .windows(2)
        .position(|w| w[0].as_os_str() == "Cellar" && w[1].as_os_str() == "vci")
    {
        let prefix: PathBuf = comps[..i].iter().collect();
        let brew = prefix.join("bin/brew");
        return InstallKind::Homebrew {
            brew: brew.is_file().then_some(brew),
        };
    }
    if let Some(prefix) = &p.homebrew_prefix
        && (p.exe.starts_with(prefix.join("opt/vci")) || p.real.starts_with(prefix.join("opt/vci")))
    {
        let brew = prefix.join("bin/brew");
        return InstallKind::Homebrew {
            brew: brew.is_file().then_some(brew),
        };
    }
    let Some(dir) = p.real.parent() else {
        return InstallKind::Standalone;
    };
    if dir.join(".fingerprint").is_dir() {
        return InstallKind::Built {
            dir: dir.to_owned(),
        };
    }
    let cargo_bin = p
        .cargo_home
        .clone()
        .or_else(|| p.home.as_ref().map(|h| h.join(".cargo")))
        .map(|c| c.join("bin"));
    let in_cargo_bin = cargo_bin.is_some_and(|b| same_dir(dir, &b))
        || p.exe.parent().is_some_and(|d| {
            p.cargo_home
                .as_ref()
                .is_some_and(|c| same_dir(d, &c.join("bin")))
        });
    let clone = p.default_clone().filter(|c| c.join(".git").exists());
    if in_cargo_bin || p.vci_home.is_some() || clone.is_some() {
        return InstallKind::Cargo { clone };
    }
    InstallKind::Standalone
}

/// The first `name` on PATH.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The checksum `SHA256SUMS-<target>` gives `asset` (`<hex>  <name>` lines,
/// or a lone hex digest).
fn checksum_for(sums: &str, asset: &str) -> Option<String> {
    let is_hex = |h: &str| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
    let lines: Vec<&str> = sums.lines().filter(|l| !l.trim().is_empty()).collect();
    for l in &lines {
        let mut it = l.split_whitespace();
        if let (Some(h), Some(name)) = (it.next(), it.next())
            && name.trim_start_matches('*') == asset
            && is_hex(h)
        {
            return Some(h.to_ascii_lowercase());
        }
    }
    match lines.as_slice() {
        [one] if is_hex(one.trim()) => Some(one.trim().to_ascii_lowercase()),
        _ => None,
    }
}

/// Collector directories beside the executable that a binary update leaves
/// as they are (`share/vci` in an ancestor, as Homebrew lays them out).
fn collectors_beside(real: &Path) -> Option<PathBuf> {
    real.parent()?
        .ancestors()
        .map(|a| a.join("share/vci"))
        .find(|d| d.is_dir())
}

/// Download release `v` for `target`, check it and rename it over `exe`.
/// Nothing at `exe` changes unless every check passed.
pub fn install_release(
    src: &Source,
    v: &Version,
    target: &str,
    exe: &Path,
    keep_old: bool,
) -> Result<()> {
    if cfg!(not(unix)) {
        bail!(
            "vci update cannot replace a release binary on this platform; download {} yourself",
            shown(&src.asset_url(v, &format!("vci-{target}.tar.gz")))
        );
    }
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("{} has no directory", exe.display()))?;
    let name = exe
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", exe.display()))?;
    // The new binary is written next to the old one so that the rename is
    // atomic; check first that it can be.
    let staged = match tempfile::Builder::new()
        .prefix(".vci-update-")
        .tempfile_in(dir)
    {
        Ok(f) => f,
        Err(e) => bail!(
            "cannot write to {} ({e}), so {} cannot be replaced; run it with the rights to: sudo {} update{}",
            dir.display(),
            exe.display(),
            exe.display(),
            if v.to_string() == CURRENT {
                String::new()
            } else {
                format!(" --version {v}")
            }
        ),
    };
    let work = tempfile::tempdir().context("creating a temporary directory")?;
    let asset = format!("vci-{target}.tar.gz");
    let sums_name = format!("SHA256SUMS-{target}");
    let tarball = work.path().join(&asset);
    let sums_path = work.path().join(&sums_name);
    for (file, path) in [(&asset, &tarball), (&sums_name, &sums_path)] {
        let url = src.asset_url(v, file);
        eprintln!("vci: downloading {}", shown(&url));
        let r = curl(src, &url, Some(path))?;
        if !ok_status(r.status) {
            bail!(
                "release {} has no {file} for this platform (HTTP {} from {})",
                v.tag(),
                r.status,
                shown(&url)
            );
        }
    }
    let sums =
        std::fs::read_to_string(&sums_path).with_context(|| format!("reading {sums_name}"))?;
    let expected = checksum_for(&sums, &asset)
        .ok_or_else(|| anyhow!("{sums_name} of {} has no checksum for {asset}", v.tag()))?;
    let actual = sha256_file(&tarball)?;
    if actual != expected {
        bail!(
            "the sha256 of {asset} is {actual}, but {sums_name} says {expected}; {} was not changed",
            exe.display()
        );
    }
    eprintln!("vci: sha256 {actual} matches {sums_name}");
    let unpacked = work.path().join("unpacked");
    std::fs::create_dir(&unpacked)?;
    let st = Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&unpacked)
        .arg("vci")
        .stdin(Stdio::null())
        .status()
        .context("running tar")?;
    let new = unpacked.join("vci");
    if !st.success() || !std::fs::symlink_metadata(&new).is_ok_and(|m| m.is_file()) {
        bail!(
            "{asset} of {} does not hold a vci binary; {} was not changed",
            v.tag(),
            exe.display()
        );
    }
    std::fs::copy(&new, staged.path())
        .with_context(|| format!("writing {}", staged.path().display()))?;
    // Closed before it is run: Linux refuses to execute a file open for writing.
    let staged = staged.into_temp_path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    }
    let out = Command::new(&*staged)
        .arg("--version")
        .stdin(Stdio::null())
        .output();
    let said = out
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if said != format!("vci {v}") {
        bail!(
            "the downloaded binary does not run as vci {v} here ({}); {} was not changed",
            match &out {
                Ok(_) if said.is_empty() => "it printed nothing".to_owned(),
                Ok(_) => format!("it says {said:?}"),
                Err(e) => e.to_string(),
            },
            exe.display()
        );
    }
    if keep_old {
        let mut old_name = name.to_owned();
        old_name.push(".old");
        let old = dir.join(old_name);
        let _ = std::fs::remove_file(&old);
        if std::fs::hard_link(exe, &old).is_err() {
            std::fs::copy(exe, &old)
                .with_context(|| format!("keeping the previous binary as {}", old.display()))?;
        }
        eprintln!("vci: kept the previous binary as {}", old.display());
    }
    staged
        .persist(exe)
        .map_err(|e| anyhow!("replacing {}: {}", exe.display(), e.error))?;
    Ok(())
}

fn run_shown(cmd: &mut Command, what: &str) -> Result<()> {
    let st = cmd
        .stdin(Stdio::inherit())
        .status()
        .with_context(|| format!("running {what}"))?;
    if !st.success() {
        bail!("{what} failed ({st})");
    }
    Ok(())
}

pub fn update(args: UpdateArgs) -> Result<i32> {
    let current = Version::parse(CURRENT)
        .ok_or_else(|| anyhow!("this vci's version {CURRENT} is unreadable"))?;
    let wanted = match &args.version {
        Some(s) => Some(Version::parse(s).ok_or_else(|| {
            anyhow!("--version takes a release version such as 2.7.32, not {s:?}")
        })?),
        None => None,
    };
    let src = Source::from_env()?;
    let target_version = match wanted {
        Some(w) => {
            if w == current {
                eprintln!("vci: {current} is already installed");
                return Ok(0);
            }
            w
        }
        None => {
            let latest = latest(&src)?;
            if is_newer(&latest, &current) {
                eprintln!("vci: {current} is installed; the latest release is {latest}");
                if args.check {
                    eprintln!("vci: run vci update to install it");
                    return Ok(1);
                }
                latest
            } else {
                if latest.core == current.core {
                    eprintln!("vci: {current} is the latest release");
                } else {
                    eprintln!(
                        "vci: {current} is installed, newer than the latest release {latest}"
                    );
                }
                return Ok(0);
            }
        }
    };
    let probe = Probe::current()?;
    let kind = detect(&probe);
    if args.keep_old && kind != InstallKind::Standalone {
        eprintln!("vci: note: --keep-old applies to a release binary only");
    }
    let tag = target_version.tag();
    match kind {
        InstallKind::Homebrew { brew } => {
            if args.version.is_some() {
                bail!(
                    "this vci was installed by Homebrew ({}), which installs only the tap's current version; for {target_version}, install a release binary from {} or build it with the install script and VCI_REF={tag}",
                    probe.real.display(),
                    shown(&format!("{}/tag/{tag}", src.base)),
                );
            }
            let Some(brew) = brew.or_else(|| which("brew")) else {
                bail!(
                    "this vci was installed by Homebrew ({}), but brew is not on PATH; run brew update && brew upgrade {FORMULA} where Homebrew is installed",
                    probe.real.display()
                );
            };
            eprintln!("vci: updating with Homebrew: brew update, then brew upgrade {FORMULA}");
            run_shown(Command::new(&brew).arg("update"), "brew update")?;
            run_shown(
                Command::new(&brew).args(["upgrade", FORMULA]),
                &format!("brew upgrade {FORMULA}"),
            )?;
            eprintln!("vci: brew upgrade finished (the latest release is {target_version})");
            Ok(0)
        }
        InstallKind::Built { dir } => bail!(
            "this vci was built by cargo in a source checkout ({}); check out {tag} there and build it again, or install a release (brew install {FORMULA})",
            dir.display()
        ),
        InstallKind::Cargo { clone } => {
            let script = clone.as_ref().map(|c| c.join("scripts/install.sh"));
            match (clone, script) {
                (Some(clone), Some(script)) if script.is_file() => {
                    eprintln!(
                        "vci: installing {tag} from source with {} (VCI_REF={tag}: git fetch, then cargo install)",
                        script.display()
                    );
                    run_shown(
                        Command::new("sh")
                            .arg(&script)
                            .env("VCI_HOME", &clone)
                            .env("VCI_REF", &tag),
                        "scripts/install.sh",
                    )?;
                    eprintln!("vci: installed {target_version}");
                    Ok(0)
                }
                _ => {
                    eprintln!(
                        "vci: this vci was installed by cargo without the install script's clone; to install {target_version}, run:"
                    );
                    eprintln!(
                        "  curl -fsSL https://raw.githubusercontent.com/{}/{tag}/scripts/install.sh | VCI_REF={tag} sh",
                        src.repo
                    );
                    Ok(1)
                }
            }
        }
        InstallKind::Standalone => {
            let target = release_target().ok_or_else(|| {
                anyhow!(
                    "there is no release binary for {}/{}; build vci from source (scripts/install.sh)",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                )
            })?;
            install_release(&src, &target_version, target, &probe.real, args.keep_old)?;
            eprintln!(
                "vci: updated {} from {current} to {target_version}",
                probe.real.display()
            );
            if let Some(dir) = collectors_beside(&probe.real) {
                eprintln!(
                    "vci: note: the collectors in {} are not updated with the binary; replace them with py/pytest-plugin, ruby/vci-collector and js/vitest-plugin of {tag}'s source",
                    dir.display()
                );
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s} does not parse"))
    }

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(v("2.7.32"), v("v2.7.32"));
        assert_eq!(v("2.7.32").to_string(), "2.7.32");
        assert_eq!(v("v2.8.0-rc1").to_string(), "2.8.0-rc1");
        assert_eq!(v("2.8.0-rc1").tag(), "v2.8.0-rc1");
        assert!(v("2.8.0-rc.1").is_prerelease());
        for bad in [
            "", "2.7", "2.7.x", "2.7.32.1", "v", "2..1", "2.7.32-", "2.7.3 2",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        // Numeric, not textual.
        assert!(is_newer(&v("2.7.32"), &v("2.7.9")));
        assert!(!is_newer(&v("2.7.9"), &v("2.7.32")));
        assert!(is_newer(&v("2.10.0"), &v("2.9.40")));
        assert!(is_newer(&v("3.0.0"), &v("2.99.99")));
        assert!(!is_newer(&v("2.7.32"), &v("2.7.32")));
        // A pre-release is never offered, and a suffix is not compared.
        assert!(!is_newer(&v("2.8.0-rc1"), &v("2.7.32")));
        assert!(!is_newer(&v("2.7.32"), &v("2.7.32-rc1")));
        assert!(is_newer(&v("2.7.33"), &v("2.7.32+local")));
        assert!(Version::parse(CURRENT).is_some());
    }

    #[test]
    fn the_latest_version_from_a_redirect_json_or_tag() {
        let url = "https://github.com/o/r/releases/tag/v2.7.33";
        assert_eq!(version_in(url), Some(v("2.7.33")));
        assert_eq!(
            version_in(r#"{"tag_name": "v2.7.40", "x": 1}"#),
            Some(v("2.7.40"))
        );
        assert_eq!(version_in("v2.7.41\n"), Some(v("2.7.41")));
        assert_eq!(version_in("https://github.com/o/r/releases"), None);
        assert_eq!(version_in("<html>"), None);
    }

    #[test]
    fn checksums() {
        let h = "a".repeat(64);
        let sums = format!("{h}  vci-x86_64-apple-darwin.tar.gz\n");
        assert_eq!(
            checksum_for(&sums, "vci-x86_64-apple-darwin.tar.gz"),
            Some(h.clone())
        );
        assert_eq!(checksum_for(&sums, "vci-aarch64-apple-darwin.tar.gz"), None);
        assert_eq!(
            checksum_for(&format!("{}\n", h.to_uppercase()), "x"),
            Some(h.clone())
        );
        assert_eq!(checksum_for("nope  x", "x"), None);
        assert_eq!(shown("https://u:tok@h/p?token=1"), "https://***@h/p");
    }

    fn mk(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "").unwrap();
    }

    #[test]
    fn install_kind_from_paths() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let probe = |exe: &Path| Probe {
            exe: exe.to_owned(),
            real: exe.canonicalize().unwrap(),
            home: Some(home.clone()),
            ..Probe::default()
        };

        // Homebrew's Cellar, its brew found in the prefix.
        let cellar = root.join("brew/Cellar/vci/2.7.32/libexec/bin/vci");
        mk(&cellar);
        assert_eq!(
            detect(&probe(&cellar)),
            InstallKind::Homebrew { brew: None }
        );
        mk(&root.join("brew/bin/brew"));
        assert_eq!(
            detect(&probe(&cellar)),
            InstallKind::Homebrew {
                brew: Some(root.join("brew/bin/brew"))
            }
        );
        // Started through $HOMEBREW_PREFIX/opt/vci (here not a symlink).
        let opt = root.join("brew/opt/vci/libexec/bin/vci");
        mk(&opt);
        assert_eq!(detect(&probe(&opt)), InstallKind::Standalone);
        let p = Probe {
            homebrew_prefix: Some(root.join("brew")),
            ..probe(&opt)
        };
        assert!(matches!(detect(&p), InstallKind::Homebrew { .. }));

        // cargo install: ~/.cargo/bin, or $CARGO_HOME/bin.
        let cargo = home.join(".cargo/bin/vci");
        mk(&cargo);
        assert_eq!(detect(&probe(&cargo)), InstallKind::Cargo { clone: None });
        let elsewhere = root.join("rust/cargo/bin/vci");
        mk(&elsewhere);
        assert_eq!(detect(&probe(&elsewhere)), InstallKind::Standalone);
        let p = Probe {
            cargo_home: Some(root.join("rust/cargo")),
            ..probe(&elsewhere)
        };
        assert_eq!(detect(&p), InstallKind::Cargo { clone: None });
        // ...with the install script's clone.
        std::fs::create_dir_all(home.join(".local/share/vci/.git")).unwrap();
        assert_eq!(
            detect(&probe(&cargo)),
            InstallKind::Cargo {
                clone: Some(home.join(".local/share/vci"))
            }
        );

        // Built in a checkout.
        let built = root.join("src/target/release/vci");
        mk(&built);
        std::fs::create_dir_all(root.join("src/target/release/.fingerprint")).unwrap();
        assert_eq!(
            detect(&probe(&built)),
            InstallKind::Built {
                dir: root.join("src/target/release")
            }
        );

        // A release binary, with no clone in this home.
        std::fs::remove_dir_all(home.join(".local")).unwrap();
        let plain = root.join("usr/local/bin/vci");
        mk(&plain);
        assert_eq!(detect(&probe(&plain)), InstallKind::Standalone);
        assert_eq!(collectors_beside(&plain), None);
        std::fs::create_dir_all(root.join("usr/local/share/vci")).unwrap();
        assert_eq!(
            collectors_beside(&plain),
            Some(root.join("usr/local/share/vci"))
        );
        // VCI_HOME names a source install.
        let p = Probe {
            vci_home: Some(root.join("vci-src")),
            ..probe(&plain)
        };
        assert_eq!(detect(&p), InstallKind::Cargo { clone: None });
    }

    /// A release directory served as file://: download/<tag>/ holds the
    /// tarball of a fake `vci` and its SHA256SUMS.
    struct Release {
        _dir: tempfile::TempDir,
        root: PathBuf,
        src: Source,
    }

    const TARGET: &str = "x86_64-unknown-linux-musl";

    fn release(version: &str, says: &str, sums: Option<&str>) -> Release {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let tag_dir = root.join(format!("releases/download/v{version}"));
        let build = root.join("build");
        std::fs::create_dir_all(&tag_dir).unwrap();
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("vci"), format!("#!/bin/sh\necho '{says}'\n")).unwrap();
        let asset = format!("vci-{TARGET}.tar.gz");
        let st = Command::new("tar")
            .arg("-czf")
            .arg(tag_dir.join(&asset))
            .arg("-C")
            .arg(&build)
            .arg("vci")
            .status()
            .unwrap();
        assert!(st.success());
        let sum = match sums {
            Some(s) => s.to_owned(),
            None => sha256_file(&tag_dir.join(&asset)).unwrap(),
        };
        std::fs::write(
            tag_dir.join(format!("SHA256SUMS-{TARGET}")),
            format!("{sum}  {asset}\n"),
        )
        .unwrap();
        std::fs::write(root.join("releases/latest"), format!("v{version}\n")).unwrap();
        let src = Source::at(&format!("file://{}/releases", root.display()));
        Release {
            _dir: dir,
            root,
            src,
        }
    }

    fn old_binary() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().canonicalize().unwrap().join("vci");
        std::fs::write(&exe, "old binary").unwrap();
        (dir, exe)
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[cfg(unix)]
    #[test]
    fn a_release_replaces_the_binary_atomically() {
        use std::os::unix::fs::PermissionsExt as _;
        let r = release("9.9.9", "vci 9.9.9", None);
        assert_eq!(latest(&r.src).unwrap(), v("9.9.9"));
        let (dir, exe) = old_binary();
        install_release(&r.src, &v("9.9.9"), TARGET, &exe, false).unwrap();
        let new = std::fs::read_to_string(&exe).unwrap();
        assert!(new.contains("vci 9.9.9"), "{new}");
        let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "{mode:o}");
        assert_eq!(listing(dir.path()), ["vci"]);

        // --keep-old keeps the one it replaced beside it.
        std::fs::write(&exe, "old binary").unwrap();
        install_release(&r.src, &v("9.9.9"), TARGET, &exe, true).unwrap();
        assert_eq!(listing(dir.path()), ["vci", "vci.old"]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("vci.old")).unwrap(),
            "old binary"
        );
        assert!(std::fs::read_to_string(&exe).unwrap().contains("vci 9.9.9"));
        assert!(r.root.join("releases/latest").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_wrong_checksum_changes_nothing() {
        let r = release("9.9.9", "vci 9.9.9", Some(&"0".repeat(64)));
        let (dir, exe) = old_binary();
        let e = install_release(&r.src, &v("9.9.9"), TARGET, &exe, true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("sha256") && e.contains("was not changed"), "{e}");
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old binary");
        assert_eq!(listing(dir.path()), ["vci"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_is_not_the_release_changes_nothing() {
        let r = release("9.9.9", "vci 1.0.0", None);
        let (dir, exe) = old_binary();
        let e = install_release(&r.src, &v("9.9.9"), TARGET, &exe, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not run as vci 9.9.9"), "{e}");
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old binary");
        assert_eq!(listing(dir.path()), ["vci"]);

        // A release without this platform's tarball.
        let e = install_release(&r.src, &v("9.9.9"), "riscv-none", &exe, false)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("could not fetch") || e.contains("no vci-riscv-none"),
            "{e}"
        );
        assert_eq!(listing(dir.path()), ["vci"]);
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_is_refused_with_the_command() {
        use std::os::unix::fs::PermissionsExt as _;
        let r = release("9.9.9", "vci 9.9.9", None);
        let (dir, exe) = old_binary();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let res = install_release(&r.src, &v("9.9.9"), TARGET, &exe, false);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        // Root can write anyway; then it simply succeeds.
        if let Err(e) = res {
            let e = e.to_string();
            assert!(e.contains("cannot write to") && e.contains("sudo"), "{e}");
            assert!(e.contains("update --version 9.9.9"), "{e}");
            assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old binary");
        }
    }
}
