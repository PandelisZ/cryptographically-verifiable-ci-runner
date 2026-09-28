//! Signing key discovery and signer ids.

use std::process::Command;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};

/// A signing key: the path handed to `ssh-keygen -Y sign` plus its public half.
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub path: Utf8PathBuf,
    /// `<type> <base64>` (no comment).
    pub public: String,
    /// Decoded public key blob.
    pub blob: Vec<u8>,
}

impl SigningKey {
    /// First 16 hex chars of SHA-256 over the public key blob.
    pub fn signer_id(&self) -> String {
        signer_id(&self.blob)
    }
}

pub fn signer_id(blob: &[u8]) -> String {
    hex::encode(Sha256::digest(blob))[..16].to_owned()
}

/// Parse an OpenSSH public key line (`type base64 [comment]`).
pub fn parse_public(line: &str) -> Result<(String, Vec<u8>)> {
    let mut it = line.split_whitespace();
    let ty = it.next().context("empty public key")?;
    let b64 = it.next().context("public key without base64 blob")?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("public key base64")?;
    Ok((format!("{ty} {b64}"), blob))
}

fn read_public(path: &Utf8Path) -> Result<String> {
    if path.extension() == Some("pub") {
        return std::fs::read_to_string(path).with_context(|| format!("reading {path}"));
    }
    let pub_path = Utf8PathBuf::from(format!("{path}.pub"));
    if pub_path.is_file() {
        return std::fs::read_to_string(&pub_path).with_context(|| format!("reading {pub_path}"));
    }
    let out = Command::new("ssh-keygen")
        .args(["-y", "-f", path.as_str()])
        .output()
        .context("running ssh-keygen -y")?;
    if !out.status.success() {
        bail!(
            "ssh-keygen -y -f {path} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Load a key from `path` (private key, or `.pub` whose private half is in
/// ssh-agent).
pub fn load(path: &Utf8Path) -> Result<SigningKey> {
    let text = read_public(path)?;
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .context("no public key found")?;
    let (public, blob) = parse_public(line)?;
    Ok(SigningKey {
        path: path.to_owned(),
        public,
        blob,
    })
}

fn git_config(repo_root: &Utf8Path, key: &str) -> Result<Option<String>> {
    let out = Command::new("git")
        .args(["-C", repo_root.as_str(), "config", "--get", key])
        .output()
        .context("running git config")?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Ok((out.status.success() && !v.is_empty()).then_some(v))
}

/// `--key`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` (only
/// when `gpg.format = ssh`: otherwise it names a GPG key, not an SSH key file).
/// Errors name the source the key came from.
pub fn discover(explicit: Option<&Utf8Path>, repo_root: &Utf8Path) -> Result<SigningKey> {
    if let Some(p) = explicit {
        return load(p).with_context(|| format!("loading the signing key from --key {p}"));
    }
    if let Ok(p) = std::env::var("VCI_SIGNING_KEY")
        && !p.is_empty()
    {
        return load(Utf8Path::new(&p))
            .with_context(|| format!("loading the signing key from $VCI_SIGNING_KEY ({p})"));
    }
    let Some(v) = git_config(repo_root, "user.signingkey")? else {
        bail!(
            "no signing key: pass --key, set VCI_SIGNING_KEY, or set git config user.signingkey (with gpg.format = ssh)"
        )
    };
    let format = git_config(repo_root, "gpg.format")?;
    if format.as_deref() != Some("ssh") {
        bail!(
            "no signing key: git config user.signingkey ({v}) is not used because gpg.format is {} (not \"ssh\"), so it names a GPG key; pass --key or set VCI_SIGNING_KEY",
            format.map_or_else(|| "unset".to_owned(), |f| format!("{f:?}"))
        );
    }
    if v.starts_with("key::") {
        bail!(
            "no signing key: git config user.signingkey is a literal public key (key::...); vci needs a key file: pass --key or set VCI_SIGNING_KEY"
        );
    }
    let expanded = match v.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => v.clone(),
    };
    load(Utf8Path::new(&expanded))
        .with_context(|| format!("loading the signing key from git config user.signingkey ({v})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a GPG `user.signingkey` (the common global setting) was
    /// handed to `ssh-keygen -y -f` and failed with a confusing error.
    #[test]
    fn gpg_signing_key_is_not_used_as_an_ssh_key() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let git = |args: &[&str]| {
            let st = Command::new("git")
                .arg("-C")
                .arg(root.as_str())
                .args(args)
                .status()
                .unwrap();
            assert!(st.success());
        };
        git(&["init", "-q"]);
        git(&[
            "config",
            "user.signingkey",
            "1A19696C8E36DD255436C9258F74F81E4A18C01A",
        ]);
        git(&["config", "gpg.format", "openpgp"]);
        if std::env::var_os("VCI_SIGNING_KEY").is_some_and(|v| !v.is_empty()) {
            return; // the env var takes precedence over git config
        }
        let err = format!("{:#}", discover(None, &root).unwrap_err());
        assert!(!err.contains("ssh-keygen"), "{err}");
        assert!(
            err.contains("user.signingkey") && err.contains("gpg.format"),
            "{err}"
        );
    }

    #[test]
    fn signer_id_is_16_hex_of_sha256_blob() {
        let (_, blob) = parse_public(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrl1rF7zZ4m9n8C7Z3pRj4gWm0M7zX5l2Y2q3xX0pQk me@x",
        )
        .unwrap();
        let id = signer_id(&blob);
        assert_eq!(id.len(), 16);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(id, hex::encode(Sha256::digest(&blob))[..16]);
    }
}
