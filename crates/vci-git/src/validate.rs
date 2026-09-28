//! Argument validation. Everything that becomes part of a ref name, tree path
//! or command line is checked here first.

use crate::GitError;

pub(crate) const SIGNER_ID_LEN: usize = 16;
pub(crate) const MIN_HEX_LEN: usize = 2;
pub(crate) const MAX_HEX_LEN: usize = 128;

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn invalid(what: &'static str, value: &str, reason: &'static str) -> GitError {
    GitError::Invalid {
        what,
        value: value.to_owned(),
        reason,
    }
}

/// Exactly 16 lowercase hex characters.
pub(crate) fn signer_id(s: &str) -> Result<(), GitError> {
    if s.len() != SIGNER_ID_LEN {
        return Err(invalid("signer_id", s, "must be exactly 16 characters"));
    }
    if !is_lower_hex(s) {
        return Err(invalid("signer_id", s, "must be lowercase hex"));
    }
    Ok(())
}

/// Lowercase hex, 2..=128 characters (blake3 hex is 64).
pub(crate) fn hex_id(what: &'static str, s: &str) -> Result<(), GitError> {
    if s.len() < MIN_HEX_LEN || s.len() > MAX_HEX_LEN {
        return Err(invalid(what, s, "must be 2 to 128 characters"));
    }
    if !is_lower_hex(s) {
        return Err(invalid(what, s, "must be lowercase hex"));
    }
    Ok(())
}

pub(crate) fn is_signer_id(s: &str) -> bool {
    signer_id(s).is_ok()
}

pub(crate) fn is_hex_id(s: &str) -> bool {
    hex_id("id", s).is_ok()
}

/// A revision expression we are willing to hand to git: non-empty, not
/// option-like, no control characters, no `:` (so `rev:path` can't be
/// smuggled in).
pub(crate) fn rev(s: &str) -> Result<(), GitError> {
    if s.is_empty() {
        return Err(invalid("revision", s, "must not be empty"));
    }
    if s.starts_with('-') {
        return Err(invalid("revision", s, "must not start with '-'"));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(invalid(
            "revision",
            s,
            "must not contain control characters",
        ));
    }
    if s.contains(':') {
        return Err(invalid("revision", s, "must not contain ':'"));
    }
    Ok(())
}

/// A repo-relative path: '/'-separated, no empty, '.' or '..' components, no
/// leading or trailing '/', no NUL.
pub(crate) fn repo_path(s: &str) -> Result<(), GitError> {
    if s.is_empty() {
        return Err(invalid("path", s, "must not be empty"));
    }
    if s.contains('\0') {
        return Err(invalid("path", s, "must not contain NUL"));
    }
    if s.starts_with('/') {
        return Err(invalid("path", s, "must be repo-relative"));
    }
    for comp in s.split('/') {
        match comp {
            "" => return Err(invalid("path", s, "must not contain empty components")),
            "." | ".." => return Err(invalid("path", s, "must not contain '.' or '..'")),
            _ => {}
        }
    }
    Ok(())
}

/// A remote name or URL: non-empty, not option-like, no control characters.
pub(crate) fn remote(s: &str) -> Result<(), GitError> {
    if s.is_empty() {
        return Err(invalid("remote", s, "must not be empty"));
    }
    if s.starts_with('-') {
        return Err(invalid("remote", s, "must not start with '-'"));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(invalid("remote", s, "must not contain control characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_ids() {
        assert!(signer_id("0123456789abcdef").is_ok());
        for bad in [
            "",
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
            "../../heads/main",
            "0123456789abcdeg",
            "01234567/9abcdef",
            "0123456789abcde\n",
        ] {
            assert!(signer_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hex_ids() {
        assert!(hex_id("t", "ab").is_ok());
        assert!(hex_id("t", &"a".repeat(64)).is_ok());
        for bad in ["", "a", "AB", "a/b", "..", "ab.dsse.json", &"a".repeat(129)] {
            assert!(hex_id("t", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn paths_and_revs() {
        assert!(repo_path("a/b.txt").is_ok());
        for bad in ["", "/a", "a/", "a//b", "./a", "a/../b", "..", "a\0b"] {
            assert!(repo_path(bad).is_err(), "{bad:?}");
        }
        assert!(rev("HEAD~1").is_ok());
        for bad in ["", "--output=x", "HEAD:secret", "a\nb"] {
            assert!(rev(bad).is_err(), "{bad:?}");
        }
    }
}
