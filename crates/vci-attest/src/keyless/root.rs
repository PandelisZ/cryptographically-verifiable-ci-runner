//! The Sigstore trust root (`application/vnd.dev.sigstore.trustedroot+json`),
//! as `gh attestation trusted-root` prints it: one JSON object per instance
//! (JSON Lines), or a single object.

use serde::Deserialize;

use super::x509::Cert;

/// `.vci/sigstore-trusted-root.json`, read from the base commit.
pub const TRUSTED_ROOT_FILE: &str = ".vci/sigstore-trusted-root.json";

/// A certificate or timestamp authority of the trust root.
pub struct Authority {
    /// `uri` (e.g. `fulcio.githubapp.com`), for messages.
    pub uri: String,
    /// Issuing certificate first, root last.
    pub(crate) chain: Vec<Cert>,
    pub valid_for: ValidFor,
}

/// `validFor` of an authority (unix seconds; `None`: unbounded).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidFor {
    pub start: Option<i64>,
    pub end: Option<i64>,
}

impl ValidFor {
    pub fn contains(&self, t: i64) -> bool {
        self.start.is_none_or(|s| t >= s) && self.end.is_none_or(|e| t <= e)
    }
}

/// Every certificate and timestamp authority of every trust root in the file.
pub struct TrustedRoot {
    pub certificate_authorities: Vec<Authority>,
    pub timestamp_authorities: Vec<Authority>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RootJson {
    media_type: String,
    #[serde(default)]
    certificate_authorities: Vec<AuthorityJson>,
    #[serde(default)]
    timestamp_authorities: Vec<AuthorityJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityJson {
    #[serde(default)]
    uri: String,
    cert_chain: ChainJson,
    #[serde(default)]
    valid_for: Option<ValidForJson>,
}

#[derive(Deserialize)]
struct ChainJson {
    certificates: Vec<RawBytesJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBytesJson {
    raw_bytes: String,
}

#[derive(Deserialize)]
struct ValidForJson {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

fn rfc3339(s: &str) -> Result<i64, String> {
    s.parse::<jiff::Timestamp>()
        .map(|t| t.as_second())
        .map_err(|e| format!("time {s:?}: {e}"))
}

fn authority(a: AuthorityJson) -> Result<Authority, String> {
    let chain = a
        .cert_chain
        .certificates
        .iter()
        .map(|c| {
            crate::b64_decode(&c.raw_bytes)
                .map_err(|e| format!("rawBytes base64: {e}"))
                .and_then(|d| Cert::parse(&d))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", a.uri))?;
    if chain.is_empty() {
        return Err(format!("{}: empty certChain", a.uri));
    }
    let valid_for = match a.valid_for {
        None => ValidFor::default(),
        Some(v) => ValidFor {
            start: v.start.as_deref().map(rfc3339).transpose()?,
            end: v.end.as_deref().map(rfc3339).transpose()?,
        },
    };
    Ok(Authority {
        uri: a.uri,
        chain,
        valid_for,
    })
}

impl TrustedRoot {
    /// Parse one trust root object, or several (JSON Lines or concatenated).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut out = TrustedRoot {
            certificate_authorities: vec![],
            timestamp_authorities: vec![],
        };
        let mut n = 0;
        for v in serde_json::Deserializer::from_str(text).into_iter::<RootJson>() {
            let v = v.map_err(|e| format!("trust root JSON: {e}"))?;
            if !v
                .media_type
                .starts_with("application/vnd.dev.sigstore.trustedroot")
            {
                return Err(format!(
                    "mediaType {:?} is not a Sigstore trusted root",
                    v.media_type
                ));
            }
            for a in v.certificate_authorities {
                out.certificate_authorities.push(authority(a)?);
            }
            for a in v.timestamp_authorities {
                out.timestamp_authorities.push(authority(a)?);
            }
            n += 1;
        }
        if n == 0 {
            return Err("no trusted root in the file".into());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_for_bounds() {
        let v = ValidFor {
            start: Some(10),
            end: Some(20),
        };
        assert!(v.contains(10) && v.contains(20) && !v.contains(9) && !v.contains(21));
        assert!(ValidFor::default().contains(i64::MIN));
    }

    #[test]
    fn rejects_other_documents() {
        assert!(TrustedRoot::parse("").is_err());
        assert!(TrustedRoot::parse(r#"{"mediaType":"x"}"#).is_err());
        assert!(TrustedRoot::parse("not json").is_err());
    }
}
