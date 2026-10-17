//! RFC 3161 timestamps: the `TimeStampResp` a Sigstore TSA returns (a CMS
//! SignedData over a TSTInfo), checked against the trust root's TSA
//! certificates.
//!
//! Parsed by hand with `der` so that the signed attributes are verified over
//! the exact bytes the TSA signed (never re-encoded or re-sorted).

use der::asn1::{ObjectIdentifier, OctetStringRef};
use der::{Any, Decode as _, Encode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};

use super::root::TrustedRoot;
use super::x509::{self, Cert};

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// What a verified timestamp says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    /// genTime, unix seconds (fractions dropped).
    pub time: i64,
    /// The trust root entry (`uri`) whose certificate signed it.
    pub authority: String,
}

struct SignerInfo<'a> {
    issuer_serial: Option<(Vec<u8>, Vec<u8>)>,
    digest_alg: ObjectIdentifier,
    /// `[0] IMPLICIT SET OF Attribute` contents (the SET's value bytes).
    signed_attrs: Option<&'a [u8]>,
    sig_alg: ObjectIdentifier,
    signature: &'a [u8],
}

struct Token<'a> {
    tst_info: &'a [u8],
    signer: SignerInfo<'a>,
}

fn err(e: der::Error) -> String {
    e.to_string()
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }`.
/// A bare `ContentInfo` (the token alone) is accepted too.
fn token_bytes(resp: &[u8]) -> Result<&[u8], String> {
    let mut r = SliceReader::new(resp).map_err(err)?;
    let first = r
        .sequence(|r| {
            let a: Any = r.decode()?;
            // Skip the rest; we only look at the first element here.
            while !r.is_finished() {
                let _: Any = r.decode()?;
            }
            Ok(a)
        })
        .map_err(err)?;
    if first.tag() == Tag::ObjectIdentifier {
        // ContentInfo itself.
        return Ok(resp);
    }
    // TimeStampResp: status, then the token.
    let mut r = SliceReader::new(resp).map_err(err)?;
    let header = der::Header::decode(&mut r).map_err(err)?;
    let body = r.read_slice(header.length).map_err(err)?;
    let mut r = SliceReader::new(body).map_err(err)?;
    let status: Any = r.decode().map_err(err)?;
    let mut sr = SliceReader::new(status.value()).map_err(err)?;
    let code: u8 = sr.decode().map_err(err)?;
    if code > 1 {
        return Err(format!("the TSA refused the request (status {code})"));
    }
    if r.is_finished() {
        return Err("the response has no timestamp token".into());
    }
    let start = r.position();
    let tok: Any = r.decode().map_err(err)?;
    let len = tok.encoded_len().map_err(err)?;
    let start = usize::try_from(start).map_err(err)?;
    let len = usize::try_from(len).map_err(err)?;
    Ok(&body[start..start + len])
}

fn parse_token(bytes: &[u8]) -> Result<Token<'_>, String> {
    // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content }
    let mut r = SliceReader::new(bytes).map_err(err)?;
    let ci = der::Header::decode(&mut r).map_err(err)?;
    let ci_body = r.read_slice(ci.length).map_err(err)?;
    let mut r = SliceReader::new(ci_body).map_err(err)?;
    let ct: ObjectIdentifier = r.decode().map_err(err)?;
    if ct != ID_SIGNED_DATA {
        return Err(format!(
            "timestamp token content type {ct} is not SignedData"
        ));
    }
    let explicit = der::Header::decode(&mut r).map_err(err)?;
    if explicit.tag
        != (Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::N0,
        })
    {
        return Err("timestamp token: expected [0] content".into());
    }
    let sd_bytes = r.read_slice(explicit.length).map_err(err)?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
    //   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos SET }
    let mut r = SliceReader::new(sd_bytes).map_err(err)?;
    let sd = der::Header::decode(&mut r).map_err(err)?;
    let sd_body = r.read_slice(sd.length).map_err(err)?;
    let mut r = SliceReader::new(sd_body).map_err(err)?;
    let _version: Any = r.decode().map_err(err)?;
    let _digest_algs: Any = r.decode().map_err(err)?;
    // EncapsulatedContentInfo ::= SEQUENCE { eContentType, [0] EXPLICIT OCTET STRING }
    let eci_h = der::Header::decode(&mut r).map_err(err)?;
    let eci = r.read_slice(eci_h.length).map_err(err)?;
    let tst_info = {
        let mut er = SliceReader::new(eci).map_err(err)?;
        let ect: ObjectIdentifier = er.decode().map_err(err)?;
        if ect != ID_CT_TST_INFO {
            return Err(format!("timestamp content type {ect} is not TSTInfo"));
        }
        let h = der::Header::decode(&mut er).map_err(err)?;
        let inner = er.read_slice(h.length).map_err(err)?;
        OctetStringRef::from_der(inner).map_err(err)?.as_bytes()
    };
    let mut signer_infos = None;
    while !r.is_finished() {
        let h = der::Header::decode(&mut r).map_err(err)?;
        let v = r.read_slice(h.length).map_err(err)?;
        if h.tag == Tag::Set {
            signer_infos = Some(v);
        }
    }
    let si_set = signer_infos.ok_or("timestamp token without signerInfos")?;
    let mut r = SliceReader::new(si_set).map_err(err)?;
    let si_h = der::Header::decode(&mut r).map_err(err)?;
    let si = r.read_slice(si_h.length).map_err(err)?;
    if !r.is_finished() {
        return Err("timestamp token with more than one signer".into());
    }
    Ok(Token {
        tst_info,
        signer: parse_signer_info(si)?,
    })
}

fn parse_signer_info(si: &[u8]) -> Result<SignerInfo<'_>, String> {
    let mut r = SliceReader::new(si).map_err(err)?;
    let _version: Any = r.decode().map_err(err)?;
    // sid: IssuerAndSerialNumber (SEQUENCE) or [0] SubjectKeyIdentifier.
    let sid: Any = r.decode().map_err(err)?;
    let issuer_serial = if sid.tag() == Tag::Sequence {
        let mut sr = SliceReader::new(sid.value()).map_err(err)?;
        let name: Any = sr.decode().map_err(err)?;
        let serial: Any = sr.decode().map_err(err)?;
        Some((name.to_der().map_err(err)?, serial.value().to_vec()))
    } else {
        None
    };
    let digest_alg = alg_oid(&mut r)?;
    let mut signed_attrs = None;
    let h = der::Header::decode(&mut r).map_err(err)?;
    let v = r.read_slice(h.length).map_err(err)?;
    let sig_alg = if h.tag
        == (Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::N0,
        }) {
        signed_attrs = Some(v);
        alg_oid(&mut r)?
    } else {
        let mut ar = SliceReader::new(v).map_err(err)?;
        ar.decode::<ObjectIdentifier>().map_err(err)?
    };
    let signature = OctetStringRef::decode(&mut r).map_err(err)?.as_bytes();
    Ok(SignerInfo {
        issuer_serial,
        digest_alg,
        signed_attrs,
        sig_alg,
        signature,
    })
}

fn alg_oid<'a>(r: &mut SliceReader<'a>) -> Result<ObjectIdentifier, String> {
    let h = der::Header::decode(r).map_err(err)?;
    let v = r.read_slice(h.length).map_err(err)?;
    let mut ar = SliceReader::new(v).map_err(err)?;
    ar.decode::<ObjectIdentifier>().map_err(err)
}

/// TSTInfo: (hash algorithm, hashed message, genTime).
fn parse_tst_info(b: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>, i64), String> {
    let mut r = SliceReader::new(b).map_err(err)?;
    let h = der::Header::decode(&mut r).map_err(err)?;
    let body = r.read_slice(h.length).map_err(err)?;
    let mut r = SliceReader::new(body).map_err(err)?;
    let _version: Any = r.decode().map_err(err)?;
    let _policy: ObjectIdentifier = r.decode().map_err(err)?;
    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    let mi_h = der::Header::decode(&mut r).map_err(err)?;
    let mi = r.read_slice(mi_h.length).map_err(err)?;
    let mut mr = SliceReader::new(mi).map_err(err)?;
    let hash_alg = alg_oid(&mut mr)?;
    let hashed = OctetStringRef::decode(&mut mr)
        .map_err(err)?
        .as_bytes()
        .to_vec();
    let _serial: Any = r.decode().map_err(err)?;
    let gen_time: Any = r.decode().map_err(err)?;
    if gen_time.tag() != Tag::GeneralizedTime {
        return Err("TSTInfo genTime is not a GeneralizedTime".into());
    }
    let time = parse_generalized_time(gen_time.value())?;
    Ok((hash_alg, hashed, time))
}

/// `YYYYMMDDHHMMSS[.f*]Z` (RFC 3161 allows fractional seconds, which DER's
/// GeneralizedTime type in `der` does not).
fn parse_generalized_time(v: &[u8]) -> Result<i64, String> {
    let s = std::str::from_utf8(v).map_err(|_| "genTime is not ASCII".to_owned())?;
    let bad = || format!("genTime {s:?} is not YYYYMMDDHHMMSS[.fff]Z");
    let s2 = s.strip_suffix('Z').ok_or_else(bad)?;
    let (whole, _frac) = s2.split_once('.').unwrap_or((s2, ""));
    if whole.len() != 14 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n = |a: usize, b: usize| whole[a..b].parse::<i16>().map_err(|_| bad());
    let dt = jiff::civil::DateTime::new(
        n(0, 4)?,
        n(4, 6)? as i8,
        n(6, 8)? as i8,
        n(8, 10)? as i8,
        n(10, 12)? as i8,
        n(12, 14)? as i8,
        0,
    )
    .map_err(|_| bad())?;
    let ts = dt
        .to_zoned(jiff::tz::TimeZone::UTC)
        .map_err(|_| bad())?
        .timestamp();
    Ok(ts.as_second())
}

/// Attribute values of `oid` in a SET OF Attribute body.
fn attr(attrs: &[u8], oid: ObjectIdentifier) -> Result<Option<&[u8]>, String> {
    let mut r = SliceReader::new(attrs).map_err(err)?;
    while !r.is_finished() {
        let h = der::Header::decode(&mut r).map_err(err)?;
        let a = r.read_slice(h.length).map_err(err)?;
        let mut ar = SliceReader::new(a).map_err(err)?;
        let id: ObjectIdentifier = ar.decode().map_err(err)?;
        let set_h = der::Header::decode(&mut ar).map_err(err)?;
        let values = ar.read_slice(set_h.length).map_err(err)?;
        if id == oid {
            return Ok(Some(values));
        }
    }
    Ok(None)
}

/// Verify `resp` (a DER TimeStampResp, as stored in a Sigstore bundle) as a
/// timestamp over `signed` (the bytes the TSA was asked to timestamp: the
/// artifact signature) by a timestamp authority of `root`. Returns the time.
pub fn verify_timestamp(
    resp: &[u8],
    signed: &[u8],
    root: &TrustedRoot,
) -> Result<Timestamp, String> {
    let token = parse_token(token_bytes(resp)?)?;
    let (hash_alg, hashed, time) = parse_tst_info(token.tst_info)?;
    if x509::digest(&hash_alg, signed)? != hashed {
        return Err("the timestamp is for other data (message imprint differs)".into());
    }
    let si = &token.signer;
    // What the TSA's key signed: the signed attributes re-tagged as a SET
    // (RFC 5652 5.4), which must bind the TSTInfo; or the TSTInfo itself.
    let message = match si.signed_attrs {
        Some(attrs) => {
            let ct =
                attr(attrs, ID_CONTENT_TYPE)?.ok_or("signed attributes without contentType")?;
            if ObjectIdentifier::from_der(ct).map_err(err)? != ID_CT_TST_INFO {
                return Err("signed contentType is not TSTInfo".into());
            }
            let md =
                attr(attrs, ID_MESSAGE_DIGEST)?.ok_or("signed attributes without messageDigest")?;
            let md = OctetStringRef::from_der(md).map_err(err)?;
            if md.as_bytes() != x509::digest(&si.digest_alg, token.tst_info)? {
                return Err("messageDigest does not match the TSTInfo".into());
            }
            let mut m = Vec::with_capacity(attrs.len() + 4);
            der::Header::new(Tag::Set, der::Length::try_from(attrs.len()).map_err(err)?)
                .map_err(err)?
                .encode_to_vec(&mut m)
                .map_err(err)?;
            m.extend_from_slice(attrs);
            m
        }
        None => token.tst_info.to_vec(),
    };
    let mut last = "the trust root lists no timestamp authority".to_owned();
    for tsa in &root.timestamp_authorities {
        let Some(leaf) = tsa.chain.first() else {
            continue;
        };
        if let Some((issuer, serial)) = &si.issuer_serial
            && (leaf.issuer_der() != *issuer || leaf.serial() != serial.as_slice())
        {
            continue;
        }
        let key = match leaf.key() {
            Ok(k) => k,
            Err(e) => {
                last = e;
                continue;
            }
        };
        if let Err(e) = key.verify(&si.sig_alg, &message, si.signature) {
            last = format!("{}: {e}", leaf.subject());
            continue;
        }
        if time < leaf.not_before() || time > leaf.not_after() {
            last = format!(
                "the timestamp ({time}) is outside the validity of the TSA certificate {}",
                leaf.subject()
            );
            continue;
        }
        if !tsa.valid_for.contains(time) {
            last = format!(
                "the timestamp ({time}) is outside the trust root's validFor of {}",
                tsa.uri
            );
            continue;
        }
        if let Err(e) = chain_ok(&tsa.chain) {
            last = e;
            continue;
        }
        return Ok(Timestamp {
            time,
            authority: tsa.uri.clone(),
        });
    }
    if si.issuer_serial.is_some() && last.starts_with("the trust root lists") {
        last = "no timestamp authority of the trust root has the signing certificate".into();
    }
    Err(last)
}

/// Each certificate of a trust root chain is issued by the next.
pub(crate) fn chain_ok(chain: &[Cert]) -> Result<(), String> {
    for w in chain.windows(2) {
        w[0].issued_by(&w[1])
            .map_err(|e| format!("trust root chain: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_with_and_without_fraction() {
        assert_eq!(parse_generalized_time(b"19700101000000Z").unwrap(), 0);
        assert_eq!(
            parse_generalized_time(b"20261017005859Z").unwrap(),
            parse_generalized_time(b"20261017005859.123Z").unwrap()
        );
        assert!(parse_generalized_time(b"20261017005859").is_err());
        assert!(parse_generalized_time(b"2026101700585Z").is_err());
    }
}
