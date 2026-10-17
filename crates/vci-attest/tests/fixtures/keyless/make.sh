#!/usr/bin/env bash
# Regenerates the keyless test fixtures in this directory (run by hand; the
# tests only read the files). Needs OpenSSL 3.4+ and network access to
# GitHub's timestamp authority.
#
# A local, Fulcio-like certificate authority (root and intermediate, ECDSA
# P-384 like GitHub's) issues a P-256 leaf carrying Fulcio's GitHub Actions
# extensions, valid for 10 minutes from now, and a second leaf for the same key
# that expired in 2020. The leaf key signs the DSSE PAE of statement.json;
# timestamp.githubapp.com (the real TSA) timestamps that signature. The trust
# root lists the local authority and GitHub's real timestamp authorities (from
# gh-trusted-root-2026-10-16.jsonl).
#
# Outputs: envelope.json (stored form: DSSE fields + sigstore member),
# expired-leaf.der, impostor-intermediate.der, trusted-root.json.
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl ecparam -name secp384r1 -genkey -noout -out "$work/root.key"
openssl ecparam -name secp384r1 -genkey -noout -out "$work/int.key"
openssl ecparam -name prime256v1 -genkey -noout -out "$work/leaf.key"

openssl req -new -x509 -key "$work/root.key" -sha384 -days 3650 \
  -subj "/O=vci test/CN=Test Root" -out "$work/root.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -new -key "$work/int.key" -subj "/O=vci test/CN=Test Fulcio Intermediate" -out "$work/int.csr"
cat > "$work/int.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
openssl x509 -req -in "$work/int.csr" -CA "$work/root.pem" -CAkey "$work/root.key" -sha384 \
  -days 3650 -set_serial 2 -extfile "$work/int.ext" -out "$work/int.pem"

# An impostor: the intermediate's name with another key (also issued by the root).
openssl ecparam -name secp384r1 -genkey -noout -out "$work/imp.key"
openssl req -new -key "$work/imp.key" -subj "/O=vci test/CN=Test Fulcio Intermediate" -out "$work/imp.csr"
openssl x509 -req -in "$work/imp.csr" -CA "$work/root.pem" -CAkey "$work/root.key" -sha384 \
  -days 3650 -set_serial 5 -extfile "$work/int.ext" -outform DER -out impostor-intermediate.der

cat > "$work/leaf.ext" <<'EOF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectAltName=critical,URI:https://github.com/ComposalAI/vex/.github/workflows/vci.yml@refs/heads/master
1.3.6.1.4.1.57264.1.8=ASN1:UTF8String:https://token.actions.githubusercontent.com
1.3.6.1.4.1.57264.1.9=ASN1:UTF8String:https://github.com/ComposalAI/vex/.github/workflows/vci.yml@refs/heads/master
1.3.6.1.4.1.57264.1.11=ASN1:UTF8String:github-hosted
1.3.6.1.4.1.57264.1.12=ASN1:UTF8String:https://github.com/ComposalAI/vex
1.3.6.1.4.1.57264.1.13=ASN1:UTF8String:0123456789abcdef0123456789abcdef01234567
1.3.6.1.4.1.57264.1.14=ASN1:UTF8String:refs/heads/master
1.3.6.1.4.1.57264.1.20=ASN1:UTF8String:push
1.3.6.1.4.1.57264.1.21=ASN1:UTF8String:https://github.com/ComposalAI/vex/actions/runs/1/attempts/1
EOF
openssl req -new -key "$work/leaf.key" -subj "/" -out "$work/leaf.csr"
nb=$(date -u -v-1M +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '-1 min' +%Y%m%d%H%M%SZ)
na=$(date -u -v+10M +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '+10 min' +%Y%m%d%H%M%SZ)
openssl x509 -req -in "$work/leaf.csr" -CA "$work/int.pem" -CAkey "$work/int.key" -sha384 \
  -not_before "$nb" -not_after "$na" -set_serial 3 -extfile "$work/leaf.ext" -outform DER -out "$work/leaf.der"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/int.pem" -CAkey "$work/int.key" -sha384 \
  -not_before 20200101000000Z -not_after 20200101001000Z -set_serial 4 -extfile "$work/leaf.ext" \
  -outform DER -out expired-leaf.der

printf '%s' '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"t.test.ts","digest":{"blake3":"ab"}}],"predicateType":"https://vci.dev/test-attestation/v1","predicate":{"x":1}}' > "$work/statement.json"
type="application/vnd.in-toto+json"
len=$(wc -c < "$work/statement.json" | tr -d ' ')
{ printf 'DSSEv1 %s %s %s ' "${#type}" "$type" "$len"; cat "$work/statement.json"; } > "$work/pae"
openssl dgst -sha256 -sign "$work/leaf.key" -out "$work/sig" "$work/pae"

hash=$(openssl dgst -sha256 -binary "$work/sig" | base64)
curl -sS --fail -H 'Content-Type: application/json' \
  --data-binary "{\"artifactHash\":\"$hash\",\"hashAlgorithm\":\"sha256\"}" \
  https://timestamp.githubapp.com/api/v1/timestamp -o "$work/tsr"

python3 - "$work" <<'PY'
import base64, json, subprocess, sys
w = sys.argv[1]
b64 = lambda p: base64.b64encode(open(p, "rb").read()).decode()
der = lambda pem: subprocess.run(["openssl", "x509", "-in", pem, "-outform", "DER"], capture_output=True, check=True).stdout
env = {
    "payloadType": "application/vnd.in-toto+json",
    "payload": b64(f"{w}/statement.json"),
    "signatures": [{"keyid": "", "sig": b64(f"{w}/sig")}],
    "sigstore": {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": b64(f"{w}/leaf.der")},
            "tlogEntries": [],
            "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": b64(f"{w}/tsr")}]},
        },
    },
}
json.dump(env, open("envelope.json", "w"), indent=1)
gh = [json.loads(l) for l in open("gh-trusted-root-2026-10-16.jsonl")]
github = next(r for r in gh if any("githubapp" in a.get("uri", "") for a in r.get("timestampAuthorities", [])))
root = {
    "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "certificateAuthorities": [{
        "subject": {"organization": "vci test", "commonName": "Test Root"},
        "uri": "fulcio.test",
        "certChain": {"certificates": [
            {"rawBytes": base64.b64encode(der(f"{w}/int.pem")).decode()},
            {"rawBytes": base64.b64encode(der(f"{w}/root.pem")).decode()},
        ]},
        "validFor": {"start": "2020-01-01T00:00:00Z"},
    }],
    "timestampAuthorities": github["timestampAuthorities"],
}
json.dump(root, open("trusted-root.json", "w"), indent=1)
PY
echo "wrote envelope.json, expired-leaf.der, impostor-intermediate.der, trusted-root.json"
