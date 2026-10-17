# Keyless (OIDC / Sigstore) signing: findings

Checked on 2026-10-16 against the sources named below (actions/toolkit `packages/attest` at commit
`b679af25032f1f40e4dee4143e4ed9422b386073`, 2026-10-06; sigstore-js `packages/sign` on `main`; Fulcio
`docs/oid-info.md` on `main`; cli/cli `pkg/cmd/attestation/trustedroot`; `gh` 2.102.0), live requests to both
timestamp authorities, and the trust root `gh attestation trusted-root` printed that day. These are the facts vci's
keyless signing (`vci run --oidc`, `vci ci --oidc`, the action's `oidc: true`) relies on.

## The job's identity token

- A job gets an OIDC token only with `permissions: id-token: write`. The runner then sets
  `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`; the token is
  `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore` with `Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
  answered with `{"value": "<JWT>"}` (sigstore-js `identity/ci.ts`; the URL already carries a query string, so the
  audience is appended with `&`). sigstore-js also takes a ready token from `SIGSTORE_ID_TOKEN`; vci does the same.
- Audience `sigstore` for Fulcio (sigstore-js `OIDC_AUDIENCE`, actions/toolkit `sign.ts`).
- Issuer: `https://token.actions.githubusercontent.com` on github.com; `https://token.actions.<host>` on a GHE.com
  tenant (actions/toolkit `oidc.ts` `getIssuer`, which accepts `https://github.com` and `https://<slug>.ghe.com`).
- Claims vci uses (actions/toolkit `oidc.ts` `REQUIRED_CLAIMS` lists `iss ref sha repository event_name
  job_workflow_ref workflow_ref repository_id repository_owner_id runner_environment run_id run_attempt`): `iss`,
  `sub` (signed for Fulcio's proof of possession), `repository` (`owner/name`), `job_workflow_ref`
  (`owner/name/.github/workflows/x.yml@refs/heads/main`: the workflow file the job is defined in, a reusable
  workflow's own file when the job calls one), `ref`, `event_name`, `environment` (only for a job with an
  `environment:`), `runner_environment` (`github-hosted` or `self-hosted`). vci decodes the token's payload only to
  name the signer (store key, principal for `vci ci`'s refusal); trust never comes from the token, only from the
  certificate Fulcio issues for it.

## Keyless signing

Exactly what `actions/attest` does (actions/toolkit `sign.ts` with sigstore-js `FulcioSigner`, `TSAWitness`,
`DSSEBundleBuilder`):

1. An ephemeral ECDSA P-256 key, in memory only.
2. Fulcio: `POST <fulcio>/api/v2/signingCert`, JSON
   `{"credentials":{"oidcIdentityToken":"<JWT>"},"publicKeyRequest":{"publicKey":{"algorithm":"ECDSA","content":"<PEM SPKI>"},"proofOfPossession":"<base64 ECDSA-SHA256 signature over the token's sub claim>"}}`.
   The answer is `signedCertificateEmbeddedSct.chain.certificates` or `signedCertificateDetachedSct.chain.certificates`
   (PEM strings, leaf first). The certificate is valid for 10 minutes.
3. The signature: ECDSA-SHA256 over the DSSE PAE of the payload (DER signature, base64 in the envelope's `sig`,
   `keyid` empty).
4. A witness: a Rekor entry and/or an RFC 3161 timestamp. The timestamp request is
   `POST <tsa>/api/v1/timestamp`, JSON `{"artifactHash":"<base64 SHA-256 of the signature bytes>","hashAlgorithm":"sha256"}`,
   answered with a DER `TimeStampResp` (`Content-Type: application/timestamp-reply`), stored as is in the bundle's
   `timestampVerificationData.rfc3161Timestamps[].signedTimestamp`.
5. The bundle: `application/vnd.dev.sigstore.bundle.v0.3+json` with `verificationMaterial.certificate.rawBytes`
   (the leaf, DER) and `dsseEnvelope`.

Endpoints (actions/toolkit `endpoints.ts`): the instance is chosen by the repository's visibility unless set.
Public repositories use the public-good instance, `https://fulcio.sigstore.dev` and `https://rekor.sigstore.dev`
(no TSA by default in `actions/attest`). Private and internal repositories use GitHub's instance,
`https://fulcio.githubapp.com` and `https://timestamp.githubapp.com` (`fulcio.<tenant>.ghe.com` and
`timestamp.<tenant>.ghe.com` on GHE.com), with no transparency log. Signing with GitHub's instance needs only the
job's token: `attestations: write` is for `POST /repos/{owner}/{repo}/attestations` (actions/toolkit `store.ts`,
storing the bundle in GitHub's attestation API), which vci does not use (its store is git-meta).

Both timestamp authorities answer unauthenticated requests: on 2026-10-16 `timestamp.githubapp.com` and
`timestamp.sigstore.dev` each granted a timestamp for SHA-256("hello") (`Status: Granted`, policy
`1.3.6.1.4.1.57264.2`, hash sha256, accuracy 1 s; signer `O=GitHub, Inc., CN=TSA Timestamping` and
`O=sigstore.dev, CN=sigstore-tsa`). The responses carry no certificates (`certificates [0]` empty: the request did
not ask for them), one SignerInfo identified by issuer and serial, digest SHA-384, signed attributes
`contentType` (id-ct-TSTInfo), `signingTime`, `messageDigest` and `signingCertificateV2`, and `ecdsa-with-SHA384`.
They are the test fixtures in `crates/vci-attest/tests/fixtures/`.

## The trust root

`gh attestation trusted-root` prints JSON Lines: one `application/vnd.dev.sigstore.trustedroot+json;version=0.1`
object for the public-good instance (fetched over TUF from `tuf-repo-cdn.sigstore.dev`) and one for GitHub's
(over TUF from `https://tuf-repo.github.com`, whose `root.json` gh embeds). Each object has
`certificateAuthorities` and `timestampAuthorities` (each `{subject, uri, certChain: {certificates: [{rawBytes}]},
validFor: {start, end?}}`, chain leaf or issuing intermediate first, root last) and, for public good, `tlogs` and
`ctlogs`. On 2026-10-16:

- GitHub: 6 certificate authorities (`uri` `fulcio.githubapp.com`, chain `Fulcio Intermediate l2` ->
  `Fulcio Intermediate l1` -> `Internal Services Root`; the l2 intermediate is renewed yearly, current one valid
  2026-06-12 .. 2027-06-12, entry `validFor.start` 2026-06-12 without end) and 6 timestamp authorities (`uri`
  `timestamp.githubapp.com`, chain `TSA Timestamping` -> `TSA intermediate` -> `Internal Services Root`, also yearly).
- Public good: 2 Fulcio authorities (`sigstore-intermediate` -> `sigstore`), 1 TSA (`sigstore-tsa` ->
  `sigstore-tsa-selfsigned`, valid from 2025-07-04), 2 Rekor logs and 2 CT logs.
- Every certificate in both roots is ECDSA P-384 signed with ecdsa-with-SHA384. The leaves Fulcio issues are the
  signer's own key (P-256 here), signed by the l2 intermediate with SHA-384.

A committed copy goes stale when an intermediate rotates (yearly for GitHub's): certificates issued under a new
intermediate then fail the chain check (fail open: the units run, `vci explain` names the issuer) until the file is
refreshed with `gh attestation trusted-root > .vci/sigstore-trusted-root.json` (or `vci init --oidc`). GitHub
publishes a new intermediate in its TUF repository weeks before it is used (the entries overlap by about a month).

## Certificate identity (Fulcio `docs/oid-info.md`)

Extensions `1.3.6.1.4.1.57264.1.8` to `.24` are DER UTF8Strings (`.1` to `.6`, deprecated, are raw bytes). For
GitHub Actions: `.8` Issuer (`iss`), `.9` Build Signer URI (`server_url + "/" + job_workflow_ref`), `.10` Build
Signer Digest, `.11` Runner Environment, `.12` Source Repository URI (`server_url + "/" + repository`), `.13` Source
Repository Digest (`sha`), `.14` Source Repository Ref (`ref`), `.15` Source Repository Identifier, `.16`/`.17`
owner URI/id, `.18` Build Config URI (`workflow_ref`), `.19` Build Config Digest, `.20` Build Trigger
(`event_name`), `.21` Run Invocation URI (`.../actions/runs/<id>/attempts/<n>`), `.22` Source Repository Visibility,
`.23` Deployment Environment (`environment`), `.24` Token Subject (`sub`). The SAN is the Build Signer URI.

vci matches `[[identity]]` entries of `.vci/identities.toml` against `.8` (issuer), the path of `.12`
(repository), the path of `.9` without `@ref` (workflow file; the short `.github/workflows/x.yml` form only when the
workflow lives in the same repository), `.14` (ref), `.20` (event), `.23` (environment) and `.11` (runner
environment).

## Rust: what to use

- `sigstore` (sigstore-rs 0.14.0, 2026-05-22, "experimental"): async (tokio, reqwest), OpenSSL or aws-lc for
  crypto, about 43 direct dependencies; its bundle verifier follows the public-good Rekor flow and has no RFC 3161
  timestamp verification, which GitHub's instance needs (it has no transparency log).
- `sigstore-verify` 0.15.0 (the newer sigstore-rust workspace, 2026-10-13): covers TSA (`sigstore-tsa`, on `cms` and
  `rustls-webpki`) and trust roots, but splits into about ten `sigstore-*` crates, its crypto backend is `aws-lc-rs`
  (C and assembly built with cmake for every release target), and signing (`sigstore-sign`, `sigstore-fulcio`,
  `sigstore-oidc`) brings an async HTTP stack.
- What vci needs is small and fixed: parse one leaf certificate and check its signature against the trust root's
  issuing intermediate (ECDSA P-384/SHA-384, P-256/SHA-256 also accepted), check one ECDSA signature over the PAE,
  parse one RFC 3161 `TimeStampResp` (CMS SignedData, signed attributes, TSTInfo) and check its signature with the
  trust root's TSA certificate, compare times, and read seven extensions. `p256`, `p384`, `ecdsa` and `sha2` 0.10
  are already in vci's dependency tree (through `ssh-key`); `x509-cert` 0.2 and `cms` 0.2 (RustCrypto, pure Rust,
  `der` 0.7) add the parsing. HTTP (three requests: token, Fulcio, TSA) goes through `curl`, which every GitHub
  runner has, the same way vci already shells out to `git` and `ssh-keygen`; secrets are passed on curl's standard
  input (`-K -`), never on its command line.
- Chosen: the RustCrypto set plus `curl`. Not done (deliberately): Rekor entries and SCTs (vci's trust is the
  identity in the certificate at the time the TSA vouches for, not public auditability), the trust root's own chain
  validation (the committed file is the trust anchor, as `allowed_signers` is), TUF (refreshing is `gh attestation
  trusted-root`, run by a person, reviewed in a pull request).

## The alternative: `actions/attest` and import

The workflow could sign vci's statement with `actions/attest` (custom predicate) and vci would import the bundle.
That needs a JavaScript action step per unit or a batch statement (one subject per unit, which then no longer
verifies per unit), the `attestations: write` permission and GitHub's attestation API (or `skip-write`), and a
second tool between `vci run` and the store. Native signing keeps one step (`vci ci --oidc`), one envelope per unit
as with SSH keys, the same store key layout, and offline verification in vci. The bundles vci writes are standard
v0.3 bundles (the envelope's DSSE fields plus the `sigstore` member) that `gh attestation verify --bundle` or
cosign can read.

## Instance choice in vci

vci signs with GitHub's instance by default for every repository (`--sigstore github`): no public log entry naming
the repository and workflow for every test unit, one Fulcio request per job (the certificate is reused while it has
more than a minute left) and one timestamp per unit. `--sigstore public-good` uses `fulcio.sigstore.dev` and
`timestamp.sigstore.dev` (no Rekor entry either). Verification accepts either, from whatever authorities the
committed trust root lists.

## Confirmed in CI (2026-10-17)

The `demo-oidc` job of `.github/workflows/ci.yml` (pull request 10 of PandelisZ/cryptographically-verifiable-ci-runner,
run 38991254498, a public repository, `ubuntu-latest`) ran `vci run --oidc` with only `permissions: id-token: write`:

- `fulcio.githubapp.com` issued certificates for a public repository's token (audience `sigstore`), valid exactly 10
  minutes, issuer `O=GitHub, Inc., CN=Fulcio Intermediate l2`, empty subject, SAN the Build Signer URI
  (`https://github.com/<repo>/.github/workflows/ci.yml@refs/pull/10/merge`), code-signing EKU, and extensions `.8`,
  `.9`, `.11`, `.12`, `.14`, `.20`, `.21` with the values listed above. `timestamp.githubapp.com` timestamped every
  signature. No `attestations: write`, no GitHub API call.
- 21 units (pytest, Go, Cargo, Rails, RSpec) were signed in about 0.1 s each (one Fulcio request for the job, one
  timestamp per unit), and `vci plan --base-ref HEAD` skipped all 21 on those attestations (`attested by
  github-actions-oidc-pr (oidc repo:... workflow:.github/workflows/ci.yml ref:refs/pull/10/merge
  event:pull_request)`); `vci verify` of one exported envelope printed `VALID` with the timestamp authority and the
  run URL. That envelope is the fixture `crates/vci-attest/tests/fixtures/keyless/github-pr10-envelope.json`,
  verified in the tests against the trust root of 2026-10-16.

