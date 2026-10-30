//! `.vci/identities.toml`: which CI identities (claims of the OIDC token,
//! as Fulcio wrote them into the certificate) sign as which principal.
//!
//! ```toml
//! [[identity]]
//! principal = "github-actions"
//! issuer = "https://token.actions.githubusercontent.com"
//! repository = "owner/name"
//! workflow = ".github/workflows/ci.yml"   # glob
//! ref = "refs/heads/main"                 # glob
//! event = "push"                          # optional, glob
//! environment = "vci-attest"              # optional, glob
//! runner_environment = "github-hosted"    # optional, glob
//! ```

use serde::Deserialize;
use sha2::Digest as _;

use super::x509::{Cert, fulcio};

/// `.vci/identities.toml`, read from the base commit.
pub const IDENTITIES_FILE: &str = ".vci/identities.toml";

/// One `[[identity]]` entry. Every field present must match.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRule {
    /// The name policy lists use (`no_skip_refs_except`, `attest_on_any_ref`).
    pub principal: String,
    /// OIDC issuer, exactly (e.g. `https://token.actions.githubusercontent.com`).
    pub issuer: String,
    /// `owner/name`, exactly (ASCII case-insensitive, as GitHub's names are).
    pub repository: String,
    /// The workflow file the signing job is defined in (glob): the path in
    /// the repository (`.github/workflows/ci.yml`), or `owner/name/<path>`
    /// (needed for a reusable workflow of another repository).
    pub workflow: String,
    /// The git ref the run was for (glob), e.g. `refs/heads/main`.
    #[serde(rename = "ref")]
    pub ref_: String,
    /// Event that triggered the run (glob), e.g. `push`.
    #[serde(default)]
    pub event: Option<String>,
    /// The job's GitHub Environment (glob).
    #[serde(default)]
    pub environment: Option<String>,
    /// `github-hosted` or `self-hosted` (glob).
    #[serde(default)]
    pub runner_environment: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentitiesFile {
    #[serde(default)]
    identity: Vec<IdentityRule>,
}

/// The parsed `.vci/identities.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identities {
    pub rules: Vec<IdentityRule>,
}

/// The identity of a signer: from a certificate's Fulcio extensions (when
/// verifying) or from the job's token claims (when signing).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertIdentity {
    pub issuer: String,
    /// `owner/name`.
    pub repository: String,
    /// `owner/name/<path>` of the job's workflow file (no `@ref`).
    pub workflow: String,
    /// The ref the workflow file was taken at (after `@`).
    pub workflow_ref: String,
    /// The run's git ref.
    pub ref_: String,
    pub event: String,
    pub environment: Option<String>,
    pub runner_environment: Option<String>,
    /// Commit (informational).
    pub sha: Option<String>,
    /// Run URL (informational).
    pub run: Option<String>,
}

impl Identities {
    pub fn parse(text: &str) -> Result<Self, String> {
        let f: IdentitiesFile = toml::from_str(text).map_err(|e| e.to_string())?;
        for (i, r) in f.identity.iter().enumerate() {
            let at = format!("[[identity]] #{}", i + 1);
            if r.principal.is_empty() || r.principal.chars().any(char::is_whitespace) {
                return Err(format!(
                    "{at}: principal {:?} must be non-empty without whitespace",
                    r.principal
                ));
            }
            if !r.issuer.starts_with("https://") {
                return Err(format!("{at}: issuer {:?} is not an https URL", r.issuer));
            }
            let parts: Vec<&str> = r.repository.split('/').collect();
            if parts.len() != 2 || parts.iter().any(|p| p.is_empty() || p.contains('*')) {
                return Err(format!(
                    "{at}: repository {:?} is not owner/name (no globs)",
                    r.repository
                ));
            }
            if r.workflow.is_empty() || r.ref_.is_empty() {
                return Err(format!("{at}: workflow and ref must be non-empty"));
            }
        }
        Ok(Self { rules: f.identity })
    }

    /// The first rule `id` matches.
    pub fn matching(&self, id: &CertIdentity) -> Option<&IdentityRule> {
        self.rules.iter().find(|r| r.matches(id))
    }

    /// Every principal a rule matching `id` names (in file order, deduplicated).
    pub fn principals(&self, id: &CertIdentity) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in self.rules.iter().filter(|r| r.matches(id)) {
            if !out.contains(&r.principal) {
                out.push(r.principal.clone());
            }
        }
        out
    }
}

impl IdentityRule {
    pub fn matches(&self, id: &CertIdentity) -> bool {
        if self.issuer != id.issuer || !self.repository.eq_ignore_ascii_case(&id.repository) {
            return false;
        }
        // The short form (path in the repository) only for a workflow file
        // of the repository itself.
        let short = id
            .workflow
            .get(..id.repository.len())
            .filter(|p| p.eq_ignore_ascii_case(&id.repository))
            .and_then(|_| id.workflow[id.repository.len()..].strip_prefix('/'));
        let workflow_ok = glob_match(&self.workflow, &id.workflow)
            || short.is_some_and(|s| glob_match(&self.workflow, s));
        let opt = |pat: &Option<String>, v: Option<&str>| match pat {
            None => true,
            Some(p) => v.is_some_and(|v| glob_match(p, v)),
        };
        workflow_ok
            && glob_match(&self.ref_, &id.ref_)
            && opt(&self.event, Some(&id.event))
            && opt(&self.environment, id.environment.as_deref())
            && opt(&self.runner_environment, id.runner_environment.as_deref())
    }
}

/// The host and path of an https URL (`https://github.com/a/b` ->
/// (`github.com`, `a/b`)).
fn url_host_path(u: &str) -> Option<(&str, &str)> {
    let (host, path) = u.strip_prefix("https://")?.split_once('/')?;
    Some((host, path.trim_end_matches('/')))
}

/// The host a certificate's repository and workflow URIs must be on for
/// this issuer: `github.com` for GitHub's issuer
/// (`https://token.actions.githubusercontent.com`, with or without an
/// enterprise's path), `<name>.ghe.com` for GHE.com's
/// (`https://token.actions.<name>.ghe.com`), and otherwise the issuer's own
/// host (GitHub Enterprise Server's `https://<host>/_services/token`,
/// GitLab). The issuer itself is matched exactly by the `[[identity]]`, so
/// a CA in the trust root cannot certify a same-named repository on another
/// host for it.
fn expected_host(issuer: &str) -> Option<String> {
    let rest = issuer.strip_prefix("https://")?;
    let host = rest.split_once('/').map_or(rest, |(h, _)| h);
    if host.is_empty() {
        return None;
    }
    Some(match host {
        "token.actions.githubusercontent.com" => "github.com".to_owned(),
        h => match h.strip_prefix("token.actions.") {
            Some(ghe) if ghe.ends_with(".ghe.com") => ghe.to_owned(),
            _ => h.to_owned(),
        },
    })
}

/// The path of `uri` (the certificate's `what`) after checking that it is
/// an https URL on `host`.
fn path_on_host<'a>(uri: &'a str, what: &str, host: &str) -> Result<&'a str, String> {
    let (h, p) = url_host_path(uri)
        .ok_or_else(|| format!("{what} {uri:?} is not an https URL with a path"))?;
    if !h.eq_ignore_ascii_case(host) {
        return Err(format!(
            "{what} {uri:?} is not on {host}, the host of the certificate's OIDC issuer"
        ));
    }
    Ok(p)
}

impl CertIdentity {
    /// From a Fulcio certificate's extensions.
    pub(crate) fn from_cert(c: &Cert) -> Result<Self, String> {
        let get = |oid| c.fulcio_string(oid);
        let issuer = get(fulcio::ISSUER)
            .or_else(|| get(fulcio::ISSUER_V1))
            .ok_or("the certificate has no OIDC issuer extension")?;
        let signer = get(fulcio::BUILD_SIGNER_URI)
            .ok_or("the certificate has no Build Signer URI (not a CI workflow identity)")?;
        let repo_uri = get(fulcio::SOURCE_REPOSITORY_URI)
            .ok_or("the certificate has no Source Repository URI")?;
        let host = expected_host(&issuer)
            .ok_or_else(|| format!("OIDC issuer {issuer:?} is not an https URL"))?;
        let repository = path_on_host(&repo_uri, "Source Repository URI", &host)?.to_owned();
        let signer_path = path_on_host(&signer, "Build Signer URI", &host)?;
        let (workflow, workflow_ref) = signer_path
            .split_once('@')
            .map(|(a, b)| (a.to_owned(), b.to_owned()))
            .unwrap_or_else(|| (signer_path.to_owned(), String::new()));
        Ok(Self {
            issuer,
            repository,
            workflow,
            workflow_ref,
            ref_: get(fulcio::SOURCE_REPOSITORY_REF).unwrap_or_default(),
            event: get(fulcio::BUILD_TRIGGER).unwrap_or_default(),
            environment: get(fulcio::DEPLOYMENT_ENVIRONMENT).filter(|s| !s.is_empty()),
            runner_environment: get(fulcio::RUNNER_ENVIRONMENT).filter(|s| !s.is_empty()),
            sha: get(fulcio::SOURCE_REPOSITORY_DIGEST),
            run: get(fulcio::RUN_INVOCATION_URI),
        })
    }

    /// From a GitHub Actions token's claims (`iss`, `repository`,
    /// `job_workflow_ref`, `ref`, `event_name`, `environment`,
    /// `runner_environment`).
    pub fn from_claims(c: &serde_json::Value) -> Result<Self, String> {
        let s = |k: &str| c.get(k).and_then(|v| v.as_str()).map(str::to_owned);
        let need = |k: &str| s(k).ok_or_else(|| format!("the token has no {k} claim"));
        let jwr = need("job_workflow_ref")?;
        let (workflow, workflow_ref) = jwr
            .split_once('@')
            .map(|(a, b)| (a.to_owned(), b.to_owned()))
            .unwrap_or_else(|| (jwr.clone(), String::new()));
        Ok(Self {
            issuer: need("iss")?,
            repository: need("repository")?,
            workflow,
            workflow_ref,
            ref_: need("ref")?,
            event: need("event_name")?,
            environment: s("environment").filter(|e| !e.is_empty()),
            runner_environment: s("runner_environment").filter(|e| !e.is_empty()),
            sha: s("sha"),
            run: None,
        })
    }

    /// `repo:<r> workflow:<w> ref:<ref> event:<e>[ environment:<env>]`, the
    /// workflow path short when it is in the repository.
    pub fn describe(&self) -> String {
        let wf = self
            .workflow
            .strip_prefix(&format!("{}/", self.repository))
            .unwrap_or(&self.workflow);
        let mut s = format!(
            "repo:{} workflow:{wf} ref:{} event:{}",
            self.repository, self.ref_, self.event
        );
        if let Some(e) = &self.environment {
            s.push_str(&format!(" environment:{e}"));
        }
        s
    }

    /// The signer id in store keys: the first 16 hex characters of SHA-256
    /// over `issuer \n repository \n workflow \n ref \n event \n environment
    /// \n runner_environment` (repository and workflow lowercased, absent
    /// claims empty), with the ref's pull request number or merge queue
    /// entry folded to `*` ([`signer_ref`]).
    ///
    /// Every claim an `[[identity]]` can match is in it, so two runs that
    /// identities.toml can trust differently (a pull request and main of one
    /// workflow file) never share a store key and never replace each other's
    /// attestations; runs of one ref (all pull requests count as one, as
    /// they would with one pull request key) supersede each other.
    pub fn signer_id(&self) -> String {
        let d = sha2::Sha256::digest(
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}",
                self.issuer,
                self.repository.to_ascii_lowercase(),
                self.workflow.to_ascii_lowercase(),
                signer_ref(&self.ref_),
                self.event,
                self.environment.as_deref().unwrap_or(""),
                self.runner_environment.as_deref().unwrap_or(""),
            )
            .as_bytes(),
        );
        d.iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
}

/// The ref as the signer id sees it: `refs/pull/<n>/...` ->
/// `refs/pull/*/...`, and a merge queue entry
/// `refs/heads/gh-readonly-queue/<base>/pr-<n>-<sha>` ->
/// `refs/heads/gh-readonly-queue/<base>/*`, so each pull request or queue
/// entry does not get a store slot of its own.
fn signer_ref(r: &str) -> String {
    if let Some(rest) = r.strip_prefix("refs/pull/")
        && let Some((n, tail)) = rest.split_once('/')
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
    {
        return format!("refs/pull/*/{tail}");
    }
    if r.starts_with("refs/heads/gh-readonly-queue/")
        && let Some((base, entry)) = r.rsplit_once('/')
        && entry.starts_with("pr-")
    {
        return format!("{base}/*");
    }
    r.to_owned()
}

/// Glob match with vci's semantics (`policy.no_skip_refs`): `*` and `?` do
/// not cross `/`, `**` does (`**/` also matches no segment).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p.starts_with(b"**") {
            let rest = &p[2..];
            if rest.first() == Some(&b'/') && rec(&rest[1..], t) {
                return true;
            }
            return (0..=t.len()).any(|i| rec(rest, &t[i..]));
        }
        match p[0] {
            b'*' => {
                for i in 0..=t.len() {
                    if rec(&p[1..], &t[i..]) {
                        return true;
                    }
                    if i < t.len() && t[i] == b'/' {
                        break;
                    }
                }
                false
            }
            b'?' => !t.is_empty() && t[0] != b'/' && rec(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0] == c && rec(&p[1..], &t[1..]),
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GHA: &str = "https://token.actions.githubusercontent.com";

    fn id() -> CertIdentity {
        CertIdentity {
            issuer: GHA.into(),
            repository: "ComposalAI/vex".into(),
            workflow: "ComposalAI/vex/.github/workflows/vci.yml".into(),
            workflow_ref: "refs/heads/master".into(),
            ref_: "refs/heads/master".into(),
            event: "push".into(),
            environment: None,
            runner_environment: Some("github-hosted".into()),
            sha: None,
            run: None,
        }
    }

    fn rules(t: &str) -> Identities {
        Identities::parse(t).unwrap()
    }

    const BASE: &str = r#"
[[identity]]
principal = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
repository = "ComposalAI/vex"
workflow = ".github/workflows/vci.yml"
ref = "refs/heads/master"
event = "push"
"#;

    #[test]
    fn exact_identity_matches() {
        let ids = rules(BASE);
        assert_eq!(ids.matching(&id()).unwrap().principal, "github-actions");
        assert_eq!(ids.principals(&id()), ["github-actions"]);
    }

    #[test]
    fn each_claim_must_match() {
        let ids = rules(BASE);
        let mut i = id();
        i.ref_ = "refs/heads/feature".into();
        assert!(ids.matching(&i).is_none(), "ref");
        let mut i = id();
        i.event = "pull_request".into();
        assert!(ids.matching(&i).is_none(), "event");
        let mut i = id();
        i.repository = "ComposalAI/other".into();
        i.workflow = "ComposalAI/other/.github/workflows/vci.yml".into();
        assert!(ids.matching(&i).is_none(), "repository");
        let mut i = id();
        i.workflow = "ComposalAI/vex/.github/workflows/other.yml".into();
        assert!(ids.matching(&i).is_none(), "workflow");
        let mut i = id();
        i.issuer = "https://token.actions.githubusercontent.com.evil".into();
        assert!(ids.matching(&i).is_none(), "issuer");
    }

    #[test]
    fn repository_is_case_insensitive_and_globs_work() {
        let ids = rules(
            r#"
[[identity]]
principal = "pr"
issuer = "https://token.actions.githubusercontent.com"
repository = "composalai/VEX"
workflow = ".github/workflows/*.yml"
ref = "refs/pull/*/merge"
event = "pull_request*"
"#,
        );
        let mut i = id();
        i.ref_ = "refs/pull/12/merge".into();
        i.event = "pull_request".into();
        assert_eq!(ids.principals(&i), ["pr"]);
        // `*` does not cross `/`.
        i.ref_ = "refs/pull/12/head/merge".into();
        assert!(ids.matching(&i).is_none());
        i.ref_ = "refs/pull/12/merge".into();
        i.workflow = "ComposalAI/vex/.github/workflows/sub/x.yml".into();
        assert!(ids.matching(&i).is_none());
    }

    #[test]
    fn a_reusable_workflow_of_another_repository_needs_the_long_form() {
        let mut i = id();
        i.workflow = "evil/repo/.github/workflows/vci.yml".into();
        assert!(rules(BASE).matching(&i).is_none());
        let long = BASE.replace(
            "workflow = \".github/workflows/vci.yml\"",
            "workflow = \"evil/repo/.github/workflows/vci.yml\"",
        );
        assert!(rules(&long).matching(&i).is_some());
    }

    #[test]
    fn optional_claims_must_be_present_when_required() {
        let with_env = BASE.replace("event = \"push\"", "environment = \"vci-attest\"");
        let ids = rules(&with_env);
        assert!(ids.matching(&id()).is_none(), "no environment claim");
        let mut i = id();
        i.environment = Some("vci-attest".into());
        assert!(ids.matching(&i).is_some());
        let hosted = BASE.replace("event = \"push\"", "runner_environment = \"github-hosted\"");
        assert!(rules(&hosted).matching(&id()).is_some());
        let mut i = id();
        i.runner_environment = Some("self-hosted".into());
        assert!(rules(&hosted).matching(&i).is_none());
    }

    #[test]
    fn invalid_files_are_errors() {
        for bad in [
            "[[identity]]\nprincipal = \"a b\"\nissuer = \"https://x\"\nrepository = \"a/b\"\nworkflow = \"w\"\nref = \"r\"\n",
            "[[identity]]\nprincipal = \"a\"\nissuer = \"http://x\"\nrepository = \"a/b\"\nworkflow = \"w\"\nref = \"r\"\n",
            "[[identity]]\nprincipal = \"a\"\nissuer = \"https://x\"\nrepository = \"a\"\nworkflow = \"w\"\nref = \"r\"\n",
            "[[identity]]\nprincipal = \"a\"\nissuer = \"https://x\"\nrepository = \"a/*\"\nworkflow = \"w\"\nref = \"r\"\n",
            "[[identity]]\nprincipal = \"a\"\nissuer = \"https://x\"\nrepository = \"a/b\"\nworkflow = \"w\"\n",
            "[[identity]]\nprincipal = \"a\"\nissuer = \"https://x\"\nrepository = \"a/b\"\nworkflow = \"w\"\nref = \"r\"\nrefs = \"typo\"\n",
            "[[identities]]\n",
        ] {
            assert!(Identities::parse(bad).is_err(), "{bad}");
        }
        assert!(Identities::parse("").unwrap().rules.is_empty());
    }

    #[test]
    fn claims_and_description() {
        let c = serde_json::json!({
            "iss": GHA,
            "repository": "ComposalAI/vex",
            "job_workflow_ref": "ComposalAI/vex/.github/workflows/vci.yml@refs/heads/master",
            "ref": "refs/heads/master",
            "event_name": "push",
            "runner_environment": "github-hosted",
            "sha": "abc",
        });
        let i = CertIdentity::from_claims(&c).unwrap();
        assert_eq!(
            i,
            CertIdentity {
                sha: Some("abc".into()),
                ..id()
            }
        );
        assert_eq!(
            i.describe(),
            "repo:ComposalAI/vex workflow:.github/workflows/vci.yml ref:refs/heads/master event:push"
        );
        let mut c2 = c.clone();
        c2.as_object_mut().unwrap().remove("job_workflow_ref");
        assert!(CertIdentity::from_claims(&c2).is_err());
    }

    #[test]
    fn signer_id_separates_what_a_rule_can_tell_apart_and_is_16_hex() {
        let a = id();
        assert_eq!(a.signer_id().len(), 16);
        assert!(
            a.signer_id()
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Stable across runs (sha, run URL, workflow file's ref).
        let mut same = id();
        same.sha = Some("abc".into());
        same.run = Some("https://github.com/x/y/actions/runs/2/attempts/1".into());
        same.workflow_ref = "refs/heads/other".into();
        assert_eq!(a.signer_id(), same.signer_id());
        // A pull request run of the same workflow file is another signer, so
        // it cannot replace main's attestation of the same inputs.
        let mut pr = id();
        pr.ref_ = "refs/pull/1/merge".into();
        pr.event = "pull_request".into();
        assert_ne!(a.signer_id(), pr.signer_id());
        // Every claim a rule can match separates signers.
        let mut differ: Vec<CertIdentity> = Vec::new();
        let mut c = id();
        c.workflow = "ComposalAI/vex/.github/workflows/other.yml".into();
        differ.push(c);
        let mut c = id();
        c.ref_ = "refs/heads/feature".into();
        differ.push(c);
        let mut c = id();
        c.event = "workflow_dispatch".into();
        differ.push(c);
        let mut c = id();
        c.environment = Some("vci-attest".into());
        differ.push(c);
        let mut c = id();
        c.runner_environment = Some("self-hosted".into());
        differ.push(c);
        let mut c = id();
        c.issuer = "https://token.actions.acme.ghe.com".into();
        differ.push(c);
        for c in &differ {
            assert_ne!(a.signer_id(), c.signer_id(), "{c:?}");
        }
        // Pull requests share one signer id, as do merge queue entries.
        let mut pr2 = pr.clone();
        pr2.ref_ = "refs/pull/2/merge".into();
        assert_eq!(pr.signer_id(), pr2.signer_id());
        let q = |r: &str| CertIdentity {
            ref_: r.into(),
            event: "merge_group".into(),
            ..id()
        };
        assert_eq!(
            q("refs/heads/gh-readonly-queue/main/pr-1-aaaa").signer_id(),
            q("refs/heads/gh-readonly-queue/main/pr-2-bbbb").signer_id()
        );
        assert_ne!(
            q("refs/heads/gh-readonly-queue/main/pr-1-aaaa").signer_id(),
            q("refs/heads/gh-readonly-queue/release/1/pr-1-aaaa").signer_id()
        );
    }

    #[test]
    fn signer_ref_folds_pull_requests_and_queue_entries_only() {
        assert_eq!(signer_ref("refs/pull/12/merge"), "refs/pull/*/merge");
        assert_eq!(signer_ref("refs/pull/12/head"), "refs/pull/*/head");
        assert_eq!(
            signer_ref("refs/heads/gh-readonly-queue/release/1/pr-7-abc"),
            "refs/heads/gh-readonly-queue/release/1/*"
        );
        for kept in [
            "refs/heads/main",
            "refs/pull/x/merge",
            "refs/pull//merge",
            "refs/pull/12",
            "refs/heads/gh-readonly-queue/main/other",
            "refs/heads/pull/12/merge",
        ] {
            assert_eq!(signer_ref(kept), kept);
        }
    }

    #[test]
    fn certificate_uris_must_be_on_the_issuers_host() {
        assert_eq!(expected_host(GHA).as_deref(), Some("github.com"));
        assert_eq!(
            expected_host("https://token.actions.githubusercontent.com/acme").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            expected_host("https://token.actions.acme.ghe.com").as_deref(),
            Some("acme.ghe.com")
        );
        assert_eq!(
            expected_host("https://ghes.example/_services/token").as_deref(),
            Some("ghes.example")
        );
        assert_eq!(
            expected_host("https://gitlab.com").as_deref(),
            Some("gitlab.com")
        );
        assert_eq!(expected_host("http://x"), None);
        assert_eq!(expected_host("https://"), None);

        let gh = "github.com";
        assert_eq!(
            path_on_host("https://github.com/acme/app", "Source Repository URI", gh),
            Ok("acme/app")
        );
        assert_eq!(
            path_on_host("https://GitHub.com/acme/app/", "Source Repository URI", gh),
            Ok("acme/app")
        );
        for bad in [
            "https://evil.example/acme/app",
            "https://github.com.evil.example/acme/app",
            "https://evil.example/github.com/acme/app",
            "http://github.com/acme/app",
            "https://github.com",
            "github.com/acme/app",
        ] {
            assert!(
                path_on_host(bad, "Source Repository URI", gh).is_err(),
                "{bad}"
            );
        }
        let e = path_on_host("https://evil.example/acme/app", "Build Signer URI", gh).unwrap_err();
        assert_eq!(
            e,
            "Build Signer URI \"https://evil.example/acme/app\" is not on github.com, the host of the certificate's OIDC issuer"
        );
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_match("refs/heads/*", "refs/heads/main"));
        assert!(!glob_match("refs/heads/*", "refs/heads/a/b"));
        assert!(glob_match("refs/heads/**", "refs/heads/a/b"));
        assert!(glob_match("**", "anything/at/all"));
        assert!(glob_match("v?", "v1") && !glob_match("v?", "v/"));
    }

    /// The two constructions of a signer id agree field for field: the
    /// one `vci run` writes into the store key's signer segment from the
    /// OIDC token's claims ([`CertIdentity::from_claims`]), and the one
    /// the plan compares it with, built from the Fulcio certificate's
    /// extensions ([`CertIdentity::from_cert`]). The fixture leaf
    /// `tests/fixtures/keyless/leaf-environment.der` (made by `make.sh`)
    /// carries a deployment environment (OID 1.3.6.1.4.1.57264.1.23,
    /// `production`) and a runner environment (`self-hosted`), which both
    /// constructions fold into the id; a job without the environment, or
    /// on another runner environment, is another signer.
    #[test]
    fn from_cert_and_from_claims_give_one_signer_id_with_an_environment() {
        let der = include_bytes!("../../tests/fixtures/keyless/leaf-environment.der");
        let cert = Cert::parse(der).unwrap();
        let from_cert = CertIdentity::from_cert(&cert).unwrap();
        assert_eq!(from_cert.environment.as_deref(), Some("production"));
        assert_eq!(from_cert.runner_environment.as_deref(), Some("self-hosted"));
        let claims = |environment: Option<&str>, runner: &str| {
            let mut c = serde_json::json!({
                "iss": GHA,
                "repository": "ComposalAI/vex",
                "job_workflow_ref": "ComposalAI/vex/.github/workflows/deploy.yml@refs/heads/master",
                "ref": "refs/heads/master",
                "event_name": "push",
                "runner_environment": runner,
                "sha": "0123456789abcdef0123456789abcdef01234567",
            });
            if let Some(e) = environment {
                c["environment"] = serde_json::Value::String(e.to_owned());
            }
            CertIdentity::from_claims(&c).unwrap()
        };
        let from_claims = claims(Some("production"), "self-hosted");
        assert_eq!(from_cert.issuer, from_claims.issuer);
        assert_eq!(from_cert.repository, from_claims.repository);
        assert_eq!(from_cert.workflow, from_claims.workflow);
        assert_eq!(from_cert.workflow_ref, from_claims.workflow_ref);
        assert_eq!(from_cert.ref_, from_claims.ref_);
        assert_eq!(from_cert.event, from_claims.event);
        assert_eq!(from_cert.environment, from_claims.environment);
        assert_eq!(from_cert.runner_environment, from_claims.runner_environment);
        assert_eq!(from_cert.signer_id(), from_claims.signer_id());
        assert_ne!(
            from_cert.signer_id(),
            claims(None, "self-hosted").signer_id(),
            "the environment is part of the id"
        );
        assert_ne!(
            from_cert.signer_id(),
            claims(Some("production"), "github-hosted").signer_id(),
            "so is the runner environment"
        );
        // An empty environment claim is no environment, as an empty
        // extension is none.
        assert_eq!(
            claims(Some(""), "self-hosted").signer_id(),
            claims(None, "self-hosted").signer_id()
        );
    }
}
