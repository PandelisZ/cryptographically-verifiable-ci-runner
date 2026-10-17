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

/// The path of a URL (`https://github.com/a/b` -> `a/b`).
fn url_path(u: &str) -> Option<&str> {
    let rest = u.split_once("://")?.1;
    Some(rest.split_once('/')?.1.trim_end_matches('/'))
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
        let repository = url_path(&repo_uri)
            .ok_or_else(|| format!("Source Repository URI {repo_uri:?} has no path"))?
            .to_owned();
        let signer_path =
            url_path(&signer).ok_or_else(|| format!("Build Signer URI {signer:?} has no path"))?;
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
    /// over `issuer \n repository \n workflow` (stable across runs and refs
    /// of one workflow file).
    pub fn signer_id(&self) -> String {
        let d = sha2::Sha256::digest(
            format!(
                "{}\n{}\n{}",
                self.issuer,
                self.repository.to_ascii_lowercase(),
                self.workflow.to_ascii_lowercase()
            )
            .as_bytes(),
        );
        d.iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
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
    fn signer_id_is_stable_across_refs_and_16_hex() {
        let a = id();
        let mut b = id();
        b.ref_ = "refs/pull/1/merge".into();
        b.event = "pull_request".into();
        assert_eq!(a.signer_id(), b.signer_id());
        assert_eq!(a.signer_id().len(), 16);
        assert!(
            a.signer_id()
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let mut c = id();
        c.workflow = "ComposalAI/vex/.github/workflows/other.yml".into();
        assert_ne!(a.signer_id(), c.signer_id());
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_match("refs/heads/*", "refs/heads/main"));
        assert!(!glob_match("refs/heads/*", "refs/heads/a/b"));
        assert!(glob_match("refs/heads/**", "refs/heads/a/b"));
        assert!(glob_match("**", "anything/at/all"));
        assert!(glob_match("v?", "v1") && !glob_match("v?", "v/"));
    }
}
