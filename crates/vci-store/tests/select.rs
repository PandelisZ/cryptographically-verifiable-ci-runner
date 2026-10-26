//! Store selection: precedence, validation, warnings, and keeping secrets
//! out of every message.

use std::sync::Arc;
use std::time::Duration;

use vci_store::select::{
    self, ENV_CONNECT_TIMEOUT, ENV_NAMESPACE, ENV_STORE, ENV_STORE_URL, ENV_TIMEOUT, Secret,
    Selection, Source, StoreSettings, redact, resolve,
};
use vci_store::{
    AttestationStore, BackendFactory, FailedStore, MissingBackend, OpenContext, StoreError,
};

/// An environment holding exactly `vars`.
fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |k| {
        vars.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| (*v).to_owned())
    }
}

/// A `vci.toml` read for its `[store]` alone.
#[derive(serde::Deserialize)]
struct OnlyStore {
    store: StoreSettings,
}

/// `[store]` of a `vci.toml`.
fn file(text: &str) -> StoreSettings {
    toml::from_str::<OnlyStore>(text).unwrap().store
}

fn sel(vars: &[(&str, &str)], toml: Option<&str>) -> Result<Selection, StoreError> {
    let f = toml.map(file);
    resolve(&env(vars), f.as_ref())
}

fn config_err(vars: &[(&str, &str)], toml: Option<&str>) -> String {
    match sel(vars, toml) {
        Err(StoreError::Config(m)) => m,
        other => panic!("expected Config for {vars:?} {toml:?}, got {other:?}"),
    }
}

const PG_URL: &str = "postgres://ci:s3cret@db.internal:5432/ci";

#[test]
fn the_environment_wins_over_the_url_scheme_over_vci_toml_over_the_default() {
    let k = |s: &Selection| (s.kind.value.clone(), s.kind.source);
    // The default.
    let s = sel(&[], None).unwrap();
    assert_eq!(k(&s), ("git-meta".into(), Source::Default));
    assert!(s.warnings.is_empty() && s.url.is_none());
    // vci.toml over the default.
    let s = sel(&[], Some("[store]\nbackend = \"sqlite\"")).unwrap();
    assert_eq!(k(&s), ("sqlite".into(), Source::File));
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    // The URL's scheme over vci.toml.
    let s = sel(
        &[(ENV_STORE_URL, "sqlite:/var/cache/vci.sqlite")],
        Some("[store]\nbackend = \"git-meta\""),
    )
    .unwrap();
    assert_eq!(k(&s), ("sqlite".into(), Source::Env(ENV_STORE_URL)));
    assert_eq!(
        s.warnings,
        [
            "vci.toml [store] backend = \"git-meta\" is overridden: using sqlite (from $VCI_STORE_URL)"
        ]
    );
    assert_eq!(
        s.sqlite.path.as_ref().map(|p| p.value.as_str()),
        Some("/var/cache/vci.sqlite")
    );
    // VCI_STORE over vci.toml.
    let s = sel(
        &[(ENV_STORE, "git-meta")],
        Some("[store]\nbackend = \"sqlite\""),
    )
    .unwrap();
    assert_eq!(k(&s), ("git-meta".into(), Source::Env(ENV_STORE)));
    assert_eq!(
        s.warnings,
        ["vci.toml [store] backend = \"sqlite\" is overridden: using git-meta (from $VCI_STORE)"]
    );
    // VCI_STORE over the URL's scheme, when they agree.
    let s = sel(
        &[(ENV_STORE, "postgres"), (ENV_STORE_URL, PG_URL)],
        Some("[store]\nbackend = \"sqlite\""),
    )
    .unwrap();
    assert_eq!(k(&s), ("postgres".into(), Source::Env(ENV_STORE)));
    assert_eq!(s.url.as_ref().unwrap().value.expose(), PG_URL);
    // A URL without a backend's scheme leaves VCI_STORE alone; git-meta
    // ignores it, and the warning shows it without its credentials.
    let s = sel(
        &[
            (ENV_STORE, "git-meta"),
            (ENV_STORE_URL, "https://u:s3cret@host/x"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(k(&s), ("git-meta".into(), Source::Env(ENV_STORE)));
    assert_eq!(s.warnings.len(), 1);
    assert!(
        s.warnings[0].contains("https://***@host/x"),
        "{:?}",
        s.warnings
    );
    assert!(!format!("{s:?}").contains("s3cret"));
    // Aliases.
    for (name, canonical) in [
        ("PostgreSQL", "postgres"),
        ("pg", "postgres"),
        (" postgres ", "postgres"),
    ] {
        let s = sel(&[(ENV_STORE, name), (ENV_STORE_URL, PG_URL)], None).unwrap();
        assert_eq!(s.kind.value, canonical, "{name}");
    }
    assert_eq!(
        sel(&[(ENV_STORE, "sqlite3")], None).unwrap().kind.value,
        "sqlite"
    );
    assert_eq!(
        sel(&[(ENV_STORE, "git_meta")], None).unwrap().kind.value,
        "git-meta"
    );
    // A well-formed unknown name is left to `open`, which lists the backends.
    assert_eq!(
        sel(&[(ENV_STORE, "redis")], None).unwrap().kind.value,
        "redis"
    );
    assert!(config_err(&[(ENV_STORE, "no such!")], None).contains("is not a store backend name"));
    // Only a value shaped like a name is quoted back.
    assert!(config_err(&[(ENV_STORE, "Redis_2")], None).contains("\"Redis_2\""));
    for v in [
        "host=h password=Vst0reKvQ",
        "host=h password = 'Vst0re KvQ'",
    ] {
        let m = config_err(&[(ENV_STORE, v)], None);
        assert!(m.contains("not printed") && !m.contains("Vst0re"), "{m}");
    }
}

#[test]
fn a_url_in_vci_store_is_refused_without_being_printed() {
    let m = config_err(&[(ENV_STORE, PG_URL)], None);
    assert!(m.contains("put the URL in $VCI_STORE_URL"), "{m}");
    for leak in ["s3cret", "ci:", "db.internal", "postgres://"] {
        assert!(!m.contains(leak), "{leak} in {m}");
    }
    assert_eq!(
        select::requested_kind(&env(&[(ENV_STORE, PG_URL)]), None),
        "unknown"
    );
    // In vci.toml too.
    let m = config_err(&[], Some(&format!("[store]\nbackend = \"{PG_URL}\"")));
    assert!(!m.contains("s3cret") && !m.contains("db.internal"), "{m}");
}

#[test]
fn postgres_needs_a_url() {
    for (vars, toml) in [
        (&[(ENV_STORE, "postgres")][..], None),
        (&[][..], Some("[store]\nbackend = \"postgres\"")),
    ] {
        let m = config_err(vars, toml);
        assert!(m.contains("needs $VCI_STORE_URL"), "{m}");
        assert!(m.contains("pull requests from forks"), "{m}");
        assert_eq!(
            select::requested_kind(&env(vars), toml.map(file).as_ref()),
            "postgres"
        );
    }
}

#[test]
fn the_url_scheme_must_agree_with_vci_store() {
    let m = config_err(&[(ENV_STORE, "sqlite"), (ENV_STORE_URL, PG_URL)], None);
    assert_eq!(
        m,
        "$VCI_STORE_URL is a postgres location but the backend is sqlite (from $VCI_STORE)"
    );
    let m = config_err(
        &[(ENV_STORE, "git-meta"), (ENV_STORE_URL, "sqlite:/x.sqlite")],
        None,
    );
    assert!(
        m.contains("is a sqlite location but the backend is git-meta"),
        "{m}"
    );
    // A sqlite store's URL is a path, never another scheme's location (a
    // password in it would be printed as a path).
    let m = config_err(
        &[
            (ENV_STORE, "sqlite"),
            (ENV_STORE_URL, "https://u:s3cret@h/x"),
        ],
        None,
    );
    assert!(!m.contains("s3cret"), "{m}");
    assert!(config_err(&[(ENV_STORE_URL, "sqlite:")], None).contains("needs a path"));
    let s = sel(
        &[(ENV_STORE, "sqlite"), (ENV_STORE_URL, "/abs/v.sqlite")],
        None,
    )
    .unwrap();
    assert_eq!(s.sqlite.path.unwrap().value, "/abs/v.sqlite");
    let s = sel(&[(ENV_STORE_URL, "sqlite:///abs/v.sqlite")], None).unwrap();
    assert_eq!(s.sqlite.path.unwrap().value, "/abs/v.sqlite");
}

#[test]
fn connection_settings_in_vci_toml_are_refused_and_never_echoed() {
    let toml = r#"
[store]
backend = "postgres"
url = "postgres://u:planted1@evil.example/db"

[store.postgres]
schema = "vci"
host = "planted2.evil.example"
user = "planted3"
password = "planted4"
dbname = { name = "planted5" }
url = ["planted6"]
"#;
    let settings = file(toml);
    assert!(!format!("{settings:?}").contains("planted"));
    let m = config_err(&[(ENV_STORE_URL, PG_URL)], Some(toml));
    assert!(
        m.starts_with(
            "vci.toml sets store.url, store.postgres.url, store.postgres.host, store.postgres.user, store.postgres.password, store.postgres.dbname:"
        ),
        "{m}"
    );
    assert!(!m.contains("planted") && !m.contains("evil"), "{m}");
    assert!(settings.check().is_err());
    // Serializing never writes them back.
    let back = serde_json::to_string(&settings).unwrap();
    assert!(
        !back.contains("planted") && !back.contains("password"),
        "{back}"
    );
    // Unknown keys are an error (the base-commit Config denies them too).
    assert!(toml::from_str::<OnlyStore>("[store]\nbackend = \"git-meta\"\nhots = 1").is_err());
    assert!(toml::from_str::<OnlyStore>("[store.postgres]\nport = 5432").is_err());
}

#[test]
fn timeouts_are_seconds_more_than_0_and_at_most_an_hour() {
    let timeout = |vars: &[(&str, &str)], toml: Option<&str>| {
        sel(vars, toml).map(|s| (s.timeout.value, s.timeout.source))
    };
    // The environment: a number of seconds.
    for bad in ["0", "-1", "NaN", "inf", "3601", "5s", "500ms", "seven"] {
        let m = match timeout(&[(ENV_TIMEOUT, bad)], None) {
            Err(StoreError::Config(m)) => m,
            other => panic!("{bad}: {other:?}"),
        };
        assert!(m.starts_with("$VCI_STORE_TIMEOUT_SECS = "), "{m}");
    }
    for (ok, d) in [("7", 7.0), ("0.5", 0.5), ("3600", 3600.0), (" 30 ", 30.0)] {
        assert_eq!(
            timeout(&[(ENV_TIMEOUT, ok)], None).unwrap(),
            (Duration::from_secs_f64(d), Source::Env(ENV_TIMEOUT)),
            "{ok}"
        );
    }
    // vci.toml: a duration.
    for bad in [
        "0",
        "0s",
        "-1s",
        "NaN",
        "3601",
        "3601s",
        "61m",
        "2h",
        "1d",
        "5 parsecs",
    ] {
        let m = match timeout(&[], Some(&format!("[store]\ntimeout = \"{bad}\""))) {
            Err(StoreError::Config(m)) => m,
            other => panic!("{bad}: {other:?}"),
        };
        assert!(m.starts_with("vci.toml [store] timeout = "), "{m}");
    }
    for (ok, d) in [
        ("5s", 5.0),
        ("500ms", 0.5),
        ("7", 7.0),
        ("2m", 120.0),
        ("1h", 3600.0),
    ] {
        assert_eq!(
            timeout(&[], Some(&format!("[store]\ntimeout = \"{ok}\""))).unwrap(),
            (Duration::from_secs_f64(d), Source::File),
            "{ok}"
        );
    }
    // The environment over vci.toml; the default otherwise.
    assert_eq!(
        timeout(&[(ENV_TIMEOUT, "7")], Some("[store]\ntimeout = \"5s\"")).unwrap(),
        (Duration::from_secs(7), Source::Env(ENV_TIMEOUT))
    );
    assert_eq!(
        timeout(&[], None).unwrap(),
        (select::DEFAULT_TIMEOUT, Source::Default)
    );
    // The connect timeout follows the same rules.
    let s = sel(
        &[(ENV_CONNECT_TIMEOUT, "2")],
        Some("[store]\nconnect_timeout = \"9s\""),
    )
    .unwrap();
    assert_eq!(
        (s.connect_timeout.value, s.connect_timeout.source),
        (Duration::from_secs(2), Source::Env(ENV_CONNECT_TIMEOUT))
    );
    assert!(
        config_err(&[(ENV_CONNECT_TIMEOUT, "0")], None)
            .starts_with("$VCI_STORE_CONNECT_TIMEOUT_SECS")
    );
    assert!(
        config_err(&[], Some("[store]\nconnect_timeout = \"1d\""))
            .starts_with("vci.toml [store] connect_timeout")
    );
    assert_eq!(
        sel(&[], None).unwrap().connect_timeout.value,
        select::DEFAULT_CONNECT_TIMEOUT
    );
}

#[test]
fn schema_namespace_pool_and_grace_bounds() {
    let pg = |postgres: &str| {
        sel(
            &[(ENV_STORE_URL, PG_URL)],
            Some(&format!("[store.postgres]\n{postgres}")),
        )
    };
    for ok in ["vci", "_x", "vci_2", &"a".repeat(63)] {
        assert_eq!(
            pg(&format!("schema = \"{ok}\""))
                .unwrap()
                .postgres
                .schema
                .value,
            ok
        );
    }
    for bad in ["", "2x", "Vci", "a-b", "a.b", &"a".repeat(64)] {
        assert!(
            matches!(pg(&format!("schema = \"{bad}\"")), Err(StoreError::Config(m)) if m.contains("lowercase SQL identifier")),
            "{bad}"
        );
    }
    // The namespace: the environment over vci.toml, else the repository id.
    assert_eq!(
        sel(&[(ENV_STORE_URL, PG_URL)], None).unwrap().namespace,
        None
    );
    let s = pg("namespace = \"from-file\"").unwrap();
    assert_eq!(
        s.namespace.map(|n| (n.value, n.source)),
        Some(("from-file".to_owned(), Source::File))
    );
    let s = sel(
        &[
            (ENV_STORE_URL, PG_URL),
            (ENV_NAMESPACE, "acme/mono-repo@1.0:x_y"),
        ],
        Some("[store.postgres]\nnamespace = \"from-file\""),
    )
    .unwrap();
    assert_eq!(
        s.namespace.map(|n| (n.value, n.source)),
        Some((
            "acme/mono-repo@1.0:x_y".to_owned(),
            Source::Env(ENV_NAMESPACE)
        ))
    );
    let long_ok = "n".repeat(128);
    assert!(sel(&[(ENV_STORE_URL, PG_URL), (ENV_NAMESPACE, &long_ok)], None).is_ok());
    for bad in ["a b", "ü", "a;b", &"n".repeat(129)] {
        let m = config_err(&[(ENV_STORE_URL, PG_URL), (ENV_NAMESPACE, bad)], None);
        assert!(m.contains("from $VCI_STORE_NAMESPACE"), "{m}");
    }
    // The pool.
    assert_eq!(
        sel(&[(ENV_STORE_URL, PG_URL)], None)
            .unwrap()
            .postgres
            .pool
            .value,
        select::DEFAULT_POOL
    );
    for ok in [1, 64] {
        assert_eq!(pg(&format!("pool = {ok}")).unwrap().postgres.pool.value, ok);
    }
    for bad in [0, 65] {
        assert!(matches!(
            pg(&format!("pool = {bad}")),
            Err(StoreError::Config(m)) if m.contains("expected 1 to 64")
        ));
    }
    // The manifest grace.
    assert_eq!(
        pg("manifest_grace = \"30d\"")
            .unwrap()
            .postgres
            .manifest_grace
            .value,
        Duration::from_secs(30 * 86_400)
    );
    assert_eq!(
        pg("manifest_grace = \"0s\"")
            .unwrap()
            .postgres
            .manifest_grace
            .value,
        Duration::ZERO
    );
    for bad in ["31d", "bogus", "-1h"] {
        assert!(matches!(
            pg(&format!("manifest_grace = \"{bad}\"")),
            Err(StoreError::Config(m)) if m.contains("at most 30 days")
        ));
    }
}

#[test]
fn a_sqlite_path_in_vci_toml_stays_in_the_git_directory() {
    let path = |p: &str| {
        sel(
            &[],
            Some(&format!(
                "[store]\nbackend = \"sqlite\"\n[store.sqlite]\npath = \"{p}\""
            )),
        )
    };
    for ok in ["vci-store.sqlite", "sub/v.sqlite", "./v.sqlite"] {
        let s = path(ok).unwrap();
        let p = s.sqlite.path.unwrap();
        assert_eq!((p.value.as_str(), p.source), (ok, Source::File));
    }
    for bad in ["../v.sqlite", "/abs/v.sqlite", "a/../b.sqlite", ".."] {
        let m = match path(bad) {
            Err(StoreError::Config(m)) => m,
            other => panic!("{bad}: {other:?}"),
        };
        assert!(
            m.contains("must be relative to the git common directory"),
            "{m}"
        );
    }
    // The default file when nothing names one.
    assert_eq!(
        sel(&[(ENV_STORE, "sqlite")], None).unwrap().sqlite.path,
        None
    );
}

#[test]
fn empty_variables_count_as_unset() {
    let s = sel(
        &[
            (ENV_STORE, ""),
            (ENV_STORE_URL, "  "),
            (ENV_NAMESPACE, ""),
            (ENV_TIMEOUT, ""),
            (ENV_CONNECT_TIMEOUT, " "),
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        (s.kind.value.as_str(), s.kind.source),
        ("git-meta", Source::Default)
    );
    assert!(s.url.is_none() && s.namespace.is_none() && s.warnings.is_empty());
    assert_eq!(s.timeout.source, Source::Default);
    assert_eq!(s.connect_timeout.source, Source::Default);
    // An empty VCI_STORE leaves the choice to vci.toml.
    let s = sel(&[(ENV_STORE, "")], Some("[store]\nbackend = \"sqlite\"")).unwrap();
    assert_eq!(s.kind.source, Source::File);
}

#[test]
fn settings_for_another_backend_are_ignored_with_a_warning() {
    let s = sel(
        &[],
        Some("[store]\n[store.sqlite]\npath = \"x.sqlite\"\n[store.postgres]\npool = 4"),
    )
    .unwrap();
    assert_eq!(
        s.warnings,
        [
            "vci.toml [store.sqlite] is ignored: the store is git-meta (from the default)",
            "vci.toml [store.postgres] is ignored: the store is git-meta (from the default)",
        ]
    );
    assert_eq!(s.sqlite.path, None);
}

#[test]
fn describe_redacts_and_names_sources() {
    let s = sel(
        &[(ENV_STORE_URL, PG_URL), (ENV_TIMEOUT, "9")],
        Some("[store.postgres]\nschema = \"ci_vci\""),
    )
    .unwrap();
    let lines: Vec<(&str, String, String)> = s
        .describe()
        .into_iter()
        .map(|l| (l.name, l.value, l.source.to_string()))
        .collect();
    let get = |n: &str| lines.iter().find(|l| l.0 == n).cloned().unwrap();
    assert_eq!(
        get("backend"),
        ("backend", "postgres".into(), "$VCI_STORE_URL".into())
    );
    assert_eq!(
        get("url"),
        (
            "url",
            "postgres://***@db.internal:5432/ci".into(),
            "$VCI_STORE_URL".into()
        )
    );
    assert_eq!(
        get("schema"),
        ("schema", "ci_vci".into(), "vci.toml [store]".into())
    );
    assert_eq!(
        get("namespace"),
        (
            "namespace",
            "(the repository id)".into(),
            "the default".into()
        )
    );
    assert_eq!(
        get("timeout"),
        ("timeout", "9s".into(), "$VCI_STORE_TIMEOUT_SECS".into())
    );
    assert!(!format!("{lines:?}{s:?}").contains("s3cret"));
    // A sqlite selection lists its path.
    let s = sel(&[(ENV_STORE, "sqlite")], None).unwrap();
    assert!(
        s.describe()
            .iter()
            .any(|l| l.name == "path" && l.value == "<git common dir>/vci-store.sqlite")
    );
    // `for_backend` is every default.
    let d = Selection::for_backend("git-meta");
    assert_eq!(d, sel(&[], None).unwrap());
}

#[test]
fn redact_removes_credentials() {
    for (input, want) in [
        (
            "postgres://u:s3cret@db.internal:5432/ci?sslmode=require",
            "postgres://***@db.internal:5432/ci?sslmode=require",
        ),
        ("postgres://u@db/ci", "postgres://***@db/ci"),
        (
            "postgres://db/ci?password=s3cret&sslmode=require",
            "postgres://db/ci?password=***&sslmode=require",
        ),
        (
            "postgres://db/ci?sslmode=verify-full&sslpassword=s3cret",
            "postgres://db/ci?sslmode=verify-full&sslpassword=***",
        ),
        (
            "postgresql://u:s3cret@db?PASSWORD=s3cret",
            "postgresql://***@db?PASSWORD=***",
        ),
        (
            "host=db user=u password=s3cret dbname=ci",
            "host=db user=u password=*** dbname=ci",
        ),
        ("host=db sslkey=/keys/k.pem", "host=db sslkey=***"),
        ("postgres://db.internal/ci", "postgres://db.internal/ci"),
        // A password holding an unencoded `/`, `?` or `@`.
        (
            "postgres://slash:Sl/sh9Pwq@127.0.0.1:55481/postgres?sslmode=disable",
            "postgres://***@127.0.0.1:55481/postgres?sslmode=disable",
        ),
        (
            "postgres://qmark:Qm?rk9Pwq@127.0.0.1:55481/postgres?sslmode=disable",
            "postgres://***@127.0.0.1:55481/postgres?sslmode=disable",
        ),
        ("postgres://u:a/b@c@db/ci", "postgres://***@db/ci"),
        (
            "postgress://u:Ty/poLeakQ@db.example/x",
            "postgress://***@db.example/x",
        ),
        // A percent-encoded key in the query.
        (
            "postgres://db/ci?pass%77ord=s3cret&x=1",
            "postgres://db/ci?pass%77ord=***&x=1",
        ),
        // libpq spacing and quoting.
        (
            "host=127.0.0.1 user=vci password = Zq9pw0rdX dbname=postgres",
            "host=127.0.0.1 user=vci password = *** dbname=postgres",
        ),
        (
            "host=h password='Sp ce9Pwq' dbname=postgres",
            "host=h password=*** dbname=postgres",
        ),
        (
            r"host=h password='it\'s q' sslmode=disable",
            "host=h password=*** sslmode=disable",
        ),
        ("host=h PASSWORD=Up9 x=1", "host=h PASSWORD=*** x=1"),
        ("host=h password=a://b@c", "host=h password=***"),
        ("host=h password='unterminated x", "host=h password=***"),
        ("git@github.com:o/r.git", "git@github.com:o/r.git"),
        ("/srv/meta.git", "/srv/meta.git"),
    ] {
        assert_eq!(redact(input), want, "{input}");
    }
}

/// A password holding an unencoded `@`, `/` or `?`, in any order, or
/// percent-encoded, or in a libpq string: no fragment of it survives
/// `redact` or `scrub`, not even the `ss@host` the PostgreSQL client would
/// take for the host. The passwords are built of the tokens `Xq7pa`,
/// `Zk9ss`, `Wm8rr` and `Yv3qq`, so a fragment shows as one of them.
#[test]
fn a_password_holding_at_slash_or_question_mark_leaves_no_fragment() {
    const TOKENS: [&str; 4] = ["Xq7pa", "Zk9ss", "Wm8rr", "Yv3qq"];
    let clean = |what: &str, text: &str| {
        for t in TOKENS {
            assert!(!text.contains(t), "{what}: {t} shows in {text:?}");
        }
    };
    // (the string, its redaction, what a client library could print: the
    // password as it reads it, decoded, and the host it would see)
    for (input, want, printed) in [
        // pa@ss: the client reads password `Xq7pa` and host `Zk9ss@db`.
        (
            "postgres://u:Xq7pa@Zk9ss@db/ci",
            "postgres://***@db/ci",
            &["Xq7pa@Zk9ss", "Xq7pa", "Zk9ss@db", "Zk9ss"][..],
        ),
        // p@a@ss
        (
            "postgres://u:Xq7pa@Wm8rr@Zk9ss@db:5432/ci?sslmode=disable",
            "postgres://***@db:5432/ci?sslmode=disable",
            &["Xq7pa@Wm8rr@Zk9ss", "Xq7pa", "Wm8rr@Zk9ss@db", "Zk9ss"],
        ),
        // pa/ss and pa?ss
        (
            "postgres://u:Xq7pa/Zk9ss@db/ci",
            "postgres://***@db/ci",
            &["Xq7pa/Zk9ss"],
        ),
        (
            "postgres://u:Xq7pa?Zk9ss@db/ci?sslmode=require",
            "postgres://***@db/ci?sslmode=require",
            &["Xq7pa?Zk9ss"],
        ),
        // `@` then `/` then `@`: the first `/` is inside the password.
        (
            "postgres://u:Xq7pa@Zk9ss/Wm8rr@Yv3qq@db/ci",
            "postgres://***@db/ci",
            // The client reads host `Zk9ss` and database
            // `Wm8rr@Yv3qq@db/ci`.
            &[
                "Xq7pa",
                "Zk9ss",
                "Wm8rr@Yv3qq@db/ci",
                "Xq7pa@Zk9ss/Wm8rr@Yv3qq",
            ],
        ),
        (
            "postgres://u:Xq7pa?Zk9ss/Wm8rr@db",
            "postgres://***@db",
            &["Xq7pa?Zk9ss/Wm8rr"],
        ),
        // Several hosts.
        (
            "postgres://u:Xq7pa@Zk9ss@h1:1,h2:5432/ci",
            "postgres://***@h1:1,h2:5432/ci",
            &["Xq7pa", "Zk9ss@h1:1,h2:5432", "Zk9ss@h1"],
        ),
        // Percent-encoded forms.
        (
            "postgres://u:Xq7pa%40Zk9ss@db/ci",
            "postgres://***@db/ci",
            &["Xq7pa%40Zk9ss", "Xq7pa@Zk9ss"],
        ),
        (
            "postgres://u:Xq7pa%2FZk9ss%3FWm8rr@db/ci",
            "postgres://***@db/ci",
            &["Xq7pa%2FZk9ss%3FWm8rr", "Xq7pa/Zk9ss?Wm8rr"],
        ),
        (
            "postgres://db/ci?password=Xq7pa%40Zk9ss&x=1",
            "postgres://db/ci?password=***&x=1",
            &["Xq7pa%40Zk9ss", "Xq7pa@Zk9ss"],
        ),
        (
            "postgres://db/ci?pass%77ord=Xq7pa%40Zk9ss",
            "postgres://db/ci?pass%77ord=***",
            &["Xq7pa@Zk9ss"],
        ),
        // A query password holding `@` or `?`.
        (
            "postgres://db/ci?password=Xq7pa@Zk9ss",
            "postgres://***",
            // The client takes `db/ci?password=Xq7pa` for the user and
            // `Zk9ss` for the host.
            &["Xq7pa@Zk9ss", "db/ci?password=Xq7pa", "Zk9ss"],
        ),
        (
            "postgres://db/ci?x=1&password=Xq7pa?Zk9ss&y=2",
            "postgres://db/ci?x=1&password=***&y=2",
            &["Xq7pa?Zk9ss"],
        ),
        (
            "postgres://db/ci?a=b@c&pass%77ord=Xq7pa",
            "postgres://***@c&pass%77ord=***",
            &["Xq7pa"],
        ),
        // libpq strings.
        (
            "host=db user=u password='Xq7pa@Zk9ss' dbname=ci",
            "host=db user=u password=*** dbname=ci",
            &["Xq7pa@Zk9ss"],
        ),
        (
            "host=db password=Xq7pa@Zk9ss dbname=ci",
            "host=db password=*** dbname=ci",
            &["Xq7pa@Zk9ss"],
        ),
        (
            "host=db password = 'Xq7pa@Zk9ss/Wm8rr?Yv3qq' dbname=ci",
            "host=db password = *** dbname=ci",
            &["Xq7pa@Zk9ss/Wm8rr?Yv3qq"],
        ),
    ] {
        let got = redact(input);
        assert_eq!(got, want, "{input}");
        clean(input, &got);
        let s = Secret::new(input);
        let msg = format!("connecting to {input}: {}", printed.join("; "));
        clean(input, &s.scrub(&msg));
        clean(input, &format!("{s:?} {s}"));
        // What a server says about the user stays.
        assert_eq!(
            s.scrub("password authentication failed for user \"u\""),
            "password authentication failed for user \"u\""
        );
    }
}

#[test]
fn secrets_are_scrubbed_from_every_message() {
    // Userinfo, raw and percent-decoded, and the URL itself.
    let s = Secret::new("postgres://ci:p%40ss%2Fw0rd@db.internal/ci");
    let msg = "error connecting to postgres://ci:p%40ss%2Fw0rd@db.internal/ci: \
               password authentication failed (p@ss/w0rd); retried with p@ss/w0rd";
    let scrubbed = s.scrub(msg);
    assert_eq!(
        scrubbed,
        "error connecting to postgres://***@db.internal/ci: \
         password authentication failed (***); retried with ***"
    );
    assert_eq!(format!("{s:?}"), "Secret(postgres://***@db.internal/ci)");
    assert_eq!(s.to_string(), "postgres://***@db.internal/ci");
    assert_eq!(s.expose(), "postgres://ci:p%40ss%2Fw0rd@db.internal/ci");
    // A password in the query string.
    let s = Secret::new("postgres://db/ci?sslmode=require&password=s3cret-q&sslpassword=k3y-pass");
    let m = s.scrub("auth failed for s3cret-q, key k3y-pass, again s3cret-q");
    assert_eq!(m, "auth failed for ***, key ***, again ***");
    // A libpq key=value string.
    let s = Secret::new("host=db user=ci password=s3cret-kv");
    assert_eq!(s.scrub("bad password s3cret-kv"), "bad password ***");
    assert_eq!(s.redacted(), "host=db user=ci password=***");
    // Passwords the URL parser of the client reads differently from a
    // naive one: an unencoded `/` or `?`, libpq spacing and quoting.
    for (url, pw) in [
        ("postgres://slash:Sl/sh9Pwq@h/postgres", "Sl/sh9Pwq"),
        ("postgres://qmark:Qm?rk9Pwq@h/postgres", "Qm?rk9Pwq"),
        ("host=h password = Zq9pw0rdX", "Zq9pw0rdX"),
        ("host=h password='Sp ce9Pwq'", "Sp ce9Pwq"),
    ] {
        let s = Secret::new(url);
        let m = s.scrub(&format!("failed for {pw}; url {url}"));
        assert!(!m.contains(pw), "{m}");
        assert!(!s.redacted().contains(pw), "{}", s.redacted());
    }
    // Passwords under 3 bytes are left (they would scrub ordinary words),
    // but the whole secret still goes.
    let s = Secret::new("postgres://u:ab@h/d");
    assert_eq!(s.scrub("ab postgres://u:ab@h/d"), "ab postgres://***@h/d");
}

#[test]
fn open_finds_the_factory_or_says_what_this_vci_has() {
    struct Fixed;
    impl BackendFactory for Fixed {
        fn kind(&self) -> &'static str {
            "fixed"
        }
        fn summary(&self) -> &'static str {
            "a test store"
        }
        fn open(
            &self,
            _sel: &Selection,
            _cx: &OpenContext,
        ) -> Result<Arc<dyn AttestationStore>, StoreError> {
            Ok(Arc::new(FailedStore::new("fixed", "only a test")))
        }
    }
    let pg = MissingBackend {
        kind: "postgres",
        feature: "postgres",
    };
    let factories: [&dyn BackendFactory; 2] = [&Fixed, &pg];
    let cx = OpenContext {
        repo_root: "/r".into(),
        git_dir: "/r/.git".into(),
        git_common_dir: "/r/.git".into(),
        repo_id: Arc::new(|| Ok("0".repeat(40))),
        jobs: 4,
        command: "plan".into(),
        long_running: false,
    };
    assert!(!format!("{cx:?}").contains("repo_id"));
    let opened = vci_store::open(&factories, &Selection::for_backend("fixed"), &cx).unwrap();
    assert_eq!(opened.kind(), "fixed");
    let err = |kind: &str| match vci_store::open(&factories, &Selection::for_backend(kind), &cx) {
        Err(StoreError::Config(m)) => m,
        Err(e) => panic!("{kind}: {e:?}"),
        Ok(_) => panic!("{kind}: opened"),
    };
    assert_eq!(
        err("redis"),
        "unknown store backend \"redis\" (from the default); this vci has: fixed, postgres"
    );
    assert_eq!(
        err("postgres"),
        "this vci was built without the postgres store (cargo feature `postgres`)"
    );
}

const TURSO: &str = "libsql://ci-acme.turso.io";

#[test]
fn libsql_modes_come_from_the_url_and_the_replica_settings() {
    use vci_store::select::{ENV_REPLICA, ENV_SYNC, ENV_TOKEN, LibsqlMode};
    let k = |s: &Selection| (s.kind.value.clone(), s.kind.source);
    let mode = |s: &Selection| (s.libsql.mode.value, s.libsql.mode.source);
    let path = |s: &Selection| s.libsql.path.as_ref().map(|p| (p.value.clone(), p.source));
    // VCI_STORE=libsql (or turso) alone: the local file, at its default.
    for name in ["libsql", "Turso"] {
        let s = sel(&[(ENV_STORE, name)], None).unwrap();
        assert_eq!(k(&s), ("libsql".into(), Source::Env(ENV_STORE)));
        assert_eq!(mode(&s), (LibsqlMode::Local, Source::Default));
        assert_eq!(path(&s), None);
        assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    }
    // A libsql:// URL selects the store, remote.
    let s = sel(&[(ENV_STORE_URL, TURSO), (ENV_TOKEN, "t0ken")], None).unwrap();
    assert_eq!(k(&s), ("libsql".into(), Source::Env(ENV_STORE_URL)));
    assert_eq!(mode(&s), (LibsqlMode::Remote, Source::Env(ENV_STORE_URL)));
    assert_eq!(s.token.as_ref().unwrap().value.expose(), "t0ken");
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    // An https:// URL alone selects nothing (it may be any service's).
    let s = sel(
        &[(ENV_STORE_URL, "https://ci-acme.turso.io?authToken=s3cret")],
        None,
    )
    .unwrap();
    assert_eq!(k(&s), ("git-meta".into(), Source::Default));
    assert!(!format!("{:?}", s.warnings).contains("s3cret"));
    // ... VCI_STORE=libsql (or vci.toml) says it is a libSQL server.
    let s = sel(
        &[
            (ENV_STORE, "libsql"),
            (ENV_STORE_URL, "https://ci-acme.turso.io"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(mode(&s).0, LibsqlMode::Remote);
    let s = sel(
        &[(ENV_STORE_URL, "http://127.0.0.1:8080")],
        Some("[store]\nbackend = \"libsql\""),
    )
    .unwrap();
    assert_eq!(k(&s), ("libsql".into(), Source::File));
    assert_eq!(mode(&s).0, LibsqlMode::Remote);
    // The replica, asked for three ways; its file from the environment,
    // else vci.toml, else the default.
    let s = sel(&[(ENV_STORE_URL, TURSO), (ENV_SYNC, "replica")], None).unwrap();
    assert_eq!(mode(&s), (LibsqlMode::Replica, Source::Env(ENV_SYNC)));
    assert_eq!(path(&s), None);
    let s = sel(
        &[(ENV_STORE_URL, TURSO), (ENV_REPLICA, "/cache/r.libsql")],
        Some("[store.libsql]\npath = \"other.libsql\""),
    )
    .unwrap();
    assert_eq!(mode(&s), (LibsqlMode::Replica, Source::Env(ENV_REPLICA)));
    assert_eq!(
        path(&s),
        Some(("/cache/r.libsql".into(), Source::Env(ENV_REPLICA)))
    );
    let s = sel(
        &[(ENV_STORE_URL, TURSO)],
        Some("[store.libsql]\nreplica = true\npath = \"r.libsql\""),
    )
    .unwrap();
    assert_eq!(mode(&s), (LibsqlMode::Replica, Source::File));
    assert_eq!(path(&s), Some(("r.libsql".into(), Source::File)));
    // A replica without a server is the local file, with a warning.
    let s = sel(&[(ENV_STORE, "libsql"), (ENV_SYNC, "replica")], None).unwrap();
    assert_eq!(mode(&s).0, LibsqlMode::Local);
    assert_eq!(
        s.warnings,
        [
            "the libsql replica (from $VCI_STORE_SYNC) is ignored: $VCI_STORE_URL names no libsql server (libsql://, https:// or http://), so the store is a local file"
        ]
    );
    // file:<path> is the local file there.
    let s = sel(
        &[(ENV_STORE, "libsql"), (ENV_STORE_URL, "file:/abs/v.libsql")],
        None,
    )
    .unwrap();
    assert_eq!(mode(&s).0, LibsqlMode::Local);
    assert_eq!(
        path(&s),
        Some(("/abs/v.libsql".into(), Source::Env(ENV_STORE_URL)))
    );
    // A token the store does not use is a warning.
    let s = sel(&[(ENV_STORE, "libsql"), (ENV_TOKEN, "t0ken")], None).unwrap();
    assert_eq!(
        s.warnings,
        ["$VCI_STORE_TOKEN is ignored: the store is libsql in local mode (from $VCI_STORE)"]
    );
    let s = sel(&[(ENV_STORE, "sqlite"), (ENV_TOKEN, "t0ken")], None).unwrap();
    assert_eq!(
        s.warnings,
        ["$VCI_STORE_TOKEN is ignored: the store is sqlite (from $VCI_STORE)"]
    );
    // The namespace: the environment, else [store.libsql], else none.
    let s = sel(
        &[(ENV_STORE_URL, TURSO)],
        Some("[store.libsql]\nnamespace = \"acme\""),
    )
    .unwrap();
    assert_eq!(s.namespace.as_ref().unwrap().value, "acme");
    let s = sel(
        &[(ENV_STORE_URL, TURSO), (ENV_NAMESPACE, "env-ns")],
        Some("[store.libsql]\nnamespace = \"acme\""),
    )
    .unwrap();
    assert_eq!(
        s.namespace.as_ref().map(|n| (n.value.as_str(), n.source)),
        Some(("env-ns", Source::Env(ENV_NAMESPACE)))
    );
    // [store.libsql] under another backend is ignored with a warning.
    let s = sel(&[], Some("[store.libsql]\nreplica = true")).unwrap();
    assert_eq!(
        s.warnings,
        ["vci.toml [store.libsql] is ignored: the store is git-meta (from the default)"]
    );
    assert_eq!(mode(&s).0, LibsqlMode::Local);
}

#[test]
fn libsql_locations_that_are_not_its_own_are_refused_unprinted() {
    // Another backend's URL, or a scheme that is no libsql location.
    assert_eq!(
        config_err(&[(ENV_STORE, "libsql"), (ENV_STORE_URL, PG_URL)], None),
        "$VCI_STORE_URL is a postgres location but the backend is libsql (from $VCI_STORE)"
    );
    assert_eq!(
        config_err(&[(ENV_STORE, "postgres"), (ENV_STORE_URL, TURSO)], None),
        "$VCI_STORE_URL is a libsql location but the backend is postgres (from $VCI_STORE)"
    );
    for url in [
        "ws://u:s3cret@db.example",
        "wss://db.example?authToken=s3cret",
        "mysql://u:s3cret@db/x",
    ] {
        let m = config_err(&[(ENV_STORE, "libsql"), (ENV_STORE_URL, url)], None);
        assert!(m.contains("is not a libsql location"), "{url}: {m}");
        assert!(!m.contains("s3cret"), "{url}: {m}");
    }
    assert!(
        config_err(&[(ENV_STORE, "libsql"), (ENV_STORE_URL, "file:")], None)
            .contains("needs a path")
    );
    // A path in vci.toml stays in the git directory.
    for p in ["/etc/x.libsql", "../x.libsql", ""] {
        let m = config_err(
            &[(ENV_STORE, "libsql")],
            Some(&format!("[store.libsql]\npath = {p:?}")),
        );
        assert!(
            m.contains("[store.libsql] path") && m.contains("VCI_STORE_REPLICA"),
            "{p}: {m}"
        );
    }
}

#[test]
fn libsql_tokens_stay_out_of_vci_toml_and_every_message() {
    use vci_store::select::{ENV_TOKEN, NEVER_TO_CHILDREN};
    // vci.toml never holds a server or a token.
    let toml = "[store]\nbackend = \"libsql\"\n[store.libsql]\nurl = \"libsql://planted1.turso.io\"\ntoken = \"planted2\"\nauthToken = \"planted3\"\n";
    let settings = file(toml);
    assert!(!format!("{settings:?}").contains("planted"));
    let m = config_err(&[], Some(toml));
    assert!(
        m.starts_with(
            "vci.toml sets store.libsql.url, store.libsql.token, store.libsql.auth_token:"
        ),
        "{m}"
    );
    assert!(m.contains("$VCI_STORE_TOKEN"), "{m}");
    assert!(!m.contains("planted"), "{m}");
    assert!(toml::from_str::<OnlyStore>("[store.libsql]\nhost = \"x\"").is_err());
    // The token never reaches a child, and is printed as `***`.
    assert!(NEVER_TO_CHILDREN.contains(&ENV_TOKEN));
    assert!(select::ENV_VARS.contains(&ENV_TOKEN));
    let t = Secret::opaque("eyJhbGciOi.s3cret+tok/en=");
    assert_eq!(t.redacted(), "***");
    assert_eq!(format!("{t:?} {t}"), "Secret(***) ***");
    assert_eq!(
        t.scrub("token eyJhbGciOi.s3cret+tok/en= or eyJhbGciOi.s3cret%2Btok%2Fen%3D"),
        "token *** or ***"
    );
    // In a URL: the authToken parameter.
    assert_eq!(
        redact("libsql://ci-acme.turso.io?authToken=s3cret.tok"),
        "libsql://ci-acme.turso.io?authToken=***"
    );
    let u = Secret::new("https://ci-acme.turso.io/?tls=1&authToken=s3cret.tok");
    assert_eq!(
        u.scrub("401 for s3cret.tok at https://ci-acme.turso.io/?tls=1&authToken=s3cret.tok"),
        "401 for *** at https://ci-acme.turso.io/?tls=1&authToken=***"
    );
    // describe() says whether a token is set, never what it is.
    let s = sel(
        &[
            (
                ENV_STORE_URL,
                "libsql://ci-acme.turso.io?authToken=s3cret-u",
            ),
            (ENV_TOKEN, "s3cret-e"),
        ],
        None,
    )
    .unwrap();
    let lines: Vec<(&str, String, String)> = s
        .describe()
        .into_iter()
        .map(|l| (l.name, l.value, l.source.to_string()))
        .collect();
    let get = |n: &str| lines.iter().find(|l| l.0 == n).cloned().unwrap();
    assert_eq!(
        get("url").1,
        "libsql://ci-acme.turso.io?authToken=***",
        "{lines:?}"
    );
    assert_eq!(
        get("mode"),
        ("mode", "remote".into(), "$VCI_STORE_URL".into())
    );
    assert_eq!(
        get("token"),
        ("token", "(set)".into(), "$VCI_STORE_TOKEN".into())
    );
    assert_eq!(get("namespace").1, "(the repository id)");
    assert!(!format!("{lines:?} {s:?}").contains("s3cret"), "{lines:?}");
    // A token only in the URL is said to be there.
    let s = sel(
        &[(
            ENV_STORE_URL,
            "libsql://ci-acme.turso.io?authToken=s3cret-u",
        )],
        None,
    )
    .unwrap();
    let token = s
        .describe()
        .into_iter()
        .find(|l| l.name == "token")
        .unwrap();
    assert_eq!(
        (token.value.as_str(), token.source),
        ("(the URL's authToken)", Source::Env(ENV_STORE_URL))
    );
    let s = sel(&[(ENV_STORE, "libsql")], None).unwrap();
    assert!(
        s.describe()
            .iter()
            .any(|l| l.name == "path" && l.value == "<git common dir>/vci-store.libsql")
    );
}
