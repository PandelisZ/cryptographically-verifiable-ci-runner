//! A PostgreSQL server for this crate's tests (interim: the store plan's
//! step D replaces it with `vci_store_postgres::testkit`).
//!
//! [`pg`] uses the server `VCI_TEST_POSTGRES_URL` names (a role there must
//! be allowed to create schemas, roles and databases), and skips the test
//! with a message when it is not set (or panics under
//! `VCI_TEST_POSTGRES=require`). Each [`PgDb`] has its own schema
//! `vci_t_<pid>_<n>`, plus the roles and databases it made; dropping it
//! drops them all.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use postgres::{Client, NoTls, Row};
use vci_store::OpenContext;
use vci_store::select::{Secret, Selection, Source, Sourced};
use vci_store_postgres::PgStore;

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// The password of every role a test creates.
pub const ROLE_PASSWORD: &str = "vci-test-role-pw";

/// One test's corner of the server.
pub struct PgDb {
    /// The server, as the tests' admin role, with an `sslmode`.
    pub url: String,
    /// This test's schema (not created until a store writes).
    pub schema: String,
    admin: Mutex<Client>,
    roles: Mutex<Vec<String>>,
    databases: Mutex<Vec<String>>,
}

/// The server, or `None` (the test is skipped) when none is configured.
pub fn pg() -> Option<PgDb> {
    let url = match std::env::var("VCI_TEST_POSTGRES_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_owned(),
        _ => {
            if std::env::var("VCI_TEST_POSTGRES").as_deref() == Ok("require") {
                panic!("VCI_TEST_POSTGRES=require, but VCI_TEST_POSTGRES_URL is not set");
            }
            eprintln!(
                "skipping: no PostgreSQL server (set VCI_TEST_POSTGRES_URL to one where this role may create schemas)"
            );
            return None;
        }
    };
    let admin = Client::connect(&url, NoTls)
        .unwrap_or_else(|e| panic!("VCI_TEST_POSTGRES_URL: cannot connect: {e}"));
    let schema = format!(
        "vci_t_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    );
    Some(PgDb {
        url: with_sslmode(&url),
        schema,
        admin: Mutex::new(admin),
        roles: Mutex::new(Vec::new()),
        databases: Mutex::new(Vec::new()),
    })
}

/// `url` with `sslmode=prefer` unless it names one (a CI service container
/// has no TLS, and vci requires it for hosts other than this machine).
fn with_sslmode(url: &str) -> String {
    if url.contains("sslmode=") {
        url.to_owned()
    } else if url.contains('?') {
        format!("{url}&sslmode=prefer")
    } else {
        format!("{url}?sslmode=prefer")
    }
}

/// `url` with this user and password.
pub fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a postgres:// URL");
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{scheme}://{user}:{password}@{host}{tail}")
}

/// `url` naming this database.
pub fn with_database(url: &str, db: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a postgres:// URL");
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let query = tail.split_once('?').map_or("", |(_, q)| q);
    if query.is_empty() {
        format!("{scheme}://{authority}/{db}")
    } else {
        format!("{scheme}://{authority}/{db}?{query}")
    }
}

/// An open context for tests: command `test`, a fixed repository id.
pub fn cx() -> OpenContext {
    cx_for("test", false)
}

/// An open context naming `command`.
pub fn cx_for(command: &str, long_running: bool) -> OpenContext {
    OpenContext {
        repo_root: "/nonexistent".into(),
        git_dir: "/nonexistent/.git".into(),
        git_common_dir: "/nonexistent/.git".into(),
        repo_id: Arc::new(|| Ok("0123456789abcdef0123456789abcdef01234567".to_owned())),
        jobs: 4,
        command: command.to_owned(),
        long_running,
    }
}

/// A selection of the postgres store at `url`, in `schema`, namespace `ns`.
pub fn selection(url: &str, schema: &str, ns: &str) -> Selection {
    let mut s = Selection::for_backend("postgres");
    s.url = Some(Sourced {
        value: Secret::new(url),
        source: Source::Env("VCI_STORE_URL"),
    });
    s.postgres.schema = Sourced {
        value: schema.to_owned(),
        source: Source::File,
    };
    s.namespace = Some(Sourced {
        value: ns.to_owned(),
        source: Source::Env("VCI_STORE_NAMESPACE"),
    });
    s
}

impl PgDb {
    fn admin(&self) -> std::sync::MutexGuard<'_, Client> {
        self.admin.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This test's selection (namespace `test`).
    pub fn selection(&self) -> Selection {
        selection(&self.url, &self.schema, "test")
    }

    /// A new handle on this test's store.
    pub fn open(&self) -> PgStore {
        self.open_with(|_| {})
    }

    /// A new handle on this test's store, with its selection changed by `f`.
    pub fn open_with(&self, f: impl FnOnce(&mut Selection)) -> PgStore {
        let mut s = self.selection();
        f(&mut s);
        PgStore::open(&s, &cx()).expect("open the store")
    }

    /// A new handle as another role (`url` from [`PgDb::role`]).
    pub fn open_as(&self, url: &str) -> PgStore {
        PgStore::open(&selection(url, &self.schema, "test"), &cx()).expect("open the store")
    }

    /// Run SQL as the admin role (`{schema}` names this test's schema).
    pub fn sql(&self, sql: &str) {
        let sql = sql.replace("{schema}", &self.schema);
        self.admin()
            .batch_execute(&sql)
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    }

    /// Query as the admin role (`{schema}` names this test's schema).
    pub fn query(&self, sql: &str) -> Vec<Row> {
        let sql = sql.replace("{schema}", &self.schema);
        self.admin()
            .query(sql.as_str(), &[])
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"))
    }

    /// One `bigint` (or `count(*)`) answer.
    pub fn count(&self, sql: &str) -> i64 {
        self.query(sql)[0].get(0)
    }

    /// Whether this test's schema exists.
    pub fn schema_exists(&self) -> bool {
        self.count("SELECT count(*) FROM pg_namespace WHERE nspname = '{schema}'") == 1
    }

    /// A login role `<schema>_<suffix>` granted `grants` (`{role}` and
    /// `{schema}` are filled in); its URL.
    pub fn role(&self, suffix: &str, grants: &str) -> String {
        let role = format!("{}_{suffix}", self.schema);
        self.sql(&format!(
            "CREATE ROLE \"{role}\" LOGIN PASSWORD '{ROLE_PASSWORD}'"
        ));
        self.roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(role.clone());
        if !grants.is_empty() {
            self.sql(&grants.replace("{role}", &format!("\"{role}\"")));
        }
        with_user(&self.url, &role, ROLE_PASSWORD)
    }

    /// A database `<schema>_<suffix>` made with `options`; its URL, or the
    /// server's error.
    pub fn database(&self, suffix: &str, options: &str) -> Result<String, String> {
        let name = format!("{}_{suffix}", self.schema);
        self.admin()
            .batch_execute(&format!("CREATE DATABASE \"{name}\" {options}"))
            .map_err(|e| format!("{e:?}"))?;
        self.databases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(name.clone());
        Ok(with_database(&self.url, &name))
    }
}

impl Drop for PgDb {
    fn drop(&mut self) {
        // Let the handles' connections close first.
        std::thread::sleep(Duration::from_millis(20));
        let mut admin = self.admin();
        let _ = admin.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
            self.schema
        ));
        for d in self
            .databases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = admin.batch_execute(&format!("DROP DATABASE IF EXISTS \"{d}\" WITH (FORCE)"));
        }
        for r in self
            .roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = admin.batch_execute(&format!(
                "DROP OWNED BY \"{r}\" CASCADE; DROP ROLE IF EXISTS \"{r}\""
            ));
        }
    }
}
