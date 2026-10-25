//! # `vci-store-postgres`: attestations on a shared PostgreSQL server
//!
//! A [`vci_store::AttestationStore`] kept in tables of one PostgreSQL schema
//! (default `vci`), one namespace per repository. Writes are visible to
//! every reader at once, so it has no exchange, and `vci ci` without
//! `--push` stores nothing (the publication gate). The connection string
//! comes only from `VCI_STORE_URL`. `docs/STORE-BACKENDS.md` (section 17) is
//! its design.
//!
//! This is the skeleton of step A1 of the store plan: the factory is
//! registered, and opening the store says that it is not implemented yet.
//! Step C implements it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use vci_store::select::Selection;
use vci_store::{AttestationStore, BackendFactory, OpenContext, StoreError};

#[doc(hidden)]
pub mod testkit;

/// Opens the PostgreSQL store (`VCI_STORE=postgres`, or a `postgres://`
/// `VCI_STORE_URL`).
#[derive(Debug, Clone, Copy, Default)]
pub struct PostgresFactory;

impl BackendFactory for PostgresFactory {
    fn kind(&self) -> &'static str {
        "postgres"
    }

    fn summary(&self) -> &'static str {
        "a shared PostgreSQL server (VCI_STORE_URL), one namespace per repository"
    }

    fn open(
        &self,
        _sel: &Selection,
        _cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        Err(StoreError::Config(
            "the postgres store is not implemented yet".into(),
        ))
    }
}

/// The PostgreSQL store. Empty until step C of the store plan implements it.
#[derive(Debug)]
pub struct PgStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_returns_config_not_implemented_yet() {
        let cx = OpenContext {
            repo_root: "/nonexistent".into(),
            git_dir: "/nonexistent/.git".into(),
            git_common_dir: "/nonexistent/.git".into(),
            repo_id: Arc::new(|| Err("no repository".to_owned())),
            jobs: 1,
            command: "test".to_owned(),
            long_running: false,
        };
        let f = PostgresFactory;
        assert_eq!(f.kind(), "postgres");
        assert!(!testkit::available());
        match f.open(&Selection::for_backend("postgres"), &cx) {
            Err(StoreError::Config(m)) => {
                assert_eq!(m, "the postgres store is not implemented yet")
            }
            Err(e) => panic!("expected Config, got {e:?}"),
            Ok(_) => panic!("expected Config, got a store"),
        }
    }
}
