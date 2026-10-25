//! # `vci-store-sqlite`: attestations in one SQLite file
//!
//! A [`vci_store::AttestationStore`] kept in a local SQLite file, by default
//! `<git common dir>/vci-store.sqlite`, shared by the repository's linked
//! worktrees. It has no exchange: `vci fetch` and `vci push` say the store
//! is local. `docs/STORE-BACKENDS.md` (section 16) is its design.
//!
//! This is the skeleton of step A1 of the store plan: the factory is
//! registered, and opening the store says that it is not implemented yet.
//! Step B implements it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use vci_store::select::Selection;
use vci_store::{AttestationStore, BackendFactory, OpenContext, StoreError};

/// Opens the SQLite store (`VCI_STORE=sqlite`, or `VCI_STORE_URL=sqlite:<path>`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteFactory;

impl BackendFactory for SqliteFactory {
    fn kind(&self) -> &'static str {
        "sqlite"
    }

    fn summary(&self) -> &'static str {
        "a local SQLite file (default <git common dir>/vci-store.sqlite)"
    }

    fn open(
        &self,
        _sel: &Selection,
        _cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        Err(StoreError::Config(
            "the sqlite store is not implemented yet".into(),
        ))
    }
}

/// The SQLite store. Empty until step B of the store plan implements it.
#[derive(Debug)]
pub struct SqliteStore;

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
        let f = SqliteFactory;
        assert_eq!(f.kind(), "sqlite");
        match f.open(&Selection::for_backend("sqlite"), &cx) {
            Err(StoreError::Config(m)) => assert_eq!(m, "the sqlite store is not implemented yet"),
            Err(e) => panic!("expected Config, got {e:?}"),
            Ok(_) => panic!("expected Config, got a store"),
        }
    }
}
