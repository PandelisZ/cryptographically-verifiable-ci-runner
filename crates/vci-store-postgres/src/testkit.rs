//! A temporary PostgreSQL for tests (test-only by contract; hidden from the
//! docs). It is always compiled, with no feature, so this crate's
//! integration tests and vci-cli's can use it without a self
//! dev-dependency, and it uses nothing beyond `std` and `postgres`.
//!
//! Step D2 of the store plan writes it: a server from
//! `VCI_TEST_POSTGRES_URL`, else a throwaway cluster from `initdb`, else a
//! skip (a panic under `VCI_TEST_POSTGRES=require`). Until then no server
//! is ever available.

/// Whether a PostgreSQL server is available to this test process. Always
/// `false` until step D2 writes the helper.
pub fn available() -> bool {
    false
}
