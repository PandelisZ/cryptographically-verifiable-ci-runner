//! A PostgreSQL server for this crate's tests: everything comes from
//! [`vci_store_postgres::testkit`], which uses `VCI_TEST_POSTGRES_URL` when
//! it is set and otherwise starts a throwaway cluster with `initdb` (or
//! skips the test, or panics under `VCI_TEST_POSTGRES=require`). Each
//! [`PgDb`] has its own schema `vci_t_<pid>_<n>`, plus the roles and
//! databases it made; dropping it drops them all.

#![allow(unused_imports)]

pub use vci_store_postgres::testkit::{
    PgDb, ROLE_PASSWORD, cx, cx_for, pg, selection, with_database, with_user,
};
