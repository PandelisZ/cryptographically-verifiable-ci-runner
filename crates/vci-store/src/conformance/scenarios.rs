//! The conformance scenarios (STORE-BACKENDS.md section 14). Each builds
//! its own world from the factory it is given and checks one rule every
//! backend keeps.
//!
//! Step A1 of the plan only declares them, so that backends can enable the
//! `conformance` feature and the macro expands; their bodies are written in
//! step D. Until then each says so on stderr and passes.

use super::StoreFactory;

/// Say that scenario `name` has no body yet (step D writes it).
fn not_written_yet(f: &dyn StoreFactory, name: &str) {
    eprintln!("{name} ({}): not written yet (step D)", f.name());
}

/// c01: 5 KB and 200 KB values, tabs and newlines, read back byte for byte; an
/// unknown unit lists empty; an identical re-put writes nothing; new bytes
/// replace.
pub fn c01_round_trip_exact_bytes(f: &dyn StoreFactory) {
    not_written_yet(f, "c01_round_trip_exact_bytes");
}

/// c02: Status, listings, manifests, count and hints on an absent store create
/// no file or schema.
pub fn c02_reading_creates_nothing(f: &dyn StoreFactory) {
    not_written_yet(f, "c02_reading_creates_nothing");
}

/// c03: `Invalid` with `what` = `signer_id`, `storage_key`, `test_key`,
/// `target`, `envelope` (empty, non-UTF-8), `input root` and `manifest`; the
/// count stays 0.
pub fn c03_invalid_arguments_write_nothing(f: &dyn StoreFactory) {
    not_written_yet(f, "c03_invalid_arguments_write_nothing");
}

/// c04: A newer hint replaces the slot; an unhinted put keeps the key; another
/// signer has its own slot.
pub fn c04_same_inputs_replace_whatever_the_hint(f: &dyn StoreFactory) {
    not_written_yet(f, "c04_same_inputs_replace_whatever_the_hint");
}

/// c05: Listings are `Unread`; keys whose bytewise and en_US orders differ
/// (`aa:ff.-` against `aaf0:1.-`) come back bytewise; the same listing twice;
/// `list_all` by (target, key).
pub fn c05_listing_is_key_only_and_byte_ordered(f: &dyn StoreFactory) {
    not_written_yet(f, "c05_listing_is_key_only_and_byte_ordered");
}

/// c06: Duplicates, unknown ids, the `project` target and cargo `#` ids; the
/// batch equals listing one by one.
pub fn c06_list_units_answers_each_id_in_order(f: &dyn StoreFactory) {
    not_written_yet(f, "c06_list_units_answers_each_id_in_order");
}

/// c07: A key removed after the listing reads as `GONE`, the others as `Read`,
/// and the call is `Ok`.
pub fn c07_read_values_reports_each_record(f: &dyn StoreFactory) {
    not_written_yet(f, "c07_read_values_reports_each_record");
}

/// c08: The `put_manifest` flag; `manifest`, `manifests` (order and `None`) and
/// `manifest_roots`; `manifest_decoded` through a base; a missing base reads as
/// not in the store; `remove_manifests` validates every root first.
pub fn c08_manifests_and_bases(f: &dyn StoreFactory) {
    not_written_yet(f, "c08_manifests_and_bases");
}

/// c09: The caller's bytes come back; a second remove returns nothing; the
/// count follows.
pub fn c09_remove_returns_what_existed(f: &dyn StoreFactory) {
    not_written_yet(f, "c09_remove_returns_what_existed");
}

/// c10: A removal reaches other peers (through `sync` for an exchange, at once
/// otherwise), and a key written again is live again.
pub fn c10_deletion_reaches_peers_and_reattestation_wins(f: &dyn StoreFactory) {
    not_written_yet(f, "c10_deletion_reaches_peers_and_reattestation_wins");
}

/// c11: After a sync both peers hold both peers' writes.
pub fn c11_union_after_sync(f: &dyn StoreFactory) {
    not_written_yet(f, "c11_union_after_sync");
}

/// c12: 8 threads x 5 puts through one handle, and across peers: every write is
/// there.
pub fn c12_concurrent_writers_lose_nothing(f: &dyn StoreFactory) {
    not_written_yet(f, "c12_concurrent_writers_lose_nothing");
}

/// c13: The same key written by two peers ends with one value both agree on.
pub fn c13_same_key_from_two_peers_converges(f: &dyn StoreFactory) {
    not_written_yet(f, "c13_same_key_from_two_peers_converges");
}

/// c14: With an exchange: `NothingStored`, then `Pushed`, then `UpToDate`, and
/// `found`; without one, `exchange()` is `None`.
pub fn c14_fetch_and_push_say_what_happened(f: &dyn StoreFactory) {
    not_written_yet(f, "c14_fetch_and_push_say_what_happened");
}

/// c15: The chosen values and their manifests read after one prefetch; a store
/// that is not lazy returns `Hydration::default()`.
pub fn c15_prefetch_makes_chosen_values_readable(f: &dyn StoreFactory) {
    not_written_yet(f, "c15_prefetch_makes_chosen_values_readable");
}

/// c16: The first failure within the connect timeout plus 1 s, 40 more calls
/// under 2 s, hints empty, never a panic.
pub fn c16_an_unreachable_store_fails_fast(f: &dyn StoreFactory) {
    not_written_yet(f, "c16_an_unreachable_store_fails_fast");
}

/// c17: Reads work; writes are `Err` (`Denied` or `Unavailable`), never a
/// panic.
pub fn c17_read_only_store_reads(f: &dyn StoreFactory) {
    not_written_yet(f, "c17_read_only_store_reads");
}

/// c18: With `keeps_hints`: remember then recall, set then get; otherwise
/// empty.
pub fn c18_hints_round_trip(f: &dyn StoreFactory) {
    not_written_yet(f, "c18_hints_round_trip");
}

/// c19: Immediate batches: visible inside the batch; deferred ones: visible
/// after `finish`, to another peer too.
pub fn c19_batch_writes_are_durable(f: &dyn StoreFactory) {
    not_written_yet(f, "c19_batch_writes_are_durable");
}

/// c20: 1,200 units listed, prefetched and read.
pub fn c20_many_values(f: &dyn StoreFactory) {
    not_written_yet(f, "c20_many_values");
}

/// c21: Six handles writing first at once (schema-creation races).
pub fn c21_concurrent_first_writes_create_the_store_once(f: &dyn StoreFactory) {
    not_written_yet(f, "c21_concurrent_first_writes_create_the_store_once");
}

/// c22: Through `World::make_unreadable`: only that entry is unreadable.
pub fn c22_one_unreadable_value_hides_only_itself(f: &dyn StoreFactory) {
    not_written_yet(f, "c22_one_unreadable_value_hides_only_itself");
}

/// c23: Through `World::inject_raw`: listings and the count skip keys without
/// vci's shape.
pub fn c23_foreign_keys_are_ignored(f: &dyn StoreFactory) {
    not_written_yet(f, "c23_foreign_keys_are_ignored");
}

/// c24: `Debug`, `location`, errors and fetch output of the unreachable handle
/// never contain `World::secret`.
pub fn c24_errors_never_show_secrets(f: &dyn StoreFactory) {
    not_written_yet(f, "c24_errors_never_show_secrets");
}

/// c25: Puts, removals and `put_manifest` after a prefetch are seen at once,
/// including a manifest the prefetch found absent.
pub fn c25_reads_see_this_handles_writes_after_a_prefetch(f: &dyn StoreFactory) {
    not_written_yet(f, "c25_reads_see_this_handles_writes_after_a_prefetch");
}

/// c26: `Absent` or `Ready`, then `Ready` after a write; manifests are not
/// counted.
pub fn c26_status_and_count(f: &dyn StoreFactory) {
    not_written_yet(f, "c26_status_and_count");
}

/// c27: The backend's `read_units` and the default (list, then read) agree.
pub fn c27_read_units_matches_list_then_read(f: &dyn StoreFactory) {
    not_written_yet(f, "c27_read_units_matches_list_then_read");
}

/// c28: Referenced roots are kept; an `Unknown` payload makes the answer empty.
pub fn c28_orphan_manifests_keeps_what_is_referenced_or_unknown(f: &dyn StoreFactory) {
    not_written_yet(
        f,
        "c28_orphan_manifests_keeps_what_is_referenced_or_unknown",
    );
}

/// c29: On a shared store: referenced, base-of-another and within-grace roots
/// are kept and not counted.
pub fn c29_remove_manifests_keeps_referenced_and_recent(f: &dyn StoreFactory) {
    not_written_yet(f, "c29_remove_manifests_keeps_referenced_and_recent");
}

/// c30: Through `World::failing_batches`: `finish` is `Err` and the batch's
/// writes are not visible.
pub fn c30_failed_batch_reports_and_loses(f: &dyn StoreFactory) {
    not_written_yet(f, "c30_failed_batch_reports_and_loses");
}

/// c31: `FailedStore`: every read and write is `Unavailable`, hints are empty.
pub fn c31_failed_store_fails_every_call(f: &dyn StoreFactory) {
    not_written_yet(f, "c31_failed_store_fails_every_call");
}

/// c32: 16 threads of `list_units`, `manifest` and `read_values` while one
/// writer puts and removes: no `Err`, no torn value.
pub fn c32_concurrent_readers_and_writer(f: &dyn StoreFactory) {
    not_written_yet(f, "c32_concurrent_readers_and_writer");
}

/// c33: Stored keys and targets equal `key::attestation_key_hinted` and
/// `key::target_label`.
pub fn c33_key_and_target_parity(f: &dyn StoreFactory) {
    not_written_yet(f, "c33_key_and_target_parity");
}

/// c34: `put(NewAttestation::copy_of(..))` into a second world keeps keys,
/// targets and bytes.
pub fn c34_copy_keeps_keys_and_targets(f: &dyn StoreFactory) {
    not_written_yet(f, "c34_copy_keeps_keys_and_targets");
}
