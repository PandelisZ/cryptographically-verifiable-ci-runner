//! The per-handle cache of the remote mode: the same rules as the
//! PostgreSQL store's (`docs/STORE-BACKENDS.md` section 17, "Reads and the
//! per-handle cache"; this file is `vci-store-postgres`'s `cache.rs`).
//!
//! [`AttestationStore::prefetch`](vci_store::AttestationStore::prefetch)
//! fills it with listings by test key, attestation values by key and input
//! manifests by root (absent ones too), so the plan's thousands of
//! listings, its batch read and its manifest reads cost no request.
//!
//! * It is a snapshot taken at prefetch time that always reflects this
//!   handle's own writes: a put updates its unit's listing and value, a
//!   removal drops the key, a `put_manifest` replaces a cached root (an
//!   absent one included). Other writers' changes are missed until the next
//!   prefetch of the units, which lists them again from the server (and
//!   drops the values of keys no longer listed); missing them only makes
//!   units run. Values and stored manifests are not read again while
//!   cached (a key names one attestation, a root one manifest); a manifest
//!   cached as absent is asked for again by the next prefetch of it.
//! * An attestation value leaves the cache when `read_values` reads it (the
//!   caller keeps it). Listings and manifests stay: bases are shared and
//!   read again.
//! * It holds at most [`CAP`] bytes; above that nothing more is added, and
//!   reads go to the server.

use std::collections::HashMap;

use vci_store::{StoredEnvelope, StoredManifest, key};

/// The most bytes the cache holds.
pub(crate) const CAP: usize = 256 << 20;

/// One listed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listed {
    pub(crate) key: String,
    pub(crate) target: String,
}

impl Listed {
    fn size(&self) -> usize {
        self.key.len() + self.target.len() + 48
    }
}

/// A cached attestation value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// The stored bytes.
    Bytes(Vec<u8>),
    /// Why it cannot be read ([`vci_store::GONE`], an unknown encoding).
    Unreadable(String),
}

impl Value {
    fn size(&self) -> usize {
        match self {
            Value::Bytes(b) => b.len() + 32,
            Value::Unreadable(s) => s.len() + 32,
        }
    }

    /// Record it on `e` ([`StoredEnvelope::set_value`] or `set_error`).
    pub(crate) fn apply(self, e: &mut StoredEnvelope) {
        match self {
            Value::Bytes(b) => e.set_value(b),
            Value::Unreadable(why) => e.set_error(why),
        }
    }
}

/// A cached input manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Manifest {
    /// Not stored.
    Absent,
    /// The stored bytes.
    Bytes(Vec<u8>),
    /// Stored but unreadable, and why.
    Unreadable(String),
}

impl Manifest {
    fn size(&self) -> usize {
        match self {
            Manifest::Absent => 32,
            Manifest::Bytes(b) => b.len() + 32,
            Manifest::Unreadable(s) => s.len() + 32,
        }
    }

    /// As [`vci_store::AttestationStore::manifest`] answers it.
    pub(crate) fn to_stored(&self, root: &str) -> Option<StoredManifest> {
        match self {
            Manifest::Absent => None,
            Manifest::Bytes(b) => Some(StoredManifest::with_bytes(root, b.clone())),
            Manifest::Unreadable(why) => Some(StoredManifest::with_error(root, why.clone())),
        }
    }
}

/// See the module docs.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    listings: HashMap<String, Vec<Listed>>,
    values: HashMap<String, Value>,
    manifests: HashMap<String, Manifest>,
    bytes: usize,
}

fn same_slot(key: &str, e: &StoredEnvelope) -> bool {
    key::parse_key(key).is_some_and(|(tk, signer, sk)| {
        tk == e.test_key && signer == e.signer && sk == e.storage_key
    })
}

impl Cache {
    /// Bytes held.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    fn fits(&self, more: usize) -> bool {
        self.bytes.saturating_add(more) <= CAP
    }

    /// The cached listing of a unit, as unread entries.
    pub(crate) fn listing(&self, test_key: &str) -> Option<Vec<StoredEnvelope>> {
        self.listings.get(test_key).map(|l| {
            l.iter()
                .filter_map(|x| StoredEnvelope::from_key(x.target.clone(), &x.key))
                .collect()
        })
    }

    /// The cached keys of a unit, in listing order.
    #[cfg(test)]
    pub(crate) fn listed_keys(&self, test_key: &str) -> Option<Vec<String>> {
        self.listings
            .get(test_key)
            .map(|l| l.iter().map(|x| x.key.clone()).collect())
    }

    /// Cache a unit's listing (sorted by key), unless the cache is full.
    pub(crate) fn set_listing(&mut self, test_key: String, mut listed: Vec<Listed>) {
        listed.sort_by(|a, b| a.key.cmp(&b.key));
        let size: usize = listed.iter().map(Listed::size).sum::<usize>() + test_key.len();
        let old: usize = self
            .listings
            .get(&test_key)
            .map(|l| l.iter().map(Listed::size).sum::<usize>() + test_key.len())
            .unwrap_or(0);
        if !self.fits(size.saturating_sub(old)) {
            // A listing that cannot be brought up to date is not kept.
            if self.listings.remove(&test_key).is_some() {
                self.bytes = self.bytes.saturating_sub(old);
            }
            return;
        }
        self.bytes = self.bytes - old + size;
        self.listings.insert(test_key, listed);
    }

    /// A unit's listing as the server has it now: the values of keys it no
    /// longer lists leave the cache, and the listing replaces the cached
    /// one.
    pub(crate) fn refresh_listing(&mut self, test_key: String, listed: Vec<Listed>) {
        if let Some(old) = self.listings.get(&test_key) {
            let gone: Vec<String> = old
                .iter()
                .filter(|o| !listed.iter().any(|n| n.key == o.key))
                .map(|o| o.key.clone())
                .collect();
            for k in gone {
                self.take_value(&k);
            }
        }
        self.set_listing(test_key, listed);
    }

    /// Whether a value is cached for `key`.
    pub(crate) fn has_value(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// The cached value of `key`, taken out of the cache.
    pub(crate) fn take_value(&mut self, key: &str) -> Option<Value> {
        let v = self.values.remove(key)?;
        self.bytes = self.bytes.saturating_sub(v.size() + key.len());
        Some(v)
    }

    /// The cached value of `key`, left in the cache.
    pub(crate) fn value(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }

    /// Cache a value, unless the cache is full.
    pub(crate) fn set_value(&mut self, key: String, v: Value) {
        self.take_value(&key);
        let size = v.size() + key.len();
        if self.fits(size) {
            self.bytes += size;
            self.values.insert(key, v);
        }
    }

    /// Whether `root` is cached as stored (readable or not): a prefetch
    /// asks the server again about a root cached as absent.
    pub(crate) fn has_stored_manifest(&self, root: &str) -> bool {
        self.manifests
            .get(root)
            .is_some_and(|m| !matches!(m, Manifest::Absent))
    }

    /// Up to `cap` roots cached as stored (readable or not), which a read of
    /// values need not bring down again.
    pub(crate) fn stored_roots(&self, cap: usize) -> Vec<&str> {
        self.manifests
            .iter()
            .filter(|(_, m)| !matches!(m, Manifest::Absent))
            .map(|(r, _)| r.as_str())
            .take(cap)
            .collect()
    }

    /// The cached answer for `root`: `None` when it is not cached,
    /// `Some(None)` when it is cached as not stored.
    pub(crate) fn manifest(&self, root: &str) -> Option<Option<StoredManifest>> {
        self.manifests.get(root).map(|m| m.to_stored(root))
    }

    fn drop_manifest(&mut self, root: &str) -> bool {
        match self.manifests.remove(root) {
            Some(m) => {
                self.bytes = self.bytes.saturating_sub(m.size() + root.len());
                true
            }
            None => false,
        }
    }

    /// Cache a manifest (or that it is absent), unless the cache is full.
    pub(crate) fn set_manifest(&mut self, root: String, m: Manifest) {
        self.drop_manifest(&root);
        let size = m.size() + root.len();
        if self.fits(size) {
            self.bytes += size;
            self.manifests.insert(root, m);
        }
    }

    // ---- this handle's own writes ---------------------------------------------

    /// This handle stored `e` (with its bytes): its unit's cached listing
    /// loses the slot's other keys and gains this one, with its value.
    pub(crate) fn put(&mut self, e: &StoredEnvelope) {
        let Some(l) = self.listings.get_mut(&e.test_key) else {
            self.take_value(&e.key);
            return;
        };
        let replaced: Vec<String> = l
            .iter()
            .filter(|x| same_slot(&x.key, e))
            .map(|x| x.key.clone())
            .collect();
        let before: usize = l.iter().map(Listed::size).sum();
        l.retain(|x| !same_slot(&x.key, e));
        l.push(Listed {
            key: e.key.clone(),
            target: e.target.clone(),
        });
        l.sort_by(|a, b| a.key.cmp(&b.key));
        let after: usize = l.iter().map(Listed::size).sum();
        self.bytes = (self.bytes + after).saturating_sub(before);
        for k in replaced {
            self.take_value(&k);
        }
        self.set_value(e.key.clone(), Value::Bytes(e.bytes.clone()));
    }

    /// This handle removed `key`.
    pub(crate) fn removed(&mut self, key: &str) {
        self.take_value(key);
        if let Some((tk, _, _)) = key::parse_key(key)
            && let Some(l) = self.listings.get_mut(tk)
        {
            let before = l.len();
            l.retain(|x| x.key != key);
            if l.len() < before {
                self.bytes = self.bytes.saturating_sub(key.len() + 48);
            }
        }
    }

    /// This handle removed every key of a slot.
    pub(crate) fn removed_slot(&mut self, test_key: &str, signer: &str, storage_key: &str) {
        let Some(l) = self.listings.get(test_key) else {
            return;
        };
        let doomed: Vec<String> = l
            .iter()
            .filter(|x| {
                key::parse_key(&x.key).is_some_and(|(_, s, k)| s == signer && k == storage_key)
            })
            .map(|x| x.key.clone())
            .collect();
        for k in doomed {
            self.removed(&k);
        }
    }

    /// This handle stored a manifest: a cached answer for its root (an
    /// absent one too) is replaced, or dropped when the cache is full.
    pub(crate) fn manifest_put(&mut self, root: &str, bytes: &[u8]) {
        if self.drop_manifest(root) {
            self.set_manifest(root.to_owned(), Manifest::Bytes(bytes.to_vec()));
        }
    }

    /// This handle removed a manifest.
    pub(crate) fn manifest_removed(&mut self, root: &str) {
        if self.drop_manifest(root) {
            self.set_manifest(root.to_owned(), Manifest::Absent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vci_store::KeyHint;

    const TK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const S1: &str = "1111111111111111";

    fn hinted(sk: &str, issued: i64) -> String {
        key::attestation_key_hinted(TK, S1, sk, &KeyHint { issued, tree: None })
    }

    fn stored(key: &str, bytes: &[u8]) -> StoredEnvelope {
        let mut e = StoredEnvelope::from_key("path:src/a", key).unwrap();
        e.set_value(bytes.to_vec());
        e
    }

    #[test]
    fn own_puts_replace_the_slot_and_removals_drop_keys() {
        let mut c = Cache::default();
        let old = hinted("ab", 1);
        let other = hinted("cd", 1);
        c.set_listing(
            TK.to_owned(),
            vec![
                Listed {
                    key: other.clone(),
                    target: "path:src/a".into(),
                },
                Listed {
                    key: old.clone(),
                    target: "path:src/a".into(),
                },
            ],
        );
        c.set_value(old.clone(), Value::Bytes(b"old".to_vec()));
        let new = hinted("ab", 2);
        c.put(&stored(&new, b"new"));
        assert_eq!(c.listed_keys(TK).unwrap(), {
            let mut v = vec![new.clone(), other.clone()];
            v.sort();
            v
        });
        assert!(!c.has_value(&old));
        assert_eq!(c.take_value(&new), Some(Value::Bytes(b"new".to_vec())));
        assert!(!c.has_value(&new), "a value leaves the cache when read");
        c.removed(&other);
        assert_eq!(c.listed_keys(TK).unwrap(), vec![new]);
    }

    #[test]
    fn manifest_puts_replace_absent_answers_only_when_cached() {
        let mut c = Cache::default();
        c.set_manifest("aa".into(), Manifest::Absent);
        assert_eq!(c.manifest("aa"), Some(None));
        c.manifest_put("aa", b"{}");
        assert_eq!(
            c.manifest("aa"),
            Some(Some(StoredManifest::with_bytes("aa", b"{}".to_vec())))
        );
        c.manifest_put("bb", b"{}");
        assert_eq!(c.manifest("bb"), None, "not cached before, not cached now");
        c.manifest_removed("aa");
        assert_eq!(c.manifest("aa"), Some(None));
        let before = c.bytes();
        c.set_manifest("cc".into(), Manifest::Bytes(vec![0; CAP]));
        assert_eq!(c.bytes(), before, "nothing is added above the cap");
    }
}
