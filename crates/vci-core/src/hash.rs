//! Hashing primitives and the canonical encodings they hash.
//!
//! Every structured hash is BLAKE3 over a sequence of fields, each written as
//! either a `u64` little-endian integer or a length-prefixed byte string
//! (`u64` LE length followed by the bytes). The first field is always a domain
//! tag, so encodings for different purposes can never collide.

/// Hash used for [`crate::EntryKind::Absent`] entries and for unset
/// environment variables: 64 lowercase hex zeros. No BLAKE3 output is expected
/// to equal it, so an unset variable never matches a set one (even when set to
/// the empty string).
pub const ABSENT_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Domain tag for [`crate::InputManifest::root`].
pub const INPUT_ROOT_DOMAIN: &[u8] = b"vci/input-root/v1";
/// Domain tag for the hash of a [`crate::EntryKind::DirListing`] entry.
pub const DIR_LISTING_DOMAIN: &[u8] = b"vci/dir-listing/v1";

/// Lowercase hex BLAKE3 of `bytes`.
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Streaming writer for the canonical length-prefixed encoding.
pub(crate) struct Enc(blake3::Hasher);

impl Enc {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut e = Enc(blake3::Hasher::new());
        e.bytes(domain);
        e
    }

    pub(crate) fn u64(&mut self, n: u64) -> &mut Self {
        self.0.update(&n.to_le_bytes());
        self
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u64(b.len() as u64);
        self.0.update(b);
        self
    }

    pub(crate) fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub(crate) fn finish(&self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

/// Kind of a directory child, as recorded in a directory listing hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ChildType {
    File,
    Dir,
    Symlink,
    Other,
}

impl ChildType {
    fn tag(self) -> &'static str {
        match self {
            ChildType::File => "file",
            ChildType::Dir => "dir",
            ChildType::Symlink => "symlink",
            ChildType::Other => "other",
        }
    }

    pub(crate) fn from_file_type(ft: std::fs::FileType) -> Self {
        if ft.is_symlink() {
            ChildType::Symlink
        } else if ft.is_dir() {
            ChildType::Dir
        } else if ft.is_file() {
            ChildType::File
        } else {
            ChildType::Other
        }
    }
}

/// Hash of a directory listing: domain tag, child count, then each child's
/// name and type (not following symlinks), sorted by name bytes.
pub(crate) fn dir_listing_hash(children: &mut [(String, ChildType)]) -> String {
    children.sort();
    let mut e = Enc::new(DIR_LISTING_DOMAIN);
    e.u64(children.len() as u64);
    for (name, ty) in children.iter() {
        e.str(name).str(ty.tag());
    }
    e.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_known_vectors() {
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(ABSENT_HASH.len(), 64);
        assert!(ABSENT_HASH.bytes().all(|b| b == b'0'));
    }

    #[test]
    fn length_prefix_prevents_concatenation_ambiguity() {
        let a = Enc::new(b"t").str("ab").str("c").finish();
        let b = Enc::new(b"t").str("a").str("bc").finish();
        assert_ne!(a, b);
    }

    #[test]
    fn dir_listing_is_order_independent_and_type_sensitive() {
        let mut a = vec![
            ("b".to_owned(), ChildType::File),
            ("a".to_owned(), ChildType::Dir),
        ];
        let mut b = vec![
            ("a".to_owned(), ChildType::Dir),
            ("b".to_owned(), ChildType::File),
        ];
        assert_eq!(dir_listing_hash(&mut a), dir_listing_hash(&mut b));
        let mut c = vec![
            ("a".to_owned(), ChildType::Dir),
            ("b".to_owned(), ChildType::Symlink),
        ];
        assert_ne!(dir_listing_hash(&mut b), dir_listing_hash(&mut c));
        let mut d = vec![("a".to_owned(), ChildType::Dir)];
        assert_ne!(dir_listing_hash(&mut b), dir_listing_hash(&mut d));
    }
}
