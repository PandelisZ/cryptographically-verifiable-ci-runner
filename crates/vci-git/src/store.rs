//! git-meta as a [`vci_store::AttestationStore`]: the store every vci has
//! used so far, behind the trait every backend implements.
//!
//! [`GitMetaStore`] delegates to [`AttestStore`], whose behaviour and messages
//! are unchanged, and adds what the trait asks of a store shared by many
//! threads: a pool of [`Reader`]s (a reader owns a SQLite connection and a
//! `git cat-file` process, so it is `Send` but not `Sync`). Each concurrent
//! caller takes one reader from the pool and gives it back, so a plan's
//! verifying threads keep one reader each, as the plan's own per-thread
//! readers did before.
//!
//! Pool rules:
//!
//! * a reader opened while the repository has no git-meta store
//!   ([`Reader::has_store`] false) is dropped, never pooled: it would read
//!   nothing for the rest of the process, even after a fetch creates the
//!   store;
//! * the pool is emptied after every [`AttestationStore::prefetch`],
//!   [`Exchange::fetch`] and [`Exchange::push`]: a reader keeps a
//!   `git cat-file` process, and what it learnt about the object database,
//!   from before the download;
//! * a reader in use while the pool is emptied is dropped when it comes
//!   back.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use git_meta_lib::Target;
use vci_core::ObjectKind;
use vci_store::key::object_key;
use vci_store::select::Selection;
use vci_store::{
    AttestationStore, BackendFactory, BatchEnd, Caps, EMPTY_VALUE, Exchange, FetchOutcome,
    Hydration, MAX_OBJECTS_ANSWER, ManifestRef, NewAttestation, NewObject, OBJECT_GRACE,
    OpenContext, Prefetch, PushMode, PushOutcome, StoreError, StoreStatus, StoredEnvelope,
    StoredManifest, StoredObject, WriteBatch, key,
};

use crate::GitError;
use crate::meta::{AttestStore, BatchGuard, ObjectRow, Reader, now_ms};
use crate::repo::Repo;

/// The backend's name ([`AttestationStore::kind`]).
const KIND: &str = "git-meta";

/// Where the attestations are exchanged ([`Exchange::exchange_point`]).
const EXCHANGE_POINT: &str = "refs/meta/main";

impl From<GitError> for StoreError {
    /// [`GitError::Invalid`] becomes [`StoreError::Invalid`] field for field;
    /// every other error is kept whole as [`StoreError::Backend`], so its
    /// text is unchanged and [`StoreError::downcast_backend`] gets it back
    /// (for example [`GitError::NoMetaRemote`]).
    fn from(e: GitError) -> Self {
        match e {
            GitError::Invalid {
                what,
                value,
                reason,
            } => StoreError::Invalid {
                what,
                value,
                reason,
            },
            other => StoreError::Backend(Box::new(other)),
        }
    }
}

/// The readers not in use, and the pool's generation: emptying the pool
/// starts a new one, and a reader taken out in an older generation is not
/// put back.
#[derive(Default)]
struct Pool {
    generation: u64,
    readers: Vec<Reader>,
}

/// The attestation store of one repository, kept by git-meta in
/// `<common git dir>/git-meta.sqlite` (`.git/git-meta.sqlite`, shared by
/// every linked worktree since 2.7.33: [`AttestStore::store_path`]) and
/// exchanged on `refs/meta/main` (see [`crate::meta`]). One value serves
/// every thread of a process.
pub struct GitMetaStore {
    repo: Repo,
    readers: Mutex<Pool>,
}

impl std::fmt::Debug for GitMetaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitMetaStore")
            .field("root", &self.repo.root())
            .field("pooled_readers", &self.pooled_readers())
            .finish()
    }
}

impl GitMetaStore {
    /// The store of `repo`. Nothing is opened or created until it is used.
    pub fn new(repo: Repo) -> Self {
        GitMetaStore {
            repo,
            readers: Mutex::new(Pool::default()),
        }
    }

    /// The repository whose store this is.
    pub fn repo(&self) -> &Repo {
        &self.repo
    }

    /// The concrete git-meta store, for what the trait does not cover
    /// (`vci init`'s remote set-up, the e2e helpers).
    pub fn attest_store(&self) -> AttestStore<'_> {
        AttestStore::new(&self.repo)
    }

    /// How many readers the pool holds now (for tests).
    #[doc(hidden)]
    pub fn pooled_readers(&self) -> usize {
        self.pool().readers.len()
    }

    fn pool(&self) -> MutexGuard<'_, Pool> {
        self.readers.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Run `f` with a reader from the pool (or a new one), and give the
    /// reader back afterwards when it read a store and `f` succeeded.
    fn with_reader<T>(
        &self,
        f: impl FnOnce(&Reader) -> Result<T, GitError>,
    ) -> Result<T, StoreError> {
        let (generation, pooled) = {
            let mut pool = self.pool();
            (pool.generation, pool.readers.pop())
        };
        let reader = match pooled {
            Some(r) => r,
            None => self.attest_store().reader()?,
        };
        let out = f(&reader);
        if out.is_ok() && reader.has_store() {
            let mut pool = self.pool();
            if pool.generation == generation {
                pool.readers.push(reader);
            }
        }
        Ok(out?)
    }

    /// Drop every pooled reader (after a download: see the module docs).
    fn refresh_readers(&self) {
        let old = {
            let mut pool = self.pool();
            pool.generation += 1;
            std::mem::take(&mut pool.readers)
        };
        // Their `git cat-file` processes end outside the lock.
        drop(old);
    }

    /// The stored objects the orphan rule would remove now, among `among`
    /// (every object when `None`): first every attestation not fetched yet
    /// is fetched (any of them could name an object: a run's records are
    /// stored on every path target), then every value is read once and the
    /// ids they name collected (`AttestStore::referenced_objects`); an
    /// object no record names, put more than [`OBJECT_GRACE`] ago, goes.
    /// One that cannot be decided keeps every object (an empty answer), as
    /// `orphan_manifests` does. State objects are in no signed field, so
    /// they are never orphans here: `prune_state_objects` removes them.
    fn orphans(&self, among: Option<&BTreeSet<&str>>) -> Result<Vec<ObjectRow>, StoreError> {
        let st = self.attest_store();
        let hydrated = st.hydrate_attestations();
        self.refresh_readers();
        hydrated?;
        let Some(referenced) = st.referenced_objects(false)? else {
            return Ok(Vec::new());
        };
        let cutoff = now_ms().saturating_sub(millis(OBJECT_GRACE));
        Ok(self
            .with_reader(Reader::object_rows)?
            .into_iter()
            .filter(|r| r.kind != ObjectKind::State)
            .filter(|r| r.put_at < cutoff)
            .filter(|r| !referenced.contains(&r.id))
            .filter(|r| among.is_none_or(|a| a.contains(r.id.as_str())))
            .collect())
    }
}

/// `d` as milliseconds, saturating.
fn millis(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// The trait's "either bytes or an error" for an entry a git-meta read
/// filled in: an error leaves no bytes, and empty bytes are
/// [`EMPTY_VALUE`] (vci never stores them).
fn settle(e: &mut StoredEnvelope) {
    match &e.error {
        Some(_) => e.bytes.clear(),
        None if e.bytes.is_empty() => e.set_error(EMPTY_VALUE),
        None => {}
    }
}

impl AttestationStore for GitMetaStore {
    fn kind(&self) -> &'static str {
        KIND
    }

    /// `.git/git-meta.sqlite` in the main worktree; in a linked one, the
    /// common git directory's store it shares (2.7.33), by its path.
    fn location(&self) -> String {
        match self.repo.linked_common() {
            Some(common) => format!(
                "{common}/git-meta.sqlite, shared by every worktree of the repository (exchanged on {EXCHANGE_POINT})"
            ),
            None => format!(".git/git-meta.sqlite (exchanged on {EXCHANGE_POINT})"),
        }
    }

    /// Lazy values, hints kept, format-3 objects kept as base64 string
    /// values; no listing columns (the hint is the key: STORE-V2 section
    /// 2.2).
    fn caps(&self) -> Caps {
        Caps::LOCAL
            .with_lazy_values(true)
            .with_hints(true)
            .with_objects(true)
    }

    fn status(&self) -> Result<StoreStatus, StoreError> {
        let exists = self.with_reader(|r| Ok(r.has_store()))?;
        Ok(if exists {
            StoreStatus::Ready {
                schema_version: None,
            }
        } else {
            StoreStatus::Absent {
                advice: "run `vci fetch`".to_owned(),
            }
        })
    }

    fn list_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        self.with_reader(|r| {
            test_ids
                .iter()
                .map(|id| r.candidates_reading(id, |_| false))
                .collect()
        })
    }

    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        self.with_reader(|r| r.all_reading(|_| false))
    }

    fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        self.attest_store()
            .read_values(envs.iter_mut().map(|e| &mut **e))?;
        for e in envs.iter_mut() {
            settle(e);
        }
        Ok(())
    }

    fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
        self.with_reader(|r| r.manifest(root))
    }

    fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        self.with_reader(Reader::manifest_roots)
    }

    fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
        att.validate()?;
        let target = match att.target.strip_prefix("path:") {
            Some(p) => Target::path(p),
            None => Target::project(),
        };
        let key = self.attest_store().put_keyed(
            &target,
            &att.test_key,
            att.signer,
            att.storage_key,
            att.hint,
            att.envelope,
        )?;
        Ok(att.stored(key))
    }

    fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        vci_store::key::check_hex("input root", root)?;
        if bytes.is_empty() {
            return Err(StoreError::invalid("manifest", "", "must not be empty"));
        }
        Ok(self.attest_store().put_manifest(root, bytes)?)
    }

    fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
        Ok(self.attest_store().remove_envelopes(doomed)?)
    }

    fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError> {
        Ok(self
            .attest_store()
            .remove_manifests(roots.iter().copied())?)
    }

    /// One listing of the object keys and one lookup per object held, on a
    /// pooled reader; the base64 text decoded here. An object not fetched
    /// yet (a lazy row: `Prefetch::Objects` first), whose blob is missing
    /// or whose text is not base64 is left out.
    fn get_objects(&self, ids: &[&str]) -> Result<Vec<StoredObject>, StoreError> {
        let mut wanted: Vec<&str> = Vec::with_capacity(ids.len());
        for id in ids {
            key::check_object_id(id)?;
            if !wanted.contains(id) {
                wanted.push(id);
            }
        }
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let texts = self.with_reader(|r| r.objects(&wanted))?;
        let mut out = Vec::with_capacity(texts.len());
        let mut total = 0usize;
        for (id, kind, text) in texts {
            let Ok(text) = text else {
                continue;
            };
            // Decoded, base64 is three quarters of the text: refused before
            // the decode allocates past the bound.
            if total + text.len() / 4 * 3 > MAX_OBJECTS_ANSWER {
                return Err(StoreError::invalid(
                    "objects",
                    &format!("{} ids", wanted.len()),
                    "the answer would be over the bound of one get_objects",
                ));
            }
            let Some(bytes) = std::str::from_utf8(&text)
                .ok()
                .and_then(|t| vci_store::object_from_base64(t).ok())
            else {
                continue;
            };
            total += bytes.len();
            out.push(StoredObject { id, kind, bytes });
        }
        Ok(out)
    }

    /// Every object validated first (its id computed from its bytes), then
    /// `AttestStore::put_objects` with the base64 text of each: inside a
    /// batch on its connection, else through git-meta.
    fn put_objects(&self, objects: &[NewObject<'_>]) -> Result<usize, StoreError> {
        let mut items = Vec::with_capacity(objects.len());
        for o in objects {
            let id = o.validate()?;
            items.push((o.kind, id, vci_store::object_to_base64(o.bytes)));
        }
        Ok(self.attest_store().put_objects(&items)?)
    }

    /// The orphan rule applied at once ([`GitMetaStore::orphans`], which
    /// fetches every attestation not fetched yet and reads every value),
    /// then the orphans among `ids` deleted (tombstones, published by the
    /// next push). Inside a batch the scan reads the store as committed
    /// before the batch, so a record the batch removed still counts as a
    /// referrer: its objects go at a later call.
    fn remove_objects(&self, ids: &[&str]) -> Result<usize, StoreError> {
        for id in ids {
            key::check_object_id(id)?;
        }
        if ids.is_empty() {
            return Ok(0);
        }
        let among: BTreeSet<&str> = ids.iter().copied().collect();
        let keys: Vec<String> = self
            .orphans(Some(&among))?
            .iter()
            .map(|r| object_key(r.kind, &r.id))
            .collect();
        Ok(self.attest_store().remove_object_keys(keys)?)
    }

    /// [`GitMetaStore::orphans`] over every object, their ids sorted.
    fn orphan_objects(&self) -> Result<Vec<String>, StoreError> {
        let mut ids: Vec<String> = self.orphans(None)?.into_iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Every state object whose row was last put or fetched here more than
    /// `older_than` ago, deleted whatever names it (values not read; the
    /// listing of the object keys on a pooled reader).
    fn prune_state_objects(&self, older_than: Duration) -> Result<usize, StoreError> {
        let cutoff = now_ms().saturating_sub(millis(older_than));
        let keys: Vec<String> = self
            .with_reader(Reader::object_rows)?
            .iter()
            .filter(|r| r.kind == ObjectKind::State && r.put_at < cutoff)
            .map(|r| object_key(r.kind, &r.id))
            .collect();
        Ok(self.attest_store().remove_object_keys(keys)?)
    }

    /// One pooled reader and one targeted query per unit, values read with
    /// it (what `AttestStore::list(Some(id))` does), never the default's
    /// scan of every row plus a `git cat-file` per call: supersession calls
    /// this once per unit from worker threads.
    fn read_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        let mut units = self.with_reader(|r| {
            test_ids
                .iter()
                .map(|id| r.candidates_reading(id, |_| true))
                .collect::<Result<Vec<_>, _>>()
        })?;
        units.iter_mut().flatten().for_each(settle);
        Ok(units)
    }

    /// Every record and its value in one pass (`AttestStore::list(None)`).
    fn read_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        let mut all = self.attest_store().list(None)?;
        all.iter_mut().for_each(settle);
        Ok(all)
    }

    fn count(&self) -> Result<usize, StoreError> {
        self.with_reader(Reader::count)
    }

    fn manifests(&self, roots: &[&str]) -> Result<Vec<Option<StoredManifest>>, StoreError> {
        self.with_reader(|r| roots.iter().map(|root| r.manifest(root)).collect())
    }

    /// vci's supersession clean-up as it was (`drop_orphan_manifests`):
    /// first fetch the attestations not fetched yet that could reference
    /// one of `roots` ([`AttestStore::hydrate_manifest_referrers`]; the roots
    /// it cannot decide are kept), then read every attestation. One that is
    /// still not fetched cannot reference a decided root and is skipped; any
    /// other unreadable value, or a payload whose `manifestRef` is unknown,
    /// makes the answer empty.
    fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let wanted: BTreeSet<String> = roots.iter().map(|r| (*r).to_owned()).collect();
        let st = self.attest_store();
        let undecided = st.hydrate_manifest_referrers(&wanted);
        self.refresh_readers();
        let undecided = undecided?;
        let mut referenced = BTreeSet::new();
        for e in st.list(None)? {
            if e.not_fetched() {
                continue;
            }
            if e.error.is_some() {
                return Ok(Vec::new());
            }
            match vci_store::key::envelope_manifest_ref(&e.bytes) {
                ManifestRef::Root(r) => {
                    referenced.insert(r);
                }
                ManifestRef::Inline => {}
                ManifestRef::Unknown => return Ok(Vec::new()),
            }
        }
        Ok(wanted
            .difference(&referenced)
            .filter(|r| !undecided.contains(*r))
            .cloned()
            .collect())
    }

    /// Writes share one git-meta session and one store connection, and are
    /// one transaction on it (2.8): durable, and visible to other readers,
    /// once the batch finishes.
    fn batch(&self) -> Result<WriteBatch, StoreError> {
        Ok(WriteBatch::deferred(Box::new(GitBatch(
            self.attest_store().batch()?,
        ))))
    }

    /// The values not fetched yet that `what` names, in batched `git fetch`
    /// of object ids (`AttestStore::hydrate_*`); then the reader pool is
    /// emptied.
    fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        let st = self.attest_store();
        let out = match what {
            Prefetch::Units {
                test_ids,
                choose: Some(choose),
            } => st.hydrate_units_choosing(test_ids.iter().copied(), |c| choose(c)),
            Prefetch::Units {
                test_ids,
                choose: None,
            } => st.hydrate_units(test_ids.iter().copied()),
            Prefetch::Manifests { roots } => st.hydrate_manifests(roots.iter().copied()),
            Prefetch::Attestations => st.hydrate_attestations(),
            Prefetch::Objects { ids } => st.hydrate_objects(ids.iter().copied()),
            _ => Ok(Hydration::default()),
        };
        self.refresh_readers();
        Ok(out?)
    }

    /// Reads the store file ([`AttestStore::store_path`]) through once on a
    /// thread.
    fn warm(&self) {
        self.attest_store().warm_in_background();
    }

    fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
        self.attest_store().passing_on(tree16)
    }

    fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        self.attest_store().remember_passing(tree16, items);
    }

    fn flag(&self, name: &str) -> bool {
        self.attest_store().flag(name)
    }

    fn set_flag(&self, name: &str) {
        self.attest_store().set_flag(name);
    }

    /// `put_manifest seconds: session …, read current …, set …, stamp …`
    /// (since the process started), the line vci has always printed.
    fn timing_report(&self) -> Vec<String> {
        let pm = AttestStore::put_manifest_seconds();
        vec![format!(
            "put_manifest seconds: session {:.1}, read current {:.1}, set {:.1}, stamp {:.1}",
            pm[0], pm[1], pm[2], pm[3]
        )]
    }

    fn exchange(&self) -> Option<&dyn Exchange> {
        Some(self)
    }
}

impl Exchange for GitMetaStore {
    fn exchange_point(&self) -> &str {
        EXCHANGE_POINT
    }

    /// The remote's URL without credentials
    /// ([`vci_store::select::redact_credentials`]): a git remote's URL, not
    /// a store's, so its path is shown, where
    /// [`vci_store::select::redact`] hides a libSQL server's.
    fn remote_location(&self, remote: &str) -> Option<String> {
        self.attest_store()
            .remote_url(remote)
            .ok()
            .flatten()
            .map(|u| vci_store::select::redact_credentials(&u))
    }

    /// [`AttestStore::fetch`]; then the reader pool is emptied.
    fn fetch(&self, remote: Option<&str>) -> Result<FetchOutcome, StoreError> {
        let out = self.attest_store().fetch(remote);
        self.refresh_readers();
        Ok(out?)
    }

    /// [`AttestStore::push`], or [`AttestStore::push_rewriting_history`];
    /// then the reader pool is emptied.
    fn push(&self, remote: Option<&str>, mode: PushMode) -> Result<PushOutcome, StoreError> {
        let st = self.attest_store();
        let out = match mode {
            PushMode::Merge => st.push(remote),
            PushMode::RewriteHistory => st.push_rewriting_history(remote),
            _ => {
                return Err(StoreError::Unsupported {
                    backend: KIND,
                    operation: "this kind of push",
                });
            }
        };
        self.refresh_readers();
        Ok(out?)
    }
}

/// An open git-meta write batch ([`AttestStore::batch`]): while it lives,
/// this thread's writes share one session and one store connection, in one
/// transaction.
struct GitBatch(BatchGuard);

impl BatchEnd for GitBatch {
    /// Commits the batch's transaction and stamps its writes, then closes
    /// the shared session and connection. Stamping fails only after the
    /// commit: a warning.
    fn finish(self: Box<Self>) -> Result<Vec<String>, StoreError> {
        Ok(self.0.finish()?)
    }
}

/// Opens the git-meta store of one repository (`VCI_STORE=git-meta`, the
/// default).
#[derive(Debug, Clone)]
pub struct GitMetaFactory {
    repo: Repo,
}

impl GitMetaFactory {
    /// The factory for `repo`'s store.
    pub fn new(repo: Repo) -> Self {
        GitMetaFactory { repo }
    }
}

impl BackendFactory for GitMetaFactory {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn summary(&self) -> &'static str {
        "git-meta in .git/git-meta.sqlite (shared by the repository's worktrees), exchanged on refs/meta/main by vci fetch and vci push (the default)"
    }

    /// The store of the factory's repository. git-meta has no settings of
    /// its own in the selection; nothing is opened until the first call.
    fn open(
        &self,
        _sel: &Selection,
        _cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        Ok(Arc::new(GitMetaStore::new(self.repo.clone())))
    }
}
