//! In-memory adapter, session store and source reader for crash-window tests.
//!
//! `#[cfg(test)]` only — this is never compiled into a shipping binary.
//!
//! AC-2 is "kill the daemon mid-upload of a 50 GB file, restart, resume without
//! re-sending verified parts". A real 50 GB upload is not a unit test, but the
//! *property* is not about the size — it is about which durable records exist
//! on each side of the kill. These fakes make each crash window reproducible on
//! demand: a real filesystem cannot be asked to lose a specific `fsync`, and a
//! real provider cannot be asked to expire a session between two calls.
//!
//! A crash is modelled as **an error returned at a chosen point, followed by
//! reloading the session from the store and running again**. That exercises the
//! true resume path — the driver reads only what was durably persisted, exactly
//! as it would after a process death.

use std::collections::HashMap;
use std::sync::Mutex;

use bytes::Bytes;
use shepherd_core::{Blake3Hash, JobId, ObjectKey, ObjectVersion, Timestamp};

use crate::adapter::{
    AdapterCapabilities, AttestationMode, ByteRange, ControlKey, CreatePrecondition, CreateReceipt,
    IncompleteUpload, ListPage, ListVisibility, ObjectChecksum, ObjectMeta, OpaqueToken,
    PartReceipt, StorageAdapter, StorageError, StorageResult, VersionGuard,
};
use crate::transfer_session::{
    SourceFingerprint, SourceReader, TransferSession, TransferSessionStore,
};

/// Faults the fake provider can be told to inject.
#[derive(Debug, Default, Clone)]
pub struct Faults {
    /// Fail `upload_part` for this part number, once.
    pub fail_part_once: Option<u32>,
    /// Report the session unknown on the next `list_parts` or `upload_part`,
    /// once — provider session expiry (window 4).
    ///
    /// One-shot on purpose: a permanently-expiring provider would send the
    /// driver round the restart loop until `max_attempt_epochs`, which is a
    /// different test (`a_target_that_never_keeps_a_session_fails_closed`).
    pub expire_session_once: bool,
    /// Perform the completion, then lose the response (window 3).
    pub lose_complete_response: bool,
}

#[derive(Debug, Default)]
struct Upload {
    /// Per part: the bytes, the opaque receipt, and the provider's own per-part
    /// checksum when the session was created with a checksum algorithm.
    parts: HashMap<u32, (Bytes, OpaqueToken, Option<String>)>,
    aborted: bool,
}

#[derive(Debug, Default)]
struct Inner {
    objects: HashMap<String, (Bytes, Option<ObjectVersion>)>,
    /// Keys LIST reports and HEAD does not — a provider naming an object it
    /// will not stand behind. Real: an eventually-consistent listing, or an
    /// object deleted between the two calls.
    phantom_keys: Vec<String>,
    uploads: HashMap<String, Upload>,
    next_token: u64,
    faults: Faults,
    /// Every `abort_multipart` that reached the provider, for assertions about
    /// orphan reaping.
    aborts: Vec<String>,
    /// Counts `list` calls, so OQ-1's "allocation never reads LIST" can be
    /// asserted directly instead of trusted.
    list_calls: usize,
    /// Keys passed to `delete_object`, in order. The destroy-path tests assert
    /// on what was actually deleted rather than inferring it from absence —
    /// absence is also what a never-created object looks like.
    deleted: Vec<String>,
    /// What `head` reports as the provider's whole-object checksum.
    ///
    /// `None` by default, modelling a provider that offers none. Settable
    /// because the two `Some` shapes are the ones that carry risk and they were
    /// unreachable while this was hardcoded: a genuine whole-object value must
    /// be **carried through** to `VerifiedLocation`, and a COMPOSITE
    /// digest-of-digests must be **dropped**. The second is a safety guard, and
    /// an untested safety guard is a comment.
    whole_object_checksum: Option<ObjectChecksum>,
    /// Whether multipart sessions carry per-part checksums, as they do once a
    /// target's registration probe adopted an algorithm.
    part_checksums: bool,
    /// The receipts `complete_multipart` was actually handed, in order.
    ///
    /// Recorded because "did completion succeed?" is a weaker question than
    /// "what did completion send?". A resumed session that skipped a part must
    /// still echo that part's provider checksum back, and the only place that
    /// claim is observable is here.
    completion_receipts: Vec<PartReceipt>,
}

/// An in-memory `StorageAdapter`.
#[derive(Debug)]
pub struct MemAdapter {
    caps: AdapterCapabilities,
    inner: Mutex<Inner>,
    versioned: bool,
}

impl MemAdapter {
    /// A non-versioned target: mechanism B, matching a default MinIO bucket.
    pub fn content_addressed() -> Self {
        Self::with(false, true)
    }

    /// A versioned target: mechanism A.
    pub fn versioned() -> Self {
        Self::with(true, true)
    }

    pub fn with(versioned: bool, conditional_create: bool) -> Self {
        Self {
            caps: AdapterCapabilities {
                provider: "mem",
                conditional_create,
                min_part_size: 8,
                max_part_size: 1024 * 1024,
                max_parts: 10_000,
                list_visibility: ListVisibility::Strong,
            },
            inner: Mutex::new(Inner::default()),
            versioned,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("test mutex poisoned")
    }

    pub fn set_faults(&self, f: Faults) {
        self.lock().faults = f;
    }

    /// Model a provider that returns a whole-object checksum from `head`.
    ///
    /// Pass a value with `whole_object: false` to model the COMPOSITE case —
    /// real S3 returns exactly that for a multipart object uploaded without
    /// `ChecksumType: FULL_OBJECT`, as `72M33w==-2`, where the trailing part
    /// count makes it visibly a digest-of-digests.
    pub fn set_whole_object_checksum(&self, c: Option<ObjectChecksum>) {
        self.lock().whole_object_checksum = c;
    }

    /// Model a provider whose multipart sessions carry **per-part checksums**,
    /// which is what a target produces once `target.add`'s registration probe
    /// has adopted an algorithm.
    ///
    /// `upload_part` and `list_parts` then return a per-part value, and
    /// `complete_multipart` **refuses a receipt that does not echo it back**.
    /// That refusal is not invented: it is MinIO's, recorded verbatim at
    /// `S3Adapter::complete_multipart` — "without it MinIO rejects the
    /// completion with `InvalidPart` — the ETag alone is not enough once the
    /// session was created with a checksum algorithm". Without modelling it,
    /// every fake completion accepts `checksum: None` and the one configuration
    /// a freshly registered S3 target actually produces is untested.
    pub fn require_part_checksums(&self) {
        self.lock().part_checksums = true;
    }

    /// The fake provider's per-part checksum: deterministic, and a function of
    /// the bytes, so a part re-sent with different content gets a different
    /// value.
    fn part_checksum(body: &Bytes) -> String {
        blake3::hash(body).to_hex()[..16].to_string()
    }

    /// The part receipts the last `complete_multipart` was handed.
    pub fn completion_receipts(&self) -> Vec<PartReceipt> {
        self.lock().completion_receipts.clone()
    }

    pub fn aborts(&self) -> Vec<String> {
        self.lock().aborts.clone()
    }

    pub fn list_calls(&self) -> usize {
        self.lock().list_calls
    }

    pub fn live_upload_count(&self) -> usize {
        self.lock().uploads.values().filter(|u| !u.aborted).count()
    }

    pub fn object(&self, key: &ObjectKey) -> Option<Bytes> {
        self.lock()
            .objects
            .get(key.as_str())
            .map(|(b, _)| b.clone())
    }

    /// Materialize an object directly, bypassing the adapter API — used to set
    /// up "the completion already happened" states.
    pub fn put_raw(&self, key: &ObjectKey, body: Bytes) {
        let v = self
            .versioned
            .then(|| ObjectVersion::new(format!("v{}", body.len())));
        self.lock()
            .objects
            .insert(key.as_str().to_owned(), (body, v));
    }

    /// Same, with an explicit version id.
    ///
    /// The destroy path pins a version at verify and re-attests it with a
    /// closing HEAD (§4.10.2 mechanism A), so its tests need to control that
    /// value rather than accept a derived one.
    pub fn put_versioned(&self, key: &ObjectKey, body: Bytes, version: &str) {
        self.lock().objects.insert(
            key.as_str().to_owned(),
            (body, Some(ObjectVersion::new(version))),
        );
    }

    /// Remove an object *without* going through the destructive verb — for
    /// setting up "the remote copy vanished underneath us" states.
    /// Make LIST report `key` while HEAD reports it absent.
    pub fn add_phantom_key(&self, key: &ObjectKey) {
        self.lock().phantom_keys.push(key.as_str().to_owned());
    }

    pub fn remove_raw(&self, key: &ObjectKey) {
        self.lock().objects.remove(key.as_str());
    }

    /// Keys passed to `delete_object`, in call order.
    ///
    /// The destroy-path tests assert on what was actually deleted rather than
    /// inferring it from absence — absence is also what a never-created object
    /// looks like, so inferring would pass on a bug that deleted nothing.
    pub fn deleted_keys(&self) -> Vec<String> {
        self.lock().deleted.clone()
    }

    fn issue_token(inner: &mut Inner, what: &str) -> OpaqueToken {
        inner.next_token += 1;
        OpaqueToken::new(format!("{what}-{}", inner.next_token))
    }
}

#[async_trait::async_trait]
impl StorageAdapter for MemAdapter {
    fn capabilities(&self) -> &AdapterCapabilities {
        &self.caps
    }

    async fn probe_attestation_mode(&self) -> StorageResult<AttestationMode> {
        Ok(if self.versioned {
            AttestationMode::Version
        } else {
            AttestationMode::Content
        })
    }

    async fn create(
        &self,
        key: &ObjectKey,
        body: Bytes,
        precondition: CreatePrecondition,
    ) -> StorageResult<CreateReceipt> {
        let mut inner = self.lock();
        if precondition == CreatePrecondition::IfAbsent && inner.objects.contains_key(key.as_str())
        {
            return Err(StorageError::PreconditionFailed {
                key: key.as_str().to_owned(),
                detail: "If-None-Match: * — key exists".into(),
            });
        }
        let version = self
            .versioned
            .then(|| ObjectVersion::new(format!("v{}", body.len())));
        let etag = Self::issue_token(&mut inner, "etag");
        inner
            .objects
            .insert(key.as_str().to_owned(), (body, version.clone()));
        Ok(CreateReceipt {
            key: key.clone(),
            version,
            etag: Some(etag),
        })
    }

    async fn create_multipart(&self, key: &ObjectKey) -> StorageResult<OpaqueToken> {
        let mut inner = self.lock();
        let id = Self::issue_token(&mut inner, "upload");
        inner
            .uploads
            .insert(id.as_opaque().to_owned(), Upload::default());
        let _ = key;
        Ok(id)
    }

    async fn upload_part(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
        part_no: u32,
        body: Bytes,
    ) -> StorageResult<PartReceipt> {
        let mut inner = self.lock();
        if inner.faults.expire_session_once {
            inner.faults.expire_session_once = false;
            return Err(StorageError::NoSuchUpload {
                key: key.as_str().to_owned(),
            });
        }
        if inner.faults.fail_part_once == Some(part_no) {
            inner.faults.fail_part_once = None;
            return Err(StorageError::Transient {
                op: format!("upload_part {part_no}"),
                detail: "injected".into(),
            });
        }
        let etag = Self::issue_token(&mut inner, "etag");
        let size = body.len() as u64;
        let checksum = inner.part_checksums.then(|| Self::part_checksum(&body));
        let up = inner
            .uploads
            .get_mut(upload_id.as_opaque())
            .ok_or_else(|| StorageError::NoSuchUpload {
                key: key.as_str().to_owned(),
            })?;
        if up.aborted {
            return Err(StorageError::NoSuchUpload {
                key: key.as_str().to_owned(),
            });
        }
        up.parts
            .insert(part_no, (body, etag.clone(), checksum.clone()));
        Ok(PartReceipt {
            part_no,
            size,
            etag,
            checksum,
        })
    }

    async fn list_parts(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
    ) -> StorageResult<Vec<PartReceipt>> {
        let mut inner = self.lock();
        if inner.faults.expire_session_once {
            inner.faults.expire_session_once = false;
            return Err(StorageError::NoSuchUpload {
                key: key.as_str().to_owned(),
            });
        }
        let up = inner
            .uploads
            .get(upload_id.as_opaque())
            .filter(|u| !u.aborted)
            .ok_or_else(|| StorageError::NoSuchUpload {
                key: key.as_str().to_owned(),
            })?;
        let mut v: Vec<PartReceipt> = up
            .parts
            .iter()
            .map(|(no, (b, e, c))| PartReceipt {
                part_no: *no,
                size: b.len() as u64,
                etag: e.clone(),
                checksum: c.clone(),
            })
            .collect();
        v.sort_by_key(|p| p.part_no);
        Ok(v)
    }

    async fn complete_multipart(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
        parts: &[PartReceipt],
        precondition: CreatePrecondition,
    ) -> StorageResult<CreateReceipt> {
        let mut inner = self.lock();
        if precondition == CreatePrecondition::IfAbsent && inner.objects.contains_key(key.as_str())
        {
            return Err(StorageError::PreconditionFailed {
                key: key.as_str().to_owned(),
                detail: "If-None-Match: * — key exists".into(),
            });
        }
        inner.completion_receipts = parts.to_vec();

        let up = inner
            .uploads
            .get(upload_id.as_opaque())
            .filter(|u| !u.aborted)
            .ok_or_else(|| StorageError::NoSuchUpload {
                key: key.as_str().to_owned(),
            })?;

        let mut assembled = Vec::new();
        for want in parts {
            let (bytes, etag, checksum) =
                up.parts
                    .get(&want.part_no)
                    .ok_or_else(|| StorageError::PreconditionFailed {
                        key: key.as_str().to_owned(),
                        detail: format!("part {} missing at completion", want.part_no),
                    })?;
            if *etag != want.etag {
                return Err(StorageError::PreconditionFailed {
                    key: key.as_str().to_owned(),
                    detail: format!("part {} etag mismatch", want.part_no),
                });
            }
            // MinIO's `InvalidPart`: once the session carries a checksum
            // algorithm, the ETag alone is not enough at completion.
            if checksum.is_some() && want.checksum != *checksum {
                return Err(StorageError::Provider {
                    provider: "mem",
                    op: "complete_multipart".into(),
                    detail: format!(
                        "InvalidPart: part {} was uploaded with checksum {:?} and the completion \
                         echoed {:?}",
                        want.part_no, checksum, want.checksum
                    ),
                });
            }
            assembled.extend_from_slice(bytes);
        }

        let body = Bytes::from(assembled);
        let version = self
            .versioned
            .then(|| ObjectVersion::new(format!("v{}", body.len())));
        inner
            .objects
            .insert(key.as_str().to_owned(), (body, version.clone()));
        inner.uploads.remove(upload_id.as_opaque());

        if inner.faults.lose_complete_response {
            inner.faults.lose_complete_response = false;
            // The object exists; the caller never learns that.
            return Err(StorageError::Transient {
                op: "complete_multipart".into(),
                detail: "injected lost response".into(),
            });
        }

        let etag = Self::issue_token(&mut inner, "etag");
        Ok(CreateReceipt {
            key: key.clone(),
            version,
            etag: Some(etag),
        })
    }

    async fn abort_multipart(&self, key: &ObjectKey, upload_id: &OpaqueToken) -> StorageResult<()> {
        let mut inner = self.lock();
        inner.aborts.push(upload_id.as_opaque().to_owned());
        let _ = key;
        if let Some(u) = inner.uploads.get_mut(upload_id.as_opaque()) {
            u.aborted = true;
            u.parts.clear();
        }
        Ok(())
    }

    async fn list_incomplete_uploads(&self, prefix: &str) -> StorageResult<Vec<IncompleteUpload>> {
        let inner = self.lock();
        Ok(inner
            .uploads
            .iter()
            .filter(|(_, u)| !u.aborted)
            .map(|(id, _)| IncompleteUpload {
                key: ObjectKey::new(prefix.to_owned()),
                upload_id: OpaqueToken::new(id.clone()),
            })
            .collect())
    }

    async fn head(&self, key: &ObjectKey) -> StorageResult<Option<ObjectMeta>> {
        let inner = self.lock();
        Ok(inner.objects.get(key.as_str()).map(|(b, v)| ObjectMeta {
            key: key.clone(),
            size: b.len() as u64,
            version: v.clone(),
            etag: Some(OpaqueToken::new("head-etag")),
            // `None` unless a test set one, which models a provider offering
            // no checksum and exercises the scrub fallback path.
            whole_object_checksum: inner.whole_object_checksum.clone(),
        }))
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> StorageResult<Bytes> {
        let inner = self.lock();
        let (b, _) = inner
            .objects
            .get(key.as_str())
            .ok_or_else(|| StorageError::NotFound {
                key: key.as_str().to_owned(),
            })?;
        let start = usize::try_from(range.offset)
            .unwrap_or(usize::MAX)
            .min(b.len());
        let end = usize::try_from(range.offset + range.len)
            .unwrap_or(usize::MAX)
            .min(b.len());
        Ok(b.slice(start..end))
    }

    async fn list(&self, prefix: &str, _page: Option<&OpaqueToken>) -> StorageResult<ListPage> {
        let mut inner = self.lock();
        inner.list_calls += 1;
        let mut keys: Vec<ObjectKey> = inner
            .objects
            .keys()
            .chain(inner.phantom_keys.iter())
            .filter(|k| k.starts_with(prefix))
            .map(|k| ObjectKey::new(k.clone()))
            .collect();
        keys.sort();
        keys.dedup();
        Ok(ListPage { keys, next: None })
    }

    async fn delete_object(&self, key: &ObjectKey, _guard: &VersionGuard) -> StorageResult<()> {
        let mut inner = self.lock();
        inner.deleted.push(key.as_str().to_owned());
        inner.objects.remove(key.as_str());
        Ok(())
    }

    async fn delete_system_object(&self, key: &ControlKey) -> StorageResult<()> {
        self.lock().objects.remove(key.as_key().as_str());
        Ok(())
    }
}

/// An in-memory [`TransferSessionStore`] that can be told to lose a write.
#[derive(Debug, Default)]
pub struct MemStore {
    inner: Mutex<MemStoreInner>,
}

#[derive(Debug, Default)]
struct MemStoreInner {
    saved: HashMap<i64, TransferSession>,
    saves: usize,
    /// How many of those arrived through `save_part` rather than `save`.
    part_saves: usize,
    /// Fail the Nth `save` (1-based) and every later one, modelling a process
    /// death: nothing after that point ever became durable.
    die_at_save: Option<usize>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Model a crash: from the Nth save onward, nothing is persisted.
    pub fn die_at_save(&self, n: usize) {
        self.inner.lock().expect("poisoned").die_at_save = Some(n);
    }

    /// Come back up: writes are durable again.
    pub fn revive(&self) {
        let mut i = self.inner.lock().expect("poisoned");
        i.die_at_save = None;
        i.saves = 0;
    }

    /// Durable writes attempted, by either route.
    pub fn saves(&self) -> usize {
        self.inner.lock().expect("poisoned").saves
    }

    /// How many of those were single-part checkpoints.
    pub fn part_saves(&self) -> usize {
        self.inner.lock().expect("poisoned").part_saves
    }
}

#[async_trait::async_trait]
impl TransferSessionStore for MemStore {
    async fn save(&self, session: &TransferSession) -> StorageResult<()> {
        let mut i = self.inner.lock().expect("poisoned");
        i.saves += 1;
        if let Some(n) = i.die_at_save
            && i.saves >= n
        {
            return Err(StorageError::Transient {
                op: "session save".into(),
                detail: "injected process death".into(),
            });
        }
        i.saved.insert(session.job_id.get(), session.clone());
        Ok(())
    }

    /// Counted, then handled exactly as `save` — this double has nothing
    /// cheaper, and the crash injection must not be able to tell the two routes
    /// apart or `die_at_save` would stop landing where the tests aim it.
    async fn save_part(&self, session: &TransferSession, _part_no: u32) -> StorageResult<()> {
        self.inner.lock().expect("poisoned").part_saves += 1;
        self.save(session).await
    }

    async fn load(&self, job_id: JobId) -> StorageResult<Option<TransferSession>> {
        Ok(self
            .inner
            .lock()
            .expect("poisoned")
            .saved
            .get(&job_id.get())
            .cloned())
    }
}

/// An in-memory [`SourceReader`] whose content can be mutated between attempts.
#[derive(Debug)]
pub struct MemSource {
    inner: Mutex<(Bytes, Timestamp)>,
}

impl MemSource {
    pub fn new(body: impl Into<Bytes>) -> Self {
        Self {
            inner: Mutex::new((body.into(), Timestamp::from_nanos(1_000))),
        }
    }

    pub fn body(&self) -> Bytes {
        self.inner.lock().expect("poisoned").0.clone()
    }

    pub fn blake3(&self) -> Blake3Hash {
        Blake3Hash::from_bytes(*blake3::hash(&self.body()).as_bytes())
    }

    /// Simulate PM-1: the user edits the file while it is being uploaded.
    pub fn mutate(&self, body: impl Into<Bytes>) {
        let mut i = self.inner.lock().expect("poisoned");
        i.0 = body.into();
        i.1 = Timestamp::from_nanos(i.1.as_nanos() + 1);
    }

    /// PM-1's sharper form: an in-place edit the cheap fingerprint cannot see.
    ///
    /// Same length, same mtime, same `fs_id`. That is what an editor which
    /// restores timestamps looks like, and what a write landing inside one
    /// mtime tick looks like on a coarse-granularity filesystem. `mutate` is
    /// the ordinary case the stat gate catches; this is the case it cannot,
    /// and it is why the driver proves the bytes it actually read hash to the
    /// planned value instead of trusting the stat.
    pub fn mutate_preserving_fingerprint(&self, body: impl Into<Bytes>) {
        let mut i = self.inner.lock().expect("poisoned");
        let body = body.into();
        assert_eq!(
            body.len(),
            i.0.len(),
            "a fingerprint-preserving edit must not change the length"
        );
        i.0 = body;
    }
}

#[async_trait::async_trait]
impl SourceReader for MemSource {
    async fn fingerprint(&self) -> StorageResult<SourceFingerprint> {
        let i = self.inner.lock().expect("poisoned");
        Ok(SourceFingerprint {
            size: i.0.len() as u64,
            mtime: i.1,
            fs_id: shepherd_core::FsId::new("vol-1:inode-7"),
        })
    }

    async fn read_range(&self, range: ByteRange) -> StorageResult<Bytes> {
        let i = self.inner.lock().expect("poisoned");
        let start = usize::try_from(range.offset)
            .unwrap_or(usize::MAX)
            .min(i.0.len());
        let end = usize::try_from(range.offset + range.len)
            .unwrap_or(usize::MAX)
            .min(i.0.len());
        Ok(i.0.slice(start..end))
    }
}
