//! The S3-family adapter, on `aws-sdk-s3` (§4.5).
//!
//! # Why this SDK and not `opendal`
//!
//! OpenDAL's maintainers confirm its high-level `Writer` hides the upload id
//! and per-part state, so **parts cannot be resumed after a disconnection**
//! `[V: apache/opendal discussions#5875]`. spec:89 requires every transfer to
//! be multipart and resumable, so that is disqualifying rather than
//! inconvenient. `aws-sdk-s3` exposes `create_multipart_upload` →
//! `upload_part` (per-part ETag) → `complete_multipart_upload`, which is
//! exactly the shape [`crate::transfer_session`] persists and resumes against.
//!
//! `force_path_style(true)` plus a custom endpoint covers MinIO, R2, B2 and
//! GCS-interop.
//!
//! # This file is the only one in the crate that names an AWS type
//!
//! Everything above it is written against [`StorageAdapter`], which is what
//! lets the state machine and the replica chain be tested with no network. The
//! job here is narrow: translate, and **do not decide**. In particular this
//! module never concludes that content is correct — it hands back bytes and
//! sizes, and the only thing entitled to say "these are the right bytes" is
//! [`crate::adapter::verify_full_content`], which hashes them.
//!
//! # Error mapping is a safety concern, not plumbing
//!
//! [`StorageError::NoSuchUpload`] must be distinguishable, because it is the
//! one failure whose correct response is "abandon this provider session and
//! start a new attempt epoch" rather than "retry". Mapping it to a generic
//! error would make the daemon retry a part against a session the provider has
//! already forgotten, forever. Mapping is done on the S3 **error code string**
//! rather than on modeled variants because the codes are stable across the
//! operations that can raise them, while the modeled enums differ per
//! operation.

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{BucketVersioningStatus, CompletedMultipartUpload, CompletedPart};
use bytes::Bytes;
use serde::Serialize;
use shepherd_core::{ObjectKey, ObjectVersion};

use crate::adapter::{
    AdapterCapabilities, AttestationMode, ByteRange, ChecksumAlgorithm, ControlKey,
    CreatePrecondition, CreateReceipt, IncompleteUpload, ListPage, ListVisibility, ObjectChecksum,
    ObjectMeta, OpaqueToken, PartReceipt, StorageAdapter, StorageError, StorageResult,
    VersionGuard,
};

/// S3 minimum non-final part size.
const S3_MIN_PART: u64 = 5 * 1024 * 1024;
/// S3 maximum part size.
const S3_MAX_PART: u64 = 5 * 1024 * 1024 * 1024;
/// S3 maximum part number.
const S3_MAX_PARTS: u32 = 10_000;

/// Static credentials, for MinIO and for targets whose secrets Shepherd holds
/// in `shepherd-secrets` rather than in the ambient environment.
#[derive(Clone)]
pub struct StaticCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl std::fmt::Debug for StaticCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret, even in a panic message or a trace span.
        f.debug_struct("StaticCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// How to reach one S3-compatible bucket.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: String,
    /// Set for MinIO/R2/B2; `None` for real AWS.
    pub endpoint_url: Option<String>,
    pub region: Option<String>,
    /// MinIO and most compatibles need path style.
    pub force_path_style: bool,
    /// `None` uses the ambient credential chain.
    pub credentials: Option<StaticCredentials>,
    /// Request a **whole-object** checksum on every multipart upload.
    ///
    /// This is a Phase-2 upload-time decision that cannot be retrofitted
    /// without re-uploading every object, which is why it is a config rather
    /// than something the scrub path turns on later. Per the Phase-0b capacity
    /// model, the 2% of files large enough to be multipart hold 60.3% of the
    /// bytes, and their ETags are digest-of-digests, so without this the only
    /// integrity check available for them is a full read.
    ///
    /// **Opt-in, and deliberately not defaulted on.** Verified working against
    /// MinIO, but R2, B2 and the other S3-compatibles are unverified, and a
    /// provider that rejects the parameter fails *every* multipart upload to
    /// that target rather than degrading. Defaulting it on would trade a
    /// scrub-cost optimisation for a total outage on an untested provider.
    ///
    /// The cost of that caution is real and belongs in target registration:
    /// this cannot be retrofitted without re-uploading every object, so the
    /// registration path must probe the provider and set it **then**, not leave
    /// it to a later decision. `None` means the scrub path must read those
    /// objects back in full.
    pub multipart_checksum: Option<ChecksumAlgorithm>,
}

impl S3Config {
    /// A local MinIO bucket, as `tests/docker-compose.yml` brings it up.
    pub fn minio(bucket: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            endpoint_url: Some(endpoint.into()),
            region: Some("us-east-1".into()),
            force_path_style: true,
            credentials: None,
            multipart_checksum: None,
        }
    }
}

/// The S3-compatible [`StorageAdapter`].
#[derive(Debug)]
pub struct S3Adapter {
    client: aws_sdk_s3::Client,
    bucket: String,
    caps: AdapterCapabilities,
    multipart_checksum: Option<ChecksumAlgorithm>,
}

fn to_sdk_algorithm(a: ChecksumAlgorithm) -> aws_sdk_s3::types::ChecksumAlgorithm {
    match a {
        ChecksumAlgorithm::Crc32 => aws_sdk_s3::types::ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c => aws_sdk_s3::types::ChecksumAlgorithm::Crc32C,
        ChecksumAlgorithm::Crc64Nvme => aws_sdk_s3::types::ChecksumAlgorithm::Crc64Nvme,
    }
}

impl S3Adapter {
    pub async fn new(cfg: S3Config) -> StorageResult<Self> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest()).region(
            aws_config::Region::new(cfg.region.clone().unwrap_or_else(|| "us-east-1".into())),
        );
        if let Some(c) = &cfg.credentials {
            loader = loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                c.access_key_id.clone(),
                c.secret_access_key.clone(),
                None,
                None,
                "shepherd-static",
            ));
        }
        let shared = loader.load().await;

        let mut b =
            aws_sdk_s3::config::Builder::from(&shared).force_path_style(cfg.force_path_style);
        if let Some(url) = &cfg.endpoint_url {
            b = b.endpoint_url(url.clone());
        }

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(b.build()),
            bucket: cfg.bucket,
            multipart_checksum: cfg.multipart_checksum,
            caps: AdapterCapabilities {
                provider: "s3",
                // S3 has offered `If-None-Match: *` on PUT and
                // CompleteMultipartUpload since 2024, and MinIO implements it.
                // OQ-1 requires it to be used where offered, with failure
                // treated as a hard error.
                conditional_create: true,
                min_part_size: S3_MIN_PART,
                max_part_size: S3_MAX_PART,
                max_parts: S3_MAX_PARTS,
                // S3 LIST is strongly consistent. Drive and Graph are not, which
                // is why this is a per-adapter fact rather than an assumption
                // baked into the reader.
                list_visibility: ListVisibility::Strong,
            },
        })
    }

    /// Map an SDK error onto the variants callers branch on.
    fn map_err<E>(op: &str, key: &str, err: aws_sdk_s3::error::SdkError<E>) -> StorageError
    where
        E: ProvideErrorMetadata + std::fmt::Debug,
    {
        let code = err.code().unwrap_or_default().to_owned();
        let detail = err
            .message()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{err:?}"));
        match code.as_str() {
            // The one failure whose correct response is a new attempt epoch.
            "NoSuchUpload" => StorageError::NoSuchUpload {
                key: key.to_owned(),
            },
            "NoSuchKey" | "NotFound" | "404" => StorageError::NotFound {
                key: key.to_owned(),
            },
            "PreconditionFailed" | "ConditionalRequestConflict" => {
                StorageError::PreconditionFailed {
                    key: key.to_owned(),
                    detail,
                }
            }
            // Throttling and 5xx: retrying can plausibly succeed.
            "SlowDown"
            | "RequestTimeout"
            | "InternalError"
            | "ServiceUnavailable"
            | "RequestTimeTooSkewed" => StorageError::Transient {
                op: op.to_owned(),
                detail,
            },
            _ => {
                // A dispatch failure never reached the service, so it is a
                // transport problem and retryable.
                if matches!(
                    err,
                    aws_sdk_s3::error::SdkError::DispatchFailure(_)
                        | aws_sdk_s3::error::SdkError::TimeoutError(_)
                ) {
                    StorageError::Transient {
                        op: op.to_owned(),
                        detail,
                    }
                } else {
                    StorageError::Provider {
                        provider: "s3",
                        op: op.to_owned(),
                        detail: if code.is_empty() {
                            detail
                        } else {
                            format!("{code}: {detail}")
                        },
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl StorageAdapter for S3Adapter {
    fn capabilities(&self) -> &AdapterCapabilities {
        &self.caps
    }

    /// §4.10.2's rider, implemented: bucket versioning is **off by default**, so
    /// an ordinary bucket is mechanism B. This probes rather than assumes,
    /// because "silently landing on B while believing A is exactly how a safety
    /// claim decays into a slogan".
    async fn probe_attestation_mode(&self) -> StorageResult<AttestationMode> {
        let out = self
            .client
            .get_bucket_versioning()
            .bucket(&self.bucket)
            .send()
            .await;
        match out {
            Ok(v) if v.status() == Some(&BucketVersioningStatus::Enabled) => {
                Ok(AttestationMode::Version)
            }
            // Not versioned, or we are not allowed to ask. Either way the
            // honest answer is mechanism B: §4.9 commits the BLAKE3 into the
            // key, so Shepherd can still attest content itself. Never `None`
            // here — that would claim the target is destruction-ineligible when
            // content self-attestation demonstrably works.
            Ok(_) | Err(_) => Ok(AttestationMode::Content),
        }
    }

    async fn create(
        &self,
        key: &ObjectKey,
        body: Bytes,
        precondition: CreatePrecondition,
    ) -> StorageResult<CreateReceipt> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .body(ByteStream::from(body.to_vec()));
        if precondition == CreatePrecondition::IfAbsent {
            req = req.if_none_match("*");
        }
        let out = req
            .send()
            .await
            .map_err(|e| Self::map_err("put_object", key.as_str(), e))?;
        Ok(CreateReceipt {
            key: key.clone(),
            version: out.version_id().map(ObjectVersion::new),
            etag: out.e_tag().map(OpaqueToken::new),
        })
    }

    async fn create_multipart(&self, key: &ObjectKey) -> StorageResult<OpaqueToken> {
        let mut req = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key.as_str());
        // FULL_OBJECT, not COMPOSITE. A composite value is a digest-of-digests
        // over the part checksums and can never be compared against a checksum
        // of the bytes — which is precisely why a multipart ETag is useless for
        // scrub. Only CRC32/CRC32C/CRC64NVME support FULL_OBJECT; the SHA
        // algorithms are composite-only for multipart.
        if let Some(alg) = self.multipart_checksum {
            req = req
                .checksum_algorithm(to_sdk_algorithm(alg))
                .checksum_type(aws_sdk_s3::types::ChecksumType::FullObject);
        }
        let out = req
            .send()
            .await
            .map_err(|e| Self::map_err("create_multipart_upload", key.as_str(), e))?;
        out.upload_id()
            .map(OpaqueToken::new)
            .ok_or_else(|| StorageError::Provider {
                provider: "s3",
                op: "create_multipart_upload".into(),
                detail: "the service returned no upload id".into(),
            })
    }

    async fn upload_part(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
        part_no: u32,
        body: Bytes,
    ) -> StorageResult<PartReceipt> {
        let size = body.len() as u64;
        let mut req = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key.as_str())
            .upload_id(upload_id.as_opaque())
            .part_number(i32::try_from(part_no).unwrap_or(i32::MAX))
            .body(ByteStream::from(body.to_vec()));
        // The part checksum algorithm MUST match the one the session was
        // created with. Verified against MinIO, which accepts the session and
        // then rejects the first part:
        //
        //   InvalidArgument: (checksum missing, want "CRC64NVME", got "CRC32")
        //
        // The SDK otherwise defaults the part to CRC32, so omitting this makes
        // every whole-object upload fail at part 1 rather than at setup.
        if let Some(alg) = self.multipart_checksum {
            req = req.checksum_algorithm(to_sdk_algorithm(alg));
        }
        let out = req
            .send()
            .await
            .map_err(|e| Self::map_err("upload_part", key.as_str(), e))?;
        Ok(PartReceipt {
            part_no,
            size,
            // Opaque. Compared against a durable checkpoint, never parsed.
            etag: OpaqueToken::new(out.e_tag().unwrap_or_default()),
            checksum: out
                .checksum_crc64_nvme()
                .or_else(|| out.checksum_crc32_c())
                .or_else(|| out.checksum_crc32())
                .map(str::to_owned),
        })
    }

    /// Exhausts pagination — S3 pages `ListParts` at 1000, and a 50 GB object
    /// at 16 MiB parts is 3 200 parts. A first-page-only reconcile would
    /// re-send verified parts or complete with a truncated part list, and both
    /// are AC-2 failures.
    async fn list_parts(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
    ) -> StorageResult<Vec<PartReceipt>> {
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_parts()
                .bucket(&self.bucket)
                .key(key.as_str())
                .upload_id(upload_id.as_opaque());
            if let Some(m) = &marker {
                req = req.part_number_marker(m.clone());
            }
            let page = req
                .send()
                .await
                .map_err(|e| Self::map_err("list_parts", key.as_str(), e))?;

            for p in page.parts() {
                out.push(PartReceipt {
                    part_no: u32::try_from(p.part_number().unwrap_or_default()).unwrap_or_default(),
                    size: u64::try_from(p.size().unwrap_or_default()).unwrap_or_default(),
                    etag: OpaqueToken::new(p.e_tag().unwrap_or_default()),
                    checksum: p
                        .checksum_crc64_nvme()
                        .or_else(|| p.checksum_crc32_c())
                        .or_else(|| p.checksum_crc32())
                        .map(str::to_owned),
                });
            }

            if page.is_truncated().unwrap_or(false) {
                marker = page.next_part_number_marker().map(str::to_owned);
                if marker.is_none() {
                    // Truncated but no marker: refuse to silently return a
                    // partial list, which resume would read as "these parts do
                    // not exist".
                    return Err(StorageError::Provider {
                        provider: "s3",
                        op: "list_parts".into(),
                        detail: "response was truncated but carried no continuation marker".into(),
                    });
                }
            } else {
                break;
            }
        }
        out.sort_by_key(|p| p.part_no);
        Ok(out)
    }

    async fn complete_multipart(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
        parts: &[PartReceipt],
        precondition: CreatePrecondition,
    ) -> StorageResult<CreateReceipt> {
        let completed: Vec<CompletedPart> = parts
            .iter()
            .map(|p| {
                let mut b = CompletedPart::builder()
                    .part_number(i32::try_from(p.part_no).unwrap_or(i32::MAX))
                    .e_tag(p.etag.as_opaque());
                // Echo the part checksum back. Without it MinIO rejects the
                // completion with `InvalidPart` — the ETag alone is not enough
                // once the session was created with a checksum algorithm.
                if let (Some(c), Some(alg)) = (p.checksum.as_deref(), self.multipart_checksum) {
                    b = match alg {
                        ChecksumAlgorithm::Crc64Nvme => b.checksum_crc64_nvme(c),
                        ChecksumAlgorithm::Crc32c => b.checksum_crc32_c(c),
                        ChecksumAlgorithm::Crc32 => b.checksum_crc32(c),
                    };
                }
                b.build()
            })
            .collect();

        let mut req = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key.as_str())
            .upload_id(upload_id.as_opaque())
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(completed))
                    .build(),
            );
        if precondition == CreatePrecondition::IfAbsent {
            req = req.if_none_match("*");
        }
        let out = req
            .send()
            .await
            .map_err(|e| Self::map_err("complete_multipart_upload", key.as_str(), e))?;
        Ok(CreateReceipt {
            key: key.clone(),
            version: out.version_id().map(ObjectVersion::new),
            etag: out.e_tag().map(OpaqueToken::new),
        })
    }

    async fn abort_multipart(&self, key: &ObjectKey, upload_id: &OpaqueToken) -> StorageResult<()> {
        match self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key.as_str())
            .upload_id(upload_id.as_opaque())
            .send()
            .await
        {
            Ok(_) => Ok(()),
            // Already gone is the desired end state, not a failure.
            Err(e) => match Self::map_err("abort_multipart_upload", key.as_str(), e) {
                StorageError::NoSuchUpload { .. } => Ok(()),
                other => Err(other),
            },
        }
    }

    async fn list_incomplete_uploads(&self, prefix: &str) -> StorageResult<Vec<IncompleteUpload>> {
        let mut out = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut id_marker: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(k) = &key_marker {
                req = req.key_marker(k.clone());
            }
            if let Some(i) = &id_marker {
                req = req.upload_id_marker(i.clone());
            }
            let page = req
                .send()
                .await
                .map_err(|e| Self::map_err("list_multipart_uploads", prefix, e))?;

            for u in page.uploads() {
                if let (Some(k), Some(id)) = (u.key(), u.upload_id()) {
                    out.push(IncompleteUpload {
                        key: ObjectKey::new(k),
                        upload_id: OpaqueToken::new(id),
                    });
                }
            }
            if page.is_truncated().unwrap_or(false) {
                key_marker = page.next_key_marker().map(str::to_owned);
                id_marker = page.next_upload_id_marker().map(str::to_owned);
                if key_marker.is_none() && id_marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(out)
    }

    async fn head(&self, key: &ObjectKey) -> StorageResult<Option<ObjectMeta>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            // S3 omits every `x-amz-checksum-*` response field unless the
            // request opts in, so without this an object that *does* carry a
            // whole-object checksum reports none. Measured against a real
            // bucket, one multipart object, two HEADs:
            //
            //   mode unset   -> etag only
            //   mode ENABLED -> x-amz-checksum-crc64nvme: CnmyweQWB7U=
            //                   x-amz-checksum-type: FULL_OBJECT
            //
            // This was the whole of the negative result the capacity model
            // recorded against multipart checksums: the upload path had been
            // storing them correctly all along and the read path could not see
            // them. Costs nothing — HEAD is priced the same either way — and
            // omitting it sends scrub to re-read every multipart object in
            // full, which is the expensive answer reached from a header we
            // simply failed to send.
            .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
            .send()
            .await
        {
            Ok(o) => {
                // Only report a checksum the provider says covers the WHOLE
                // object. A composite value would never match a checksum of the
                // bytes, so surfacing it would make every multipart object look
                // corrupt on the first scrub.
                let whole_object =
                    o.checksum_type() == Some(&aws_sdk_s3::types::ChecksumType::FullObject);
                let checksum = [
                    (ChecksumAlgorithm::Crc64Nvme, o.checksum_crc64_nvme()),
                    (ChecksumAlgorithm::Crc32c, o.checksum_crc32_c()),
                    (ChecksumAlgorithm::Crc32, o.checksum_crc32()),
                ]
                .into_iter()
                .find_map(|(algorithm, v)| {
                    v.map(|value| ObjectChecksum {
                        algorithm,
                        value: value.to_owned(),
                        whole_object,
                    })
                });
                Ok(Some(ObjectMeta {
                    key: key.clone(),
                    size: u64::try_from(o.content_length().unwrap_or_default()).unwrap_or_default(),
                    version: o.version_id().map(ObjectVersion::new),
                    etag: o.e_tag().map(OpaqueToken::new),
                    whole_object_checksum: checksum,
                }))
            }
            // Absence is a legitimate answer to a HEAD, not an error — the
            // ambiguous-completion path asks exactly this question.
            Err(e) => match Self::map_err("head_object", key.as_str(), e) {
                StorageError::NotFound { .. } => Ok(None),
                other => Err(other),
            },
        }
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> StorageResult<Bytes> {
        if range.len == 0 {
            return Ok(Bytes::new());
        }
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .range(format!(
                "bytes={}-{}",
                range.offset,
                range.offset + range.len - 1
            ))
            .send()
            .await
            .map_err(|e| Self::map_err("get_object", key.as_str(), e))?;
        let body = out
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Transient {
                op: "get_object body".into(),
                detail: e.to_string(),
            })?;
        Ok(body.into_bytes())
    }

    async fn list(&self, prefix: &str, page: Option<&OpaqueToken>) -> StorageResult<ListPage> {
        let mut req = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix);
        if let Some(t) = page {
            req = req.continuation_token(t.as_opaque());
        }
        let out = req
            .send()
            .await
            .map_err(|e| Self::map_err("list_objects_v2", prefix, e))?;
        Ok(ListPage {
            keys: out
                .contents()
                .iter()
                .filter_map(|o| o.key().map(ObjectKey::new))
                .collect(),
            next: out.next_continuation_token().map(OpaqueToken::new),
        })
    }

    /// User data. Callable only from `shepherd-tier::destroy` (§4.1 rule 4).
    ///
    /// Version-scoped under mechanism A, so a discard cannot destroy a
    /// *replacement*. Under mechanism B the key is content-addressed, which is
    /// the guard: a replacement carrying different bytes belongs under a
    /// different key, so no writer following Shepherd's key discipline can
    /// produce the state this would otherwise need to defend against.
    async fn delete_object(&self, key: &ObjectKey, guard: &VersionGuard) -> StorageResult<()> {
        let mut req = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key.as_str());
        if let VersionGuard::Version(v) = guard {
            req = req.version_id(v.as_opaque());
        }
        req.send()
            .await
            .map_err(|e| Self::map_err("delete_object", key.as_str(), e))?;
        Ok(())
    }

    /// Control objects. Confined to `_shepherd/` by the [`ControlKey`]
    /// argument, and never counted by the discard breaker.
    ///
    /// Note that nothing in Phase 2 calls this: OQ-1 disables replica GC in v1
    /// (D-10), because a compactor working from a stale LIST can classify a
    /// segment as orphaned while an unseen newer pointer references it.
    async fn delete_system_object(&self, key: &ControlKey) -> StorageResult<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key.as_key().as_str())
            .send()
            .await
            .map_err(|e| Self::map_err("delete_system_object", key.as_key().as_str(), e))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The registration-time whole-object-checksum probe (E-5)
// ---------------------------------------------------------------------------

/// The three algorithms that can produce a **FULL_OBJECT** multipart checksum,
/// strongest first.
///
/// The SHA family is deliberately absent and its absence is load-bearing: for
/// multipart uploads SHA1/SHA256 are COMPOSITE-only — a digest-of-digests over
/// the part checksums, which can never be compared against a checksum of the
/// bytes. Adopting one would produce a value that looks like an integrity
/// check, is stored like one, and makes every multipart object appear corrupt
/// the first time scrub compares it.
pub const FULL_OBJECT_PREFERENCE: [ChecksumAlgorithm; 3] = [
    ChecksumAlgorithm::Crc64Nvme,
    ChecksumAlgorithm::Crc32c,
    ChecksumAlgorithm::Crc32,
];

/// Why one algorithm's round trip did not complete.
///
/// **The split is the entire point of this type.** E-5: "a false negative here
/// is silent, permanent, and indistinguishable from genuine non-support". A
/// timeout while probing CRC64NVME and a provider that genuinely rejects
/// CRC64NVME produce the same *shape* of failure and must not produce the same
/// *conclusion* — one is "this provider cannot do it", the other is "we do not
/// know", and recording the second as the first permanently strands every
/// object written through the target afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// The provider answered, and its answer was no. Evidence about the
    /// provider.
    Unsupported {
        /// Which call refused: `create_multipart`, `upload_part`,
        /// `complete_multipart` or `head`.
        step: &'static str,
        detail: String,
    },
    /// The probe never got an answer — a timeout, a dropped connection, a 5xx.
    /// Evidence about the network, and about nothing else.
    Unreachable { step: &'static str, detail: String },
}

/// What one algorithm's probe did.
///
/// `Serialize` and not `Deserialize`: `step` is a `&'static str`, and the only
/// consumer is a registration path that **writes** this record down beside the
/// target it produced. Reading it back is not a capability anything has asked
/// for, and adding it would mean owning those strings for no live reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
// Internally tagged, so a serialized attempt reads
// `{"algorithm": "...", "outcome": {"result": "rejected", "step": ..., "detail": ...}}`.
// `result` rather than the type's own name, because the field holding it is
// already called `outcome` and `outcome.outcome` reads like a bug.
#[serde(rename_all = "snake_case", tag = "result")]
pub enum AttemptOutcome {
    /// A genuine multipart upload completed and HEAD returned a whole-object
    /// checksum of this algorithm. `value` is the checksum the provider
    /// returned, kept because "record the outcome WITH its evidence rather than
    /// as a boolean" is E-5's explicit instruction.
    RoundTripped { value: String },
    /// The provider refused this algorithm, at this step, for this reason.
    Rejected { step: &'static str, detail: String },
    /// Not attempted: an earlier algorithm was already adopted.
    NotAttempted,
}

/// One algorithm's line in the probe record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeAttempt {
    pub algorithm: ChecksumAlgorithm,
    pub outcome: AttemptOutcome,
}

/// The record of a registration-time probe.
///
/// Deliberately not a `bool` and not a bare `Option<ChecksumAlgorithm>`. The
/// negative result — "this provider supports none of them" — is a claim that
/// costs $441/month against $0.68 on a 50 TB corpus (ADR 0b §3, 649x) and
/// cannot be revisited without re-uploading every object, so it has to arrive
/// with the per-algorithm reasons that produced it. A boolean would make a
/// wrong negative indistinguishable from a right one forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChecksumProbe {
    /// The algorithm to configure. `None` means the provider supports none of
    /// them and scrub must read multipart objects back in full — the expensive
    /// answer, never the wrong one.
    pub adopted: Option<ChecksumAlgorithm>,
    /// The endpoint actually reached. A probe that reports a negative without
    /// naming where it was pointed is indistinguishable from one that never
    /// left the emulator.
    pub endpoint: String,
    pub bucket: String,
    /// Every algorithm tried, in preference order, with what happened.
    pub attempts: Vec<ProbeAttempt>,
}

impl ChecksumProbe {
    /// A one-line human summary, for the registration log and the report.
    pub fn summary(&self) -> String {
        let head = match self.adopted {
            Some(a) => format!("adopted {}", a.as_str()),
            None => "adopted none: scrub must read multipart objects in full".to_string(),
        };
        let detail: Vec<String> = self
            .attempts
            .iter()
            .map(|a| match &a.outcome {
                AttemptOutcome::RoundTripped { value } => {
                    format!("{}=round-tripped({value})", a.algorithm.as_str())
                }
                AttemptOutcome::Rejected { step, detail } => {
                    format!("{}=rejected at {step}: {detail}", a.algorithm.as_str())
                }
                AttemptOutcome::NotAttempted => format!("{}=not attempted", a.algorithm.as_str()),
            })
            .collect();
        format!(
            "{head} against {} bucket `{}` [{}]",
            self.endpoint,
            self.bucket,
            detail.join("; ")
        )
    }
}

/// One algorithm's end-to-end round trip, as the probe needs it.
///
/// A trait so the *selection* — the ordering, and what each failure kind means
/// — is testable without a provider. The ordering is the part a plain
/// integration test cannot check: an integration test against a provider that
/// supports CRC64NVME never exercises the fallback at all, and one against a
/// provider that supports none never exercises adoption.
#[async_trait::async_trait]
pub(crate) trait ChecksumRoundTrip {
    /// Upload a genuine multipart object requesting `alg` as a FULL_OBJECT
    /// checksum and read the value back. `Ok` only if HEAD returned a
    /// whole-object checksum **of that algorithm**.
    async fn round_trip(&self, alg: ChecksumAlgorithm) -> Result<String, AttemptError>;
}

/// Try each algorithm in `order` and adopt the first that round-trips.
///
/// Returns `Err` — refusing to produce a record at all — the moment any attempt
/// is [`AttemptError::Unreachable`]. That is the fail-closed direction: a
/// registration that could not reach the provider must fail loudly rather than
/// persist "this provider supports nothing", because the second is permanent
/// and looks exactly like a correct measurement afterwards.
pub(crate) async fn adopt_first_round_trip<P>(
    prober: &P,
    order: &[ChecksumAlgorithm],
    endpoint: &str,
    bucket: &str,
) -> StorageResult<ChecksumProbe>
where
    P: ChecksumRoundTrip + Sync,
{
    let mut attempts = Vec::with_capacity(order.len());
    let mut adopted = None;

    for &alg in order {
        if adopted.is_some() {
            attempts.push(ProbeAttempt {
                algorithm: alg,
                outcome: AttemptOutcome::NotAttempted,
            });
            continue;
        }
        match prober.round_trip(alg).await {
            Ok(value) => {
                adopted = Some(alg);
                attempts.push(ProbeAttempt {
                    algorithm: alg,
                    outcome: AttemptOutcome::RoundTripped { value },
                });
            }
            Err(AttemptError::Unsupported { step, detail }) => attempts.push(ProbeAttempt {
                algorithm: alg,
                outcome: AttemptOutcome::Rejected { step, detail },
            }),
            Err(AttemptError::Unreachable { step, detail }) => {
                return Err(StorageError::Transient {
                    op: format!("probing {} at {step}", alg.as_str()),
                    detail: format!(
                        "{detail} — the provider was not reached, so this run proves nothing \
                         about whether it supports whole-object checksums. Registering a target \
                         on this result would record `unsupported` permanently for every object \
                         written through it."
                    ),
                });
            }
        }
    }

    Ok(ChecksumProbe {
        adopted,
        endpoint: endpoint.to_string(),
        bucket: bucket.to_string(),
        attempts,
    })
}

/// The probe object's key.
///
/// Under `_shepherd/`, so it is a [`ControlKey`] and can be cleaned up with
/// `delete_system_object`. `delete_object` is off limits here by §4.1 rule 4 —
/// `shepherd-tier::destroy` is its sole caller — and that constraint is a
/// feature rather than an obstacle: a registration probe has no business being
/// able to reach the verb that destroys user data.
fn probe_key(alg: ChecksumAlgorithm) -> ControlKey {
    ControlKey::under(format!("probe/checksum-{}", alg.as_str().to_lowercase()))
}

/// One S3 target, probed one algorithm at a time through the **real** upload
/// path.
struct S3RoundTrip {
    cfg: S3Config,
}

#[async_trait::async_trait]
impl ChecksumRoundTrip for S3RoundTrip {
    async fn round_trip(&self, alg: ChecksumAlgorithm) -> Result<String, AttemptError> {
        // A fresh adapter per algorithm, because `multipart_checksum` is fixed
        // at construction and `create_multipart`/`upload_part` read it from
        // there. This is deliberate: the probe then exercises the exact code
        // path production uploads take, rather than a parallel implementation
        // of it that could drift.
        let cfg = S3Config {
            multipart_checksum: Some(alg),
            ..self.cfg.clone()
        };
        let adapter = S3Adapter::new(cfg).await.map_err(|e| classify("new", e))?;

        let key = probe_key(alg);
        let object = key.as_key().clone();

        let upload = adapter
            .create_multipart(&object)
            .await
            .map_err(|e| classify("create_multipart", e))?;

        // Genuinely multipart: two parts at the S3 minimum. A single-part
        // upload would return an ETag that *is* a content digest, so it would
        // report success for the one case the whole exercise does not care
        // about.
        let mut receipts = Vec::new();
        for part_no in 1..=2u32 {
            let body = Bytes::from(vec![part_no as u8; S3_MIN_PART as usize]);
            match adapter.upload_part(&object, &upload, part_no, body).await {
                Ok(r) => receipts.push(r),
                Err(e) => {
                    let _ = adapter.abort_multipart(&object, &upload).await;
                    return Err(classify("upload_part", e));
                }
            }
        }

        // `IfAbsent` would fail on the second registration against the same
        // bucket, since the probe key is fixed per algorithm. This object is a
        // scratch control object whose bytes carry no meaning, which is the one
        // case where overwrite is not a lost fact.
        if let Err(e) = adapter
            .complete_multipart(
                &object,
                &upload,
                &receipts,
                CreatePrecondition::Unconditional,
            )
            .await
        {
            let _ = adapter.abort_multipart(&object, &upload).await;
            return Err(classify("complete_multipart", e));
        }

        let head = adapter.head(&object).await.map_err(|e| classify("head", e));
        // Clean up whatever the outcome. A failure to delete is not a probe
        // failure — it leaves one 10 MiB control object behind, which is a
        // storage cost and not a correctness one.
        let _ = adapter.delete_system_object(&key).await;
        let head = head?;

        // Read from HEAD, never from `GetObjectAttributes`: MinIO omits
        // `ChecksumType` there while reporting it correctly on HEAD, so the
        // attributes call produces a false negative on a provider that
        // supports the feature. Recorded in E-5 from handling the API directly.
        let checksum = head.and_then(|m| m.whole_object_checksum).ok_or_else(|| {
            AttemptError::Unsupported {
                step: "head",
                detail: "the object completed but HEAD returned no whole-object checksum".into(),
            }
        })?;

        if !checksum.whole_object {
            return Err(AttemptError::Unsupported {
                step: "head",
                detail: format!(
                    "HEAD returned a {} checksum that is COMPOSITE, not FULL_OBJECT — a \
                     digest-of-digests can never be compared against a checksum of the bytes",
                    checksum.algorithm.as_str()
                ),
            });
        }
        if checksum.algorithm != alg {
            return Err(AttemptError::Unsupported {
                step: "head",
                detail: format!(
                    "asked for {} and the provider stored {} — adopting the request rather than \
                     the answer is how a probe reports support the provider never gave",
                    alg.as_str(),
                    checksum.algorithm.as_str()
                ),
            });
        }
        Ok(checksum.value)
    }
}

/// Which side of the [`AttemptError`] split a storage failure lands on.
///
/// [`StorageError::Transient`] is the crate's own "this never reached the
/// service" classification — `map_err` puts dispatch failures, timeouts and
/// 5xx there. Everything else is the provider answering, which is evidence.
fn classify(step: &'static str, e: StorageError) -> AttemptError {
    match e {
        StorageError::Transient { detail, .. } => AttemptError::Unreachable { step, detail },
        other => AttemptError::Unsupported {
            step,
            detail: other.to_string(),
        },
    }
}

/// **Probe a bucket for whole-object multipart checksum support, at
/// registration time.**
///
/// This is the producer for [`S3Config::multipart_checksum`] that E-5 records
/// as owed. The field's own doc has always said the value "must be probed at
/// registration" because "a checksum not requested at upload cannot be
/// retrofitted without re-uploading the object" — this is that probe.
///
/// # What it costs to skip
///
/// Measured, not estimated (ADR 0b §3): scrub over a 50 TB corpus costs
/// **$441/month** with no whole-object checksum against **$0.68** with one —
/// 649x — because the 2% of files large enough to be multipart hold 60.3% of
/// the bytes and their ETags are digest-of-digests, so the only integrity check
/// left for them is a full read. The setting is **irreversible per object**: an
/// object already uploaded without the checksum keeps the expensive
/// configuration for its lifetime.
///
/// # Failure directions, which are not symmetric
///
/// * `Ok(probe)` with `adopted: None` — the provider answered and supports none
///   of the three. Legitimate, and the R2/B2 case this cannot guess at. Scrub
///   degrades to full reads: expensive, never wrong.
/// * `Err(_)` — the provider was never reached. **Not** a statement about the
///   provider, and a caller must not persist it as one.
///
/// The probe leaves one ~10 MiB control object per attempted algorithm under
/// `_shepherd/probe/` while it runs and deletes it afterwards.
pub async fn probe_multipart_checksum(cfg: &S3Config) -> StorageResult<ChecksumProbe> {
    let endpoint = cfg
        .endpoint_url
        .clone()
        .unwrap_or_else(|| "aws s3 (default endpoint)".to_string());
    let bucket = cfg.bucket.clone();
    let prober = S3RoundTrip { cfg: cfg.clone() };
    adopt_first_round_trip(&prober, &FULL_OBJECT_PREFERENCE, &endpoint, &bucket).await
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A scripted provider: what each algorithm does, and what was asked.
    struct Fake {
        script: BTreeMap<&'static str, Result<String, AttemptError>>,
        asked: Mutex<Vec<&'static str>>,
    }

    impl Fake {
        fn new(script: &[(&'static str, Result<String, AttemptError>)]) -> Self {
            Self {
                script: script.iter().cloned().collect(),
                asked: Mutex::new(Vec::new()),
            }
        }
        fn asked(&self) -> Vec<&'static str> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl ChecksumRoundTrip for Fake {
        async fn round_trip(&self, alg: ChecksumAlgorithm) -> Result<String, AttemptError> {
            self.asked.lock().unwrap().push(alg.as_str());
            self.script
                .get(alg.as_str())
                .cloned()
                .unwrap_or(Err(AttemptError::Unsupported {
                    step: "create_multipart",
                    detail: "not in script".into(),
                }))
        }
    }

    fn unsupported(detail: &str) -> Result<String, AttemptError> {
        Err(AttemptError::Unsupported {
            step: "create_multipart",
            detail: detail.into(),
        })
    }

    fn run<P: ChecksumRoundTrip + Sync>(p: &P) -> StorageResult<ChecksumProbe> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(adopt_first_round_trip(
                p,
                &FULL_OBJECT_PREFERENCE,
                "http://probe.invalid",
                "b",
            ))
    }

    /// The preference order is the whole design, so it is asserted rather than
    /// left to the constant's declaration order.
    #[test]
    fn the_preference_order_is_crc64_then_crc32c_then_crc32() {
        assert_eq!(
            FULL_OBJECT_PREFERENCE.map(|a| a.as_str()),
            ["CRC64NVME", "CRC32C", "CRC32"]
        );
    }

    #[test]
    fn the_first_algorithm_that_round_trips_is_adopted_and_the_rest_are_not_tried() {
        let f = Fake::new(&[("CRC64NVME", Ok("CnmyweQWB7U=".into()))]);
        let p = run(&f).unwrap();
        assert_eq!(p.adopted, Some(ChecksumAlgorithm::Crc64Nvme));
        assert_eq!(
            f.asked(),
            ["CRC64NVME"],
            "a provider that answered on the first algorithm must not be billed for two more \
             10 MiB uploads"
        );
        // The evidence, not merely the verdict.
        assert_eq!(
            p.attempts[0].outcome,
            AttemptOutcome::RoundTripped {
                value: "CnmyweQWB7U=".into()
            }
        );
        assert_eq!(p.attempts[1].outcome, AttemptOutcome::NotAttempted);
    }

    /// The fallback leg. An integration test against any single provider
    /// exercises exactly one path through this function; only a scripted one
    /// reaches the middle.
    #[test]
    fn a_provider_that_refuses_crc64_falls_through_to_crc32c() {
        let f = Fake::new(&[
            (
                "CRC64NVME",
                unsupported("InvalidRequest: unknown algorithm"),
            ),
            ("CRC32C", Ok("72M33w==".into())),
        ]);
        let p = run(&f).unwrap();
        assert_eq!(p.adopted, Some(ChecksumAlgorithm::Crc32c));
        assert_eq!(f.asked(), ["CRC64NVME", "CRC32C"]);
        // The refusal is kept with its reason. A caller looking at a CRC32C
        // target later can see it was a fallback and why.
        assert!(
            matches!(&p.attempts[0].outcome, AttemptOutcome::Rejected { detail, .. }
                     if detail.contains("unknown algorithm")),
            "{:?}",
            p.attempts[0]
        );
    }

    #[test]
    fn a_provider_that_refuses_all_three_adopts_none_and_says_why_for_each() {
        let f = Fake::new(&[
            ("CRC64NVME", unsupported("no crc64")),
            ("CRC32C", unsupported("no crc32c")),
            ("CRC32", unsupported("no crc32")),
        ]);
        let p = run(&f).unwrap();
        assert_eq!(p.adopted, None);
        assert_eq!(f.asked(), ["CRC64NVME", "CRC32C", "CRC32"]);
        assert_eq!(p.attempts.len(), 3);
        for a in &p.attempts {
            assert!(
                matches!(&a.outcome, AttemptOutcome::Rejected { .. }),
                "a negative must carry the reason for EVERY algorithm, or it is a boolean \
                 wearing a struct: {a:?}"
            );
        }
        // And it names where it was pointed, so the negative is reproducible.
        assert!(
            p.summary().contains("http://probe.invalid"),
            "{}",
            p.summary()
        );
    }

    /// **The load-bearing case.** E-5: a false negative here is silent,
    /// permanent, and indistinguishable from genuine non-support.
    #[test]
    fn an_unreachable_provider_is_an_error_and_never_a_negative_result() {
        let f = Fake::new(&[(
            "CRC64NVME",
            Err(AttemptError::Unreachable {
                step: "create_multipart",
                detail: "connection reset".into(),
            }),
        )]);
        let err = run(&f).unwrap_err();
        assert!(
            matches!(err, StorageError::Transient { .. }),
            "an unreachable provider must be retryable, not a verdict: {err:?}"
        );
        assert!(
            err.to_string().contains("proves nothing"),
            "the error must say why it is not a negative result: {err}"
        );
        // It stopped rather than continuing to "measure" an unreachable host.
        assert_eq!(f.asked(), ["CRC64NVME"]);
    }

    /// The paired non-zero for the test above: the same failure text, arriving
    /// as a provider answer rather than a transport failure, IS a negative
    /// result. Without this pair, `an_unreachable_provider_...` would pass on
    /// an implementation that errored on every failure whatsoever.
    #[test]
    fn the_same_step_failing_as_a_provider_answer_is_a_negative_not_an_error() {
        let f = Fake::new(&[
            ("CRC64NVME", unsupported("connection reset")),
            ("CRC32C", unsupported("connection reset")),
            ("CRC32", unsupported("connection reset")),
        ]);
        let p = run(&f).expect("a provider answer is a result, not an error");
        assert_eq!(p.adopted, None);
    }

    /// The probe writes under `_shepherd/`, which is what makes cleanup
    /// possible without `delete_object` — whose sole caller is
    /// `shepherd-tier::destroy` (§4.1 rule 4).
    #[test]
    fn the_probe_object_is_a_control_object() {
        for alg in FULL_OBJECT_PREFERENCE {
            let k = probe_key(alg);
            assert!(
                k.as_key()
                    .as_str()
                    .starts_with(shepherd_core::CONTROL_PREFIX),
                "{}",
                k.as_key().as_str()
            );
            assert!(ControlKey::new(k.as_key().clone()).is_some());
        }
        // Distinct per algorithm: a shared key would make a second algorithm's
        // HEAD read the first one's object.
        let keys: std::collections::BTreeSet<String> = FULL_OBJECT_PREFERENCE
            .iter()
            .map(|a| probe_key(*a).as_key().as_str().to_string())
            .collect();
        assert_eq!(keys.len(), 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_match_the_s3_limits_the_part_planner_assumes() {
        // Not a tautology: `PartPlan` grows the part size against these
        // numbers, so a wrong constant here silently produces objects S3
        // refuses at completion time.
        assert_eq!(S3_MIN_PART, 5 * 1024 * 1024);
        assert_eq!(S3_MAX_PARTS, 10_000);
        let plan =
            crate::multipart::PartPlan::new(50 * 1024 * 1024 * 1024, &caps(), 16 * 1024 * 1024)
                .expect("50 GB must be plannable on S3");
        assert!(plan.part_count <= S3_MAX_PARTS);
    }

    fn caps() -> AdapterCapabilities {
        AdapterCapabilities {
            provider: "s3",
            conditional_create: true,
            min_part_size: S3_MIN_PART,
            max_part_size: S3_MAX_PART,
            max_parts: S3_MAX_PARTS,
            list_visibility: ListVisibility::Strong,
        }
    }

    #[test]
    fn static_credentials_never_render_their_secret() {
        let c = StaticCredentials {
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: "super-secret-value".into(),
        };
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(rendered.contains("AKIAEXAMPLE"));
    }

    #[test]
    fn the_minio_preset_uses_path_style() {
        let c = S3Config::minio("shepherd-test", "http://127.0.0.1:9000");
        assert!(
            c.force_path_style,
            "MinIO does not serve virtual-host-style buckets by default"
        );
        assert_eq!(c.endpoint_url.as_deref(), Some("http://127.0.0.1:9000"));
    }
}
