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
