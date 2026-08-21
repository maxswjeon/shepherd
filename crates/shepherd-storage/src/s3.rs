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
        // Destructured rather than read field-by-field. `new` takes `cfg` by
        // value and is the last owner of it, so every field can be moved; the
        // borrow-then-clone shape this replaced was copying strings it was
        // about to drop. It matters most for `credentials`: cloning left a
        // second copy of the secret access key on the heap for the whole of
        // `new`, including across the `load().await`.
        let S3Config {
            bucket,
            endpoint_url,
            region,
            force_path_style,
            credentials,
            multipart_checksum,
        } = cfg;

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest()).region(
            aws_config::Region::new(region.unwrap_or_else(|| "us-east-1".into())),
        );
        if let Some(c) = credentials {
            loader = loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                c.access_key_id,
                c.secret_access_key,
                None,
                None,
                "shepherd-static",
            ));
        }
        let shared = loader.load().await;

        let mut b = aws_sdk_s3::config::Builder::from(&shared).force_path_style(force_path_style);
        if let Some(url) = endpoint_url {
            b = b.endpoint_url(url);
        }

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(b.build()),
            bucket,
            multipart_checksum,
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
            // A definite "not enabled" is mechanism B, and that is an honest
            // answer: §4.9 commits the BLAKE3 into the key, so Shepherd can
            // still attest content itself. Never `None` here — that would claim
            // the target is destruction-ineligible when content
            // self-attestation demonstrably works.
            Ok(_) => Ok(AttestationMode::Content),
            // A FAILED probe is not an answer, and treating it as one is the
            // decay this function's own comment warns about. Lacking
            // `s3:GetBucketVersioning` on a bucket that IS versioned used to
            // land on `Content` — after which `verify_upload` omits the version
            // it could have pinned and the closing check falls back to
            // existence and size, so a same-sized replacement written after
            // verification authorises unlinking the local copy. The weaker
            // mechanism was chosen by an unanswered question rather than by the
            // bucket.
            Err(e) => Err(StorageError::Provider {
                provider: self.capabilities().provider,
                op: "probe_attestation_mode".into(),
                detail: format!(
                    "could not read the bucket's versioning state, so this build cannot tell \
                     whether the target attests by version or by content — and guessing \
                     content would silently take the weaker one. Grant \
                     `s3:GetBucketVersioning` on `{}`: {e}",
                    self.bucket
                ),
            }),
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
            // `from(body)`, not `from(body.to_vec())`. `Bytes` is refcounted and
            // `impl From<Bytes> for ByteStream` is documented as *the* retryable
            // constructor, so the copy the `to_vec` made bought nothing.
            .body(ByteStream::from(body));
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
            // See `create`. This is the hot one: `to_vec` here deep-copied the
            // whole part body — 16 MiB at the default part size — on every part
            // AND on every SDK-internal retry of it, which is precisely what
            // taking `Bytes` was supposed to avoid.
            .body(ByteStream::from(body));
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
        // Every marker this listing has already requested — see the cycle
        // refusal below.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            let mut req = self
                .client
                .list_parts()
                .bucket(&self.bucket)
                .key(key.as_str())
                .upload_id(upload_id.as_opaque());
            // `take`: the marker is consumed by exactly this request, and the
            // truncated branch below always writes the next one back.
            let requested = marker.take();
            let _ = &requested;
            if let Some(m) = requested.clone() {
                req = req.part_number_marker(m);
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
                let next = page.next_part_number_marker().map(str::to_owned);
                let Some(next) = next else {
                    // Truncated but no marker: refuse to silently return a
                    // partial list, which resume would read as "these parts do
                    // not exist".
                    return Err(StorageError::Provider {
                        provider: "s3",
                        op: "list_parts".into(),
                        detail: "response was truncated but carried no continuation marker".into(),
                    });
                };
                // A marker that does not ADVANCE is the same refusal wearing a
                // different shape. The adjacent case above is caught because
                // the marker is absent; this one hands back the marker just
                // requested, so the loop re-issues an identical request,
                // appends the same receipts again, and never terminates —
                // resume never leaves reconciliation and the daemon grows
                // until it is killed. Bounded by the marker having to move,
                // rather than by an iteration cap, because a cap would also
                // truncate a legitimately long listing.
                // EVERY marker seen, not just the previous one: an endpoint
                // that alternates A -> B -> A never repeats its immediate
                // predecessor and would page forever.
                if !seen.insert(next.clone()) {
                    return Err(StorageError::Provider {
                        provider: "s3",
                        op: "list_parts".into(),
                        detail: format!(
                            "response was truncated and returned a continuation marker \
                             already used on this listing ({next}); paging is cycling rather \
                             than advancing"
                        ),
                    });
                }
                marker = Some(next);
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
        // Every marker pair this listing has already requested — see the cycle
        // refusal below.
        let mut seen: std::collections::HashSet<(Option<String>, Option<String>)> =
            std::collections::HashSet::new();
        loop {
            let mut req = self
                .client
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .prefix(prefix);
            // `take`, as in `list_parts`: consumed by this request, and the
            // truncated branch below writes both markers back unconditionally.
            // Kept as `requested_*` so that branch can tell an advancing marker
            // pair from one the provider handed straight back.
            let (requested_key, requested_id) = (key_marker.take(), id_marker.take());
            let _ = (&requested_key, &requested_id);
            if let Some(k) = requested_key.clone() {
                req = req.key_marker(k);
            }
            if let Some(i) = requested_id.clone() {
                req = req.upload_id_marker(i);
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
                let (next_key, next_id) = (
                    page.next_key_marker().map(str::to_owned),
                    page.next_upload_id_marker().map(str::to_owned),
                );
                // The same refusal `list_parts` makes, for the same reason: a
                // marker pair that does not ADVANCE re-issues an identical
                // request forever, appending the same uploads each time. Not
                // flagged by review here — this is the sibling of the loop that
                // was, and one function over is exactly where the missing-marker
                // case had been missing too.
                // EVERY pair seen, not just the previous one. An endpoint that
                // alternates — A returns B, B returns A — never repeats its
                // immediate predecessor, so an equality check against the last
                // request walks that cycle forever, appending the same pages.
                // A set costs one allocation per page against a listing that is
                // already one network round trip per page.
                if !seen.insert((next_key.clone(), next_id.clone())) {
                    return Err(StorageError::Provider {
                        provider: "s3",
                        op: "list_multipart_uploads".into(),
                        detail: "response was truncated and returned continuation markers \
                                 already used on this listing; paging is cycling rather than \
                                 advancing"
                            .into(),
                    });
                }
                key_marker = next_key;
                id_marker = next_id;
                if key_marker.is_none() && id_marker.is_none() {
                    // Truncated but no marker, refused for the same reason
                    // `list_parts` refuses it: the page cannot be continued, so
                    // it cannot be reported as the whole list. This used to
                    // `break` and return the partial page as exhaustive, which
                    // is worse here than there — `adopt_or_reap` aborts the
                    // orphans it was told about and then creates a new session,
                    // so the undiscovered multiparts keep accruing storage cost
                    // with nothing left to report them. One malformed response,
                    // two readings, is the drift this refusal closes.
                    return Err(StorageError::Provider {
                        provider: "s3",
                        op: "list_multipart_uploads".into(),
                        detail: "response was truncated but carried no continuation marker".into(),
                    });
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

    async fn get_range_versioned(
        &self,
        key: &ObjectKey,
        version: &ObjectVersion,
        range: ByteRange,
    ) -> StorageResult<Bytes> {
        // `version_id`, which is what makes this a read of a VERSION rather
        // than of whatever is current. See the trait docs for why verification
        // cannot use the mutable key.
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .version_id(version.as_opaque())
            .range(format!(
                "bytes={}-{}",
                range.offset,
                range.offset + range.len - 1
            ))
            .send()
            .await
            .map_err(|e| Self::map_err("get_range_versioned", key.as_str(), e))?;
        let body = out
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Transient {
                op: "get_range_versioned".into(),
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
        list_page(
            out.is_truncated().unwrap_or(false),
            page.map(OpaqueToken::as_opaque),
            out.next_continuation_token(),
            out.contents()
                .iter()
                .filter_map(|o| o.key().map(ObjectKey::new))
                .collect(),
        )
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
    /// The provider answered, and its answer was about something other than the
    /// checksum algorithm: the credential, the permission, or the bucket.
    ///
    /// The third direction, and the one whose absence made `Unsupported` a
    /// dumping ground. `AccessDenied` is a complete, non-transient, perfectly
    /// well-formed provider answer — it is simply not an answer to the question
    /// asked, and folding it into `Unsupported` lets a bucket nobody can write
    /// to be registered as one that merely lacks CRC64NVME.
    Fatal { step: &'static str, detail: String },
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
            Err(AttemptError::Fatal { step, detail }) => {
                return Err(StorageError::Provider {
                    provider: "s3",
                    op: format!("probing {} at {step}", alg.as_str()),
                    detail: format!(
                        "{detail} — the provider answered, but about authentication, \
                         authorization or the bucket itself, not about checksum support. This \
                         target is unusable as configured; it is not a target that lacks \
                         whole-object checksums. Registering on this result would persist \
                         `adopted: none` as though it had been measured, and that answer is \
                         irreversible per object."
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

/// The probe object's key, unique to one invocation.
///
/// Under `_shepherd/`, so it is a [`ControlKey`] and can be cleaned up with
/// `delete_system_object`. `delete_object` is off limits here by §4.1 rule 4 —
/// `shepherd-tier::destroy` is its sole caller — and that constraint is a
/// feature rather than an obstacle: a registration probe has no business being
/// able to reach the verb that destroys user data.
///
/// # Why the nonce
///
/// The key used to be a pure function of the algorithm, so every concurrent
/// `target.add` against one bucket wrote and deleted **the same object**. One
/// probe's cleanup `DELETE` landing between another's `complete_multipart` and
/// its `HEAD` makes the second read a missing object — and a missing checksum
/// reads as non-support here, which `target.add` persists as `adopted: none`.
/// A transient race must not mint a durable claim about a provider's
/// capabilities; that is the same argument that stopped an auth failure being
/// recorded as non-support. Observed against real MinIO, which supports
/// CRC64NVME, being recorded as rejecting it.
///
/// Same discipline as `shepherd-catalog`'s filesystem probes
/// (`identity::unique_stem`, `atime::probe_atime_advance`): a per-invocation
/// name, and delete only what this invocation created.
/// Where every checksum probe's objects and uploads live.
///
/// One place, so the sweep and the key builder cannot disagree about what the
/// sweep is allowed to delete.
const PROBE_PREFIX: &str = "_shepherd/probe/";

/// How old a probe artifact must be before the sweep may reap it.
///
/// A probe is a handful of round trips; anything still in flight is seconds
/// old. This is the margin that keeps a CONCURRENT registration's artifacts out
/// of the sweep's reach — two `target.add` calls against one bucket run on
/// separate connection threads with no bucket-level serialization, so without
/// it one aborts the other's upload and deletes its object just before the
/// HEAD, and a healthy provider looks broken.
const PROBE_REAP_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);

/// Whether a probe key is old enough to reap.
///
/// The nonce is `{pid}-{nanos}-{seq}`, so the artifact carries its own start
/// time and the sweep needs no provider timestamps — which is the point, since
/// `list` returns keys and nothing else. A key this cannot parse is LEFT: an
/// unrecognised name under this prefix is not one this sweep put there, and
/// deleting what it does not understand is how a tidy-up becomes a data loss.
fn probe_is_stale(key: &str, now_nanos: u128) -> bool {
    let Some(nonce) = key.rsplit('-').nth(1) else {
        return false;
    };
    let Ok(started) = nonce.parse::<u128>() else {
        return false;
    };
    now_nanos.saturating_sub(started) > PROBE_REAP_AFTER.as_nanos()
}

/// Abort and delete whatever earlier probes left under the probe prefix.
///
/// Best-effort by construction: this is tidying, and a provider that will not
/// list or will not abort must not turn a registration into a failure. What it
/// must not do is stay silent — a sweep that never works is a leak nobody sees,
/// so every refusal is logged with the key it could not reap.
///
/// Uploads first. An incomplete multipart holds allocated parts and bills for
/// them; a finished probe object is 10 MiB. Both are worth reclaiming, and the
/// first is worth more.
async fn sweep_probe_leftovers(adapter: &S3Adapter) {
    let prefix = PROBE_PREFIX;
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    match adapter.list_incomplete_uploads(prefix).await {
        Ok(uploads) => {
            for u in uploads {
                // Old enough to be nobody's live probe. Two registrations
                // against one bucket run concurrently on separate connection
                // threads, and aborting the other one's upload makes a healthy
                // provider look broken.
                if !probe_is_stale(u.key.as_str(), now_nanos) {
                    continue;
                }
                if let Err(e) = adapter.abort_multipart(&u.key, &u.upload_id).await {
                    tracing::warn!(
                        key = u.key.as_str(),
                        error = %e,
                        "could not abort a probe upload left by an earlier run; its parts \
                         stay allocated"
                    );
                }
            }
        }
        Err(e) => tracing::warn!(
            prefix,
            error = %e,
            "could not list probe uploads to reap; earlier runs' parts may still be allocated"
        ),
    }

    let mut page: Option<OpaqueToken> = None;
    // Cycles, not just immediate echoes: `list_page` catches a token handed
    // straight back, and an alternating provider needs the caller's memory.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        match adapter.list(prefix, page.as_ref()).await {
            Ok(listing) => {
                for key in &listing.keys {
                    // `delete_system_object`, never `delete_object`: §4.1 rule 4
                    // makes `shepherd-tier::destroy` the sole caller of the
                    // latter, and this is a control object rather than a user's
                    // bytes. `ControlKey::new` returning `None` would mean the
                    // provider listed something outside the prefix it was
                    // asked for, which is not ours to delete.
                    let Some(control) = ControlKey::new(key.clone()) else {
                        continue;
                    };
                    // Same age gate as the uploads above: a concurrent probe's
                    // object deleted just before its own HEAD fails a
                    // registration that had nothing wrong with it.
                    if !probe_is_stale(key.as_str(), now_nanos) {
                        continue;
                    }
                    if let Err(e) = adapter.delete_system_object(&control).await {
                        tracing::warn!(
                            key = key.as_str(),
                            error = %e,
                            "could not delete a probe object left by an earlier run"
                        );
                    }
                }
                match listing.next {
                    Some(token) => {
                        if !seen.insert(token.as_opaque().to_owned()) {
                            tracing::warn!(
                                prefix,
                                "the provider is cycling its continuation tokens; stopping \
                                 the probe sweep rather than paging forever"
                            );
                            break;
                        }
                        page = Some(token);
                    }
                    None => break,
                }
            }
            Err(e) => {
                tracing::warn!(
                    prefix,
                    error = %e,
                    "could not list probe objects to reap; earlier runs' objects may remain"
                );
                break;
            }
        }
    }
}

fn probe_key(alg: ChecksumAlgorithm, nonce: &str) -> ControlKey {
    ControlKey::under(format!(
        "probe/checksum-{}-{nonce}",
        alg.as_str().to_lowercase()
    ))
}

/// `{pid}-{nanos}-{seq}`: unique per process, per call, and per algorithm.
///
/// `identity::unique_stem` uses `{pid}-{nanos}` and leans on `create_new`
/// (`O_CREAT|O_EXCL`) for the guarantee. There is no `O_EXCL` on this side —
/// `IfAbsent` would tie the *checksum* probe to a provider's *conditional
/// create* support, and this probe exists to measure arbitrary
/// S3-compatibles — so the name has to carry the guarantee alone, and the
/// counter turns "two calls will not land on the same nanosecond" from a
/// probability into a fact within a process. Across processes the pid does it.
fn probe_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// What a completed upload's HEAD says about checksum support.
///
/// Two different `None`s used to be one. `head.and_then(|m| m.whole_object_checksum)`
/// gave `None` both when the object was PRESENT without a checksum and when the
/// object was ABSENT, and reported both as [`AttemptError::Unsupported`].
///
/// That difference decides whether a bucket can be registered. `Unsupported`
/// means "this provider does not do this algorithm", and every algorithm
/// answering that is exactly what makes `target.add` record `adopted: none` and
/// register the bucket anyway — a legitimate outcome for R2 or B2. But a
/// lifecycle rule, an inconsistent provider or an external deletion produces
/// the absent-`None` for every algorithm too, and then registration succeeds on
/// a bucket that has just demonstrated it does not retain what is uploaded to
/// it. That is the one property this probe most needs to establish, and it was
/// being reported as a checksum quirk.
///
/// [`AttemptError::Fatal`] for the absent case: a complete provider answer
/// about something other than the checksum algorithm, which is the variant's
/// stated purpose, and the one the orchestration refuses registration on.
fn checksum_from_head(head: Option<ObjectMeta>) -> Result<ObjectChecksum, AttemptError> {
    let Some(meta) = head else {
        return Err(AttemptError::Fatal {
            step: "head",
            detail: "the multipart upload completed and HEAD then reported the object ABSENT. \
                     That is not a statement about checksum support: the bucket did not retain \
                     an object it had just accepted, so nothing uploaded to it can be trusted \
                     to survive"
                .into(),
        });
    };
    meta.whole_object_checksum
        .ok_or_else(|| AttemptError::Unsupported {
            step: "head",
            detail: "the object completed but HEAD returned no whole-object checksum".into(),
        })
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

        // SWEEP FIRST, then probe.
        //
        // Every failure path below cleans up after itself, and none of them
        // runs if the daemon exits mid-probe: a kill between `create_multipart`
        // and the abort leaves parts allocated, and one between `complete` and
        // the delete leaves a 10 MiB control object. The nonce means the next
        // probe never collides with them — and never tidies them either, so
        // they accumulated with nothing in the product that would ever look.
        //
        // Registration is the right moment: it is the only time this prefix is
        // touched at all, so a sweep here cannot race a live probe of the same
        // algorithm in another process, and the cost falls on an operation
        // already measured in seconds.
        sweep_probe_leftovers(&adapter).await;

        let key = probe_key(alg, &probe_nonce());
        let object = key.as_key();

        let upload = adapter
            .create_multipart(object)
            .await
            .map_err(|e| classify("create_multipart", e))?;

        // Genuinely multipart: two parts at the S3 minimum. A single-part
        // upload would return an ETag that *is* a content digest, so it would
        // report success for the one case the whole exercise does not care
        // about.
        let mut receipts = Vec::new();
        for part_no in 1..=2u32 {
            let body = Bytes::from(vec![part_no as u8; S3_MIN_PART as usize]);
            match adapter.upload_part(object, &upload, part_no, body).await {
                Ok(r) => receipts.push(r),
                Err(e) => {
                    let _ = adapter.abort_multipart(object, &upload).await;
                    return Err(classify("upload_part", e));
                }
            }
        }

        // `Unconditional`, and it is a decision rather than a leftover. The key
        // now carries a per-invocation nonce, so there is nothing to overwrite
        // and the precondition would buy no safety. It would cost plenty:
        // `IfAbsent` requires `AdapterCapabilities::conditional_create`, and
        // this probe's whole job is measuring arbitrary S3-compatibles — a
        // registration that failed because a provider lacks conditional create
        // would be reporting the wrong fact about it entirely. `create_new` is
        // load-bearing in `shepherd-catalog`'s probes because those write into
        // a USER's directory where a collision hits real data; `_shepherd/`
        // is Shepherd's own namespace, so that motivation does not transfer.
        if let Err(e) = adapter
            .complete_multipart(
                object,
                &upload,
                &receipts,
                CreatePrecondition::Unconditional,
            )
            .await
        {
            let _ = adapter.abort_multipart(object, &upload).await;
            return Err(classify("complete_multipart", e));
        }

        let head = adapter.head(object).await.map_err(|e| classify("head", e));
        // Clean up whatever the outcome, and — because the key is this
        // invocation's alone — only this probe's own object. A failure to
        // delete is not a probe failure: it leaves one 10 MiB control object
        // behind, a storage cost and not a correctness one. The nonce moves
        // where that cost lands. A probe killed between `complete` and here
        // used to be tidied by the next probe of the same algorithm, which is
        // exactly the cross-probe deletion being removed; now it survives under
        // `_shepherd/probe/` until something sweeps the prefix.
        let _ = adapter.delete_system_object(&key).await;
        let head = head?;

        // Read from HEAD, never from `GetObjectAttributes`: MinIO omits
        // `ChecksumType` there while reporting it correctly on HEAD, so the
        // attributes call produces a false negative on a provider that
        // supports the feature. Recorded in E-5 from handling the API directly.
        let checksum = checksum_from_head(head)?;

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

/// The S3 error codes that are an answer about **checksum support**.
///
/// An allowlist, and the direction matters. "The provider answered, so it is
/// evidence" is true but too coarse: `AccessDenied` is also an answer, and
/// treating every answer as checksum evidence is how a bucket nobody can write
/// to gets registered as one that merely lacks CRC64NVME. So an unrecognized
/// code fails registration, loudly and with the code in the message, rather
/// than being recorded as non-support — because a wrong `adopted: none` is
/// permanent per object and costs 649x (ADR 0b §3), while a wrong refusal costs
/// one re-run of `target.add`.
///
/// Seeded only with codes there is evidence for, rather than a guessed vendor
/// list: `InvalidArgument` is what MinIO returns for a checksum-algorithm
/// mismatch (recorded verbatim at [`S3Adapter::upload_part`]), `InvalidRequest`
/// is AWS's answer to an unacceptable checksum algorithm, and `NotImplemented`
/// is how an S3-compatible provider says it does not offer the feature at all.
/// A provider that refuses with some fourth code will fail registration once,
/// visibly, with that code quoted — which is the signal needed to add it here,
/// and is recoverable in a way that a silent negative is not.
const CHECKSUM_REJECTION_CODES: &[&str] = &["InvalidArgument", "InvalidRequest", "NotImplemented"];

/// The S3 error code [`S3Adapter::map_err`] folded into a
/// [`StorageError::Provider`] detail, or `""` when it recorded none.
///
/// The inverse of one `format!` rather than a parser: `map_err` writes
/// `"{code}: {detail}"` when the SDK reported a code and the bare message when
/// it did not, and S3 error codes are single CamelCase tokens. A prefix
/// carrying anything but alphanumerics is therefore prose, not a code, and
/// reads as "no code" — which fails closed, since an unrecognized code is
/// fatal. Pinned by `the_probe_reads_the_error_code_map_err_wrote`.
fn provider_error_code(detail: &str) -> &str {
    match detail.split_once(':') {
        Some((code, _)) if !code.is_empty() && code.chars().all(|c| c.is_ascii_alphanumeric()) => {
            code
        }
        _ => "",
    }
}

/// Which of the three [`AttemptError`] directions a storage failure lands on.
///
/// [`StorageError::Transient`] is the crate's own "this never reached the
/// service" classification — `map_err` puts dispatch failures, timeouts and
/// 5xx there. Everything else is the provider answering, but an answer is only
/// evidence about checksums when it is an answer *about checksums*: see
/// [`CHECKSUM_REJECTION_CODES`].
///
/// The structured variants are routed deliberately rather than swept into the
/// catch-all. [`StorageError::Unsupported`] is the adapter itself reporting a
/// missing primitive, which is exactly the claim being probed for.
/// `NoSuchUpload`, `NotFound`, `PreconditionFailed` and `ContentMismatch`
/// during a probe mean the round trip came apart for reasons that have nothing
/// to do with the algorithm, so they refuse registration instead of being
/// recorded as non-support.
///
/// Probe-only: [`S3RoundTrip`] is its sole caller, so nothing here changes how
/// a production upload's errors are mapped.
fn classify(step: &'static str, e: StorageError) -> AttemptError {
    let about_checksums = match &e {
        StorageError::Unsupported { .. } => true,
        StorageError::Provider { detail, .. } => {
            CHECKSUM_REJECTION_CODES.contains(&provider_error_code(detail))
        }
        _ => false,
    };
    match e {
        StorageError::Transient { detail, .. } => AttemptError::Unreachable { step, detail },
        other if about_checksums => AttemptError::Unsupported {
            step,
            detail: other.to_string(),
        },
        other => AttemptError::Fatal {
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
/// * `Err(StorageError::Transient)` — the provider was never reached. **Not** a
///   statement about the provider, and a caller must not persist it as one.
/// * `Err(StorageError::Provider)` — the provider answered, about credentials,
///   permissions or the bucket rather than about checksums. The target is
///   unusable as configured, which is a different fact from "supports none of
///   the three" and must not be recorded as that one.
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
            let k = probe_key(alg, &probe_nonce());
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
        let nonce = probe_nonce();
        let keys: std::collections::BTreeSet<String> = FULL_OBJECT_PREFERENCE
            .iter()
            .map(|a| probe_key(*a, &nonce).as_key().as_str().to_string())
            .collect();
        assert_eq!(keys.len(), 3);
    }

    /// Two probes of one algorithm must not write to one object key.
    ///
    /// They did: the key was a pure function of the algorithm, so every
    /// concurrent `target.add` against a bucket shared one control object and
    /// one probe's cleanup `DELETE` could land between another's
    /// `complete_multipart` and its `HEAD`. A missing checksum reads as
    /// non-support here, and `adopted: none` is irreversible per object.
    #[test]
    fn two_probes_of_one_algorithm_do_not_share_an_object_key() {
        let alg = ChecksumAlgorithm::Crc64Nvme;
        let a = probe_key(alg, &probe_nonce());
        let b = probe_key(alg, &probe_nonce());
        assert_ne!(
            a.as_key().as_str(),
            b.as_key().as_str(),
            "a fixed key makes every concurrent probe clean up after every other"
        );

        // Still a control object, so `delete_system_object` can still reach it
        // — a nonce that escaped `_shepherd/` would leave the probe unable to
        // clean up without `delete_object`, which §4.1 rule 4 reserves for
        // `shepherd-tier::destroy`.
        for k in [&a, &b] {
            assert!(
                ControlKey::new(k.as_key().clone()).is_some(),
                "{}",
                k.as_key().as_str()
            );
        }

        // The accepting direction: within one invocation the key is stable, so
        // `complete`, `HEAD` and `DELETE` address the same object. A nonce
        // minted per *call site* rather than per probe would pass the
        // assertions above and break the probe outright.
        let nonce = probe_nonce();
        assert_eq!(
            probe_key(alg, &nonce).as_key().as_str(),
            probe_key(alg, &nonce).as_key().as_str()
        );
    }

    fn provider(detail: &str) -> StorageError {
        StorageError::Provider {
            provider: "s3",
            op: "create_multipart".into(),
            detail: detail.into(),
        }
    }

    /// The extractor is the inverse of `map_err`'s `format!`, so it is pinned
    /// against the shapes that function actually writes rather than against
    /// invented ones.
    #[test]
    fn the_probe_reads_the_error_code_map_err_wrote() {
        assert_eq!(
            provider_error_code("AccessDenied: Access Denied"),
            "AccessDenied"
        );
        assert_eq!(
            provider_error_code("InvalidArgument: checksum missing, want \"CRC64NVME\""),
            "InvalidArgument"
        );
        // `map_err` passes the message through unprefixed when the SDK reported
        // no code. Prose must not be mistaken for a code — and reading it as
        // "no code" is the fail-closed direction, since an unrecognized code is
        // fatal.
        assert_eq!(provider_error_code("dispatch failure: reset by peer"), "");
        assert_eq!(provider_error_code("no colon at all"), "");
    }

    /// **Authentication is not a checksum answer.**
    ///
    /// Each of these is a complete, non-transient provider response, and none
    /// of them says anything about whether the bucket can produce a FULL_OBJECT
    /// checksum. Classifying them as `Unsupported` is what let `target.add`
    /// persist an unusable target with the $441/month configuration recorded as
    /// though it had been measured.
    #[test]
    fn authentication_and_bucket_failures_are_fatal_not_unsupported() {
        for code in [
            "AccessDenied",
            "InvalidAccessKeyId",
            "SignatureDoesNotMatch",
            "NoSuchBucket",
            "ExpiredToken",
        ] {
            let got = classify("create_multipart", provider(&format!("{code}: refused")));
            match got {
                AttemptError::Fatal { step, ref detail } => {
                    assert_eq!(step, "create_multipart");
                    assert!(detail.contains(code), "the code must survive: {detail}");
                }
                other => panic!("{code} was classified as {other:?}, not as fatal"),
            }
        }
    }

    /// An object that VANISHED after completing is fatal, not "no checksum".
    ///
    /// Both used to arrive as `None` and both were reported as `Unsupported` —
    /// and every algorithm reporting `Unsupported` is precisely what makes
    /// `target.add` record `adopted: none` and register the bucket anyway. A
    /// lifecycle rule, an inconsistent provider or an external deletion
    /// therefore looked like a bucket that merely lacks CRC64NVME, while it was
    /// a bucket that did not keep an object it had just accepted.
    #[test]
    fn a_probe_object_that_disappears_is_fatal_not_unsupported() {
        match checksum_from_head(None) {
            Err(AttemptError::Fatal { step, detail }) => {
                assert_eq!(step, "head");
                assert!(detail.contains("ABSENT"), "{detail}");
            }
            other => panic!("a vanished probe object must be fatal, got {other:?}"),
        }

        // The paired non-zero: a PRESENT object with no checksum is still the
        // ordinary negative result, or this fix would refuse every legitimate
        // R2/B2 bucket.
        let present = ObjectMeta {
            key: ObjectKey::new("k"),
            size: 1,
            version: None,
            etag: None,
            whole_object_checksum: None,
        };
        assert!(matches!(
            checksum_from_head(Some(present.clone())),
            Err(AttemptError::Unsupported { .. })
        ));

        // And a present object WITH one is the success path.
        let supported = ObjectMeta {
            whole_object_checksum: Some(ObjectChecksum {
                algorithm: ChecksumAlgorithm::Crc64Nvme,
                value: "abc".into(),
                whole_object: true,
            }),
            ..present
        };
        assert!(checksum_from_head(Some(supported)).is_ok());
    }

    /// The paired non-zero. Without it the guard above is satisfiable by
    /// "everything is fatal", which would refuse every legitimate R2/B2 bucket.
    #[test]
    fn a_checksum_specific_rejection_is_still_a_negative_result() {
        for code in CHECKSUM_REJECTION_CODES {
            assert!(
                matches!(
                    classify(
                        "upload_part",
                        provider(&format!("{code}: bad checksum algorithm"))
                    ),
                    AttemptError::Unsupported { .. }
                ),
                "{code} is a provider answering about checksums and must stay a negative"
            );
        }
        // And the adapter's own "this provider lacks the primitive" is exactly
        // the claim being probed for.
        assert!(matches!(
            classify(
                "create_multipart",
                StorageError::Unsupported {
                    provider: "s3",
                    what: "full-object checksums".into()
                }
            ),
            AttemptError::Unsupported { .. }
        ));
    }

    /// A transport failure must still be `Unreachable` and not swept into the
    /// new variant — the two refusals are different errors on purpose, and only
    /// one of them is retryable.
    #[test]
    fn a_transport_failure_is_still_unreachable_not_fatal() {
        assert!(matches!(
            classify(
                "head",
                StorageError::Transient {
                    op: "head".into(),
                    detail: "connection reset".into()
                }
            ),
            AttemptError::Unreachable { .. }
        ));
    }

    /// End to end: a bucket that answers `AccessDenied` to every algorithm must
    /// fail registration rather than produce `adopted: None`.
    #[test]
    fn an_auth_failure_refuses_registration_instead_of_recording_no_support() {
        let f = Fake::new(&[(
            "CRC64NVME",
            Err(AttemptError::Fatal {
                step: "create_multipart",
                detail: "s3 error on create_multipart: AccessDenied: Access Denied".into(),
            }),
        )]);
        let err = run(&f).expect_err(
            "an unusable bucket must not produce a probe record — `adopted: None` is the \
             $441/month answer and it is irreversible per object",
        );
        let text = err.to_string();
        // The refusal names authentication, not checksum support.
        assert!(
            text.contains("AccessDenied") && text.contains("authentication"),
            "the refusal must say it is about credentials rather than checksums: {text}"
        );
        assert!(
            !text.contains("does not support"),
            "the refusal must not read as a checksum verdict: {text}"
        );
        // Not retryable: `AccessDenied` retried forever is its own bug, which
        // is why this is `Provider` rather than `Transient`.
        assert!(
            matches!(err, StorageError::Provider { .. }) && !err.is_retryable(),
            "{err:?}"
        );
        // It stopped rather than spending two more 10 MiB uploads proving the
        // same credential still cannot write.
        assert_eq!(f.asked(), ["CRC64NVME"]);
    }
}

/// One listing page, refusing a truncation that carries no way to continue.
///
/// `is_truncated` and `next_continuation_token` are two separate fields and a
/// provider can set the first without the second. Reading only the token maps
/// that to `next: None`, which every caller — `replica::read_chain` above all —
/// is entitled to read as "the listing is exhaustive". A partial pointer set
/// then resolves as though it were whole, producing stale recovery state or a
/// chain gap that is reported as the *bucket's* fault rather than the
/// response's.
///
/// `list_parts` in this same file already refuses this. This is the same
/// refusal, one function over, where it was missing.
fn list_page(
    truncated: bool,
    requested: Option<&str>,
    token: Option<&str>,
    keys: Vec<ObjectKey>,
) -> StorageResult<ListPage> {
    let next = token.map(OpaqueToken::new);
    if truncated && next.is_none() {
        return Err(StorageError::Provider {
            provider: "s3",
            op: "list_objects_v2".into(),
            detail: "response was truncated but carried no continuation token".into(),
        });
    }
    // And a token that does not ADVANCE, which is the same fault one step
    // further on: the caller loops until `next` is `None`, so a provider
    // handing back the token it was given makes that loop permanent. Caught
    // here rather than in each caller, because "exhaust the pagination" is
    // exactly what every caller is told to do.
    //
    // This is the IMMEDIATE echo only. A provider alternating A -> B -> A never
    // repeats its predecessor, and a pure function has nowhere to remember the
    // pairs it has already seen — so the loops that call `list` keep a set of
    // their own. `list_parts` and `list_multipart_uploads` own their loops and
    // do it there.
    if truncated && token.is_some() && token == requested {
        return Err(StorageError::Provider {
            provider: "s3",
            op: "list_objects_v2".into(),
            detail: "response was truncated and returned the same continuation token it was \
                     given; paging cannot advance"
                .into(),
        });
    }
    Ok(ListPage { keys, next })
}

#[cfg(test)]
mod tests {

    /// A truncated listing with no continuation token is malformed provider
    /// evidence, not an exhaustive page.
    ///
    /// The two fields are independent, and mapping only the token to `next`
    /// turned "there is more and I cannot tell you where" into "that was all".
    /// `replica::read_chain` stops on `next: None`, so a partial pointer set
    /// resolves as a complete one — stale recovery state, or a chain gap
    /// blamed on the bucket instead of the response.
    #[test]
    fn a_truncated_listing_without_a_token_is_refused() {
        let keys = vec![ObjectKey::new("p/objects/aa")];

        let err = list_page(true, None, None, keys.clone())
            .expect_err("a truncated page with nowhere to continue is not exhaustive");
        assert!(
            matches!(err, StorageError::Provider { op, .. } if op == "list_objects_v2"),
            "the refusal must name the operation"
        );

        // The two pages that ARE well-formed still pass through.
        let last =
            list_page(false, None, None, keys.clone()).expect("an untruncated page is the last");
        assert!(last.next.is_none());
        let more = list_page(true, None, Some("tok"), keys.clone())
            .expect("truncated WITH a token continues");

        // A token that does not ADVANCE is the same fault one step on: the
        // caller loops until `next` is `None`, so a provider handing back the
        // token it was given makes that loop permanent — the page is re-fetched
        // and re-appended until the daemon is killed.
        let stuck = list_page(true, Some("tok"), Some("tok"), keys.clone())
            .expect_err("a non-advancing token must be refused, not paged forever");
        assert!(
            stuck.to_string().contains("cannot advance"),
            "the refusal must say why: {stuck}"
        );
        // And advancing normally is unaffected.
        assert!(list_page(true, Some("tok-1"), Some("tok-2"), keys).is_ok());
        assert!(more.next.is_some());
    }
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

    // -----------------------------------------------------------------
    // Pagination, scripted at the transport.
    //
    // Both listing loops decide what to do from `is_truncated` plus the
    // continuation markers, and the case that matters — truncated while
    // carrying no marker at all — is a malformed response no real provider
    // can be asked to emit on demand. So the responses are scripted below
    // the SDK and the real `S3Adapter` runs against them unmodified.
    // -----------------------------------------------------------------

    use aws_smithy_runtime_api::client::http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
    };
    use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
    use std::sync::{Arc, Mutex};

    /// Answers each request with the next scripted body, and records the URIs
    /// it was asked for so a test can assert which markers were sent back.
    #[derive(Debug, Clone)]
    struct ScriptedHttp {
        pages: Arc<Mutex<std::collections::VecDeque<String>>>,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl ScriptedHttp {
        fn new(pages: &[&str]) -> Self {
            Self {
                pages: Arc::new(Mutex::new(pages.iter().map(|p| (*p).to_owned()).collect())),
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn requests(&self) -> Vec<String> {
            self.seen.lock().expect("poisoned").clone()
        }
    }

    impl HttpConnector for ScriptedHttp {
        fn call(&self, request: aws_sdk_s3::config::http::HttpRequest) -> HttpConnectorFuture {
            self.seen
                .lock()
                .expect("poisoned")
                .push(request.uri().to_owned());
            let body = self
                .pages
                .lock()
                .expect("poisoned")
                .pop_front()
                .expect("the adapter made more requests than the script has pages");
            HttpConnectorFuture::ready(Ok(aws_sdk_s3::config::http::HttpResponse::new(
                200.try_into().expect("200 is a status code"),
                aws_sdk_s3::primitives::SdkBody::from(body),
            )))
        }
    }

    impl HttpClient for ScriptedHttp {
        fn http_connector(
            &self,
            _: &HttpConnectorSettings,
            _: &RuntimeComponents,
        ) -> SharedHttpConnector {
            SharedHttpConnector::new(self.clone())
        }
    }

    fn adapter_over(http: ScriptedHttp) -> S3Adapter {
        let conf = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "AKIAEXAMPLE",
                "secret",
                None,
                None,
                "shepherd-test",
            ))
            .force_path_style(true)
            .endpoint_url("http://s3.invalid")
            .http_client(http)
            .build();
        S3Adapter {
            client: aws_sdk_s3::Client::from_conf(conf),
            bucket: "shepherd-test".into(),
            caps: caps(),
            multipart_checksum: None,
        }
    }

    const UPLOADS_TRUNCATED_NO_MARKERS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>shepherd-test</Bucket>
  <MaxUploads>1000</MaxUploads>
  <IsTruncated>true</IsTruncated>
  <Upload><Key>objects/aa/bb/one</Key><UploadId>upload-1</UploadId></Upload>
</ListMultipartUploadsResult>"#;

    const UPLOADS_TRUNCATED_WITH_MARKERS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>shepherd-test</Bucket>
  <MaxUploads>1000</MaxUploads>
  <IsTruncated>true</IsTruncated>
  <NextKeyMarker>objects/aa/bb/one</NextKeyMarker>
  <NextUploadIdMarker>upload-1</NextUploadIdMarker>
  <Upload><Key>objects/aa/bb/one</Key><UploadId>upload-1</UploadId></Upload>
</ListMultipartUploadsResult>"#;

    const UPLOADS_LAST_PAGE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>shepherd-test</Bucket>
  <MaxUploads>1000</MaxUploads>
  <IsTruncated>false</IsTruncated>
  <Upload><Key>objects/aa/bb/two</Key><UploadId>upload-2</UploadId></Upload>
</ListMultipartUploadsResult>"#;

    /// The finding: a partial page reported as exhaustive.
    ///
    /// `TransferDriver::adopt_or_reap` aborts the orphans on whatever this
    /// returns and then starts a new session, so a page silently treated as
    /// the whole list leaves the undiscovered multiparts accruing storage
    /// cost with nothing reporting it. The assertion is on the returned
    /// value, not on `is_err()`: pre-fix this call **succeeds**, and it is
    /// the success that is the defect.
    #[tokio::test]
    async fn a_truncated_upload_listing_with_no_continuation_markers_is_refused() {
        let http = ScriptedHttp::new(&[UPLOADS_TRUNCATED_NO_MARKERS]);
        let adapter = adapter_over(http);

        let out = adapter.list_incomplete_uploads("objects/").await;

        let err = out.expect_err(
            "a truncated page with no marker cannot be continued, so it cannot be reported as              the complete list of live uploads",
        );
        assert!(
            matches!(
                &err,
                StorageError::Provider { provider, op, .. }
                    if *provider == "s3" && op == "list_multipart_uploads"
            ),
            "must fail the same way `list_parts` already fails on this exact response, got {err:?}"
        );
    }

    /// The sibling this one had to be made to agree with.
    ///
    /// Pinned so the two cannot drift apart again in the other direction.
    #[tokio::test]
    async fn a_truncated_part_listing_with_no_continuation_marker_is_refused() {
        let page = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>shepherd-test</Bucket>
  <IsTruncated>true</IsTruncated>
  <Part><PartNumber>1</PartNumber><ETag>"e1"</ETag><Size>10</Size></Part>
</ListPartsResult>"#;
        let adapter = adapter_over(ScriptedHttp::new(&[page]));

        let err = adapter
            .list_parts(
                &ObjectKey::new("objects/aa/bb/one"),
                &OpaqueToken::new("u1"),
            )
            .await
            .expect_err("a truncated part list with no marker is not a complete part list");
        assert!(
            matches!(
                &err,
                StorageError::Provider { provider, op, .. }
                    if *provider == "s3" && op == "list_parts"
            ),
            "got {err:?}"
        );
    }

    /// The accepting direction, and the one that proves the fix is not
    /// "refuse whenever truncated": a well-formed truncated page is followed,
    /// the markers really are sent back, and the union of both pages returns.
    #[tokio::test]
    async fn a_truncated_upload_listing_with_markers_is_followed_to_the_next_page() {
        let http = ScriptedHttp::new(&[UPLOADS_TRUNCATED_WITH_MARKERS, UPLOADS_LAST_PAGE]);
        let adapter = adapter_over(http.clone());

        let live = adapter
            .list_incomplete_uploads("objects/")
            .await
            .expect("a page carrying its markers is continuable");

        let ids: Vec<&str> = live.iter().map(|u| u.upload_id.as_opaque()).collect();
        assert_eq!(
            ids,
            vec!["upload-1", "upload-2"],
            "both pages must be returned, or `adopt_or_reap` leaves orphans behind"
        );

        let seen = http.requests();
        assert_eq!(seen.len(), 2, "the second page must have been fetched");
        assert!(
            seen[1].contains("key-marker=objects") && seen[1].contains("upload-id-marker=upload-1"),
            "the second request must carry both markers from the first page: {}",
            seen[1]
        );
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
