//! `target.add`: the registration path, and the probe that has to run on it.
//!
//! # Why this module exists at all
//!
//! [`shepherd_storage::s3::probe_multipart_checksum`] answers one question —
//! does this bucket return a **whole-object** checksum on a genuine multipart
//! upload — and the answer is only usable if it is asked **before the first
//! upload**. A checksum not requested at upload cannot be retrofitted without
//! re-uploading the object, and scrub over a 50 TB corpus costs **$441/month**
//! without one against **$0.68** with one (ADR 0b §3, 649x), because the 2% of
//! files large enough to be multipart hold 60.3% of the bytes and their ETags
//! are digest-of-digests.
//!
//! So registration is the only moment this can be decided, and this module is
//! that moment. Everything here exists to make one call — `probe` — happen
//! before a `target` row exists, and to write what it returned down beside the
//! target it produced.
//!
//! # The runtime boundary, and why it sits here
//!
//! `shepherd-daemon` had no `tokio` and no async before this. The probe is the
//! whole reason it has any now, and the shape is the narrowest one that works:
//! a **current-thread runtime, built per registration, on the IPC connection's
//! own thread**, in [`probe_multipart_checksum_blocking`].
//!
//! `shepherd_catalog::writer`'s module doc states the rule this follows
//! verbatim: *"A consumer that needs an async client inside a closure builds a
//! runtime in its own thread and blocks on it there."* The alternatives were
//! considered and are worse:
//!
//! * **A process-wide multi-threaded runtime owned by [`crate::state::Daemon`]**
//!   would put a pool of worker threads next to a catalog whose single-writer
//!   discipline is carried by `&mut self` and by one actor thread. Nothing in
//!   the runtime would violate that on day one; the risk is that a future
//!   handler spawns onto it holding a [`shepherd_catalog::writer::CatalogWriter`]
//!   and discovers the second writer at runtime rather than at compile time.
//!   The daemon pays that standing risk for one method that runs at most a few
//!   times in a machine's life.
//! * **Awaiting inside the writer closure** would park the one thread permitted
//!   to touch the catalog on three 10 MiB network round trips. Every scan
//!   ingest, every job transition and every search behind it would queue for
//!   the duration of a registration against a slow provider.
//!
//! The probe therefore completes **entirely before** any catalog call, and no
//! future is ever alive across a `cat()`. The connection thread is already
//! one-request-at-a-time and blocking, so blocking it on the probe changes
//! nothing about the daemon's concurrency model — which is exactly the property
//! wanted.
//!
//! # The credential handle is a trust boundary
//!
//! `credentials_ref` is a name, never a secret (§4.1). It is resolved here,
//! held only long enough to build one [`S3Config`], and never logged, never
//! stored in `config_json`, and never returned on the wire. A reference that
//! does not resolve is a **refusal**, not a silent fall-through to the ambient
//! credential chain: falling through would register a target against whatever
//! credentials the daemon's environment happened to carry, which is a different
//! bucket's worth of authority than the operator asked for.

use serde::{Deserialize, Serialize};
use shepherd_proto::{ErrorCode, RpcError};
use shepherd_secrets::{SecretRef, SecretStore};
use shepherd_storage::adapter::ChecksumAlgorithm;
use shepherd_storage::s3::{ChecksumProbe, S3Config, StaticCredentials, probe_multipart_checksum};

/// The one adapter id this build registers.
///
/// Named rather than matched loosely, so an unknown adapter is an explicit
/// refusal naming what is served. A target registered against an adapter the
/// daemon cannot construct would be a row that every later phase has to
/// special-case.
pub const S3_ADAPTER: &str = "s3";

/// One S3-family target's configuration, in both the shape a caller sends and
/// the shape the catalog stores.
///
/// **One struct for both directions on purpose.** The stored form is the
/// caller's form plus what registration measured, so a later phase hydrating a
/// [`S3Config`] out of `target.config_json` deserializes it with this same type
/// rather than a parallel one that could drift. `deny_unknown_fields` is what
/// makes a mistyped key a refusal instead of a silently defaulted value — on a
/// struct where a defaulted `endpoint_url` means "talk to AWS instead of the
/// MinIO you meant".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3TargetConfig {
    pub bucket: String,
    /// Set for MinIO/R2/B2; absent for real AWS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// MinIO and most compatibles need path style; real S3 serves virtual-host
    /// buckets. No default is right for both, so the caller states it.
    #[serde(default)]
    pub force_path_style: bool,

    // --- measured at registration, never supplied ---------------------------
    /// The algorithm the registration probe adopted, or `None` if the provider
    /// answered that it supports none of them.
    ///
    /// This is [`S3Config::multipart_checksum`]'s producer. It is written here
    /// once, by [`ChecksumProbe::adopted`], and it is the field every upload
    /// through this target reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multipart_checksum: Option<ChecksumAlgorithm>,
    /// The probe's evidence: every algorithm tried, in preference order, with
    /// what the provider said.
    ///
    /// Kept because `multipart_checksum: None` is a claim that costs 649x and
    /// cannot be revisited without re-uploading every object, so it has to
    /// arrive with the per-algorithm reasons that produced it. A boolean would
    /// make a wrong negative indistinguishable from a right one forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_probe: Option<serde_json::Value>,
}

impl S3TargetConfig {
    /// Parse `TargetAddRequest::config`.
    ///
    /// The two measured fields are **refused on input**, not ignored. Accepting
    /// `multipart_checksum` from a caller would let a request assert
    /// whole-object checksum support that the provider never gave — which is
    /// the precise failure the probe exists to prevent, arriving through the
    /// front door. Silently dropping them would be worse still: the caller
    /// would have no way to tell their value was not honoured.
    pub fn parse_request(config: &serde_json::Value) -> Result<Self, RpcError> {
        for measured in ["multipart_checksum", "checksum_probe"] {
            if config.get(measured).is_some() {
                return Err(RpcError::new(
                    ErrorCode::Invalid,
                    format!(
                        "`config.{measured}` is measured by the registration probe, not supplied. \
                         A caller-asserted whole-object checksum algorithm would configure every \
                         upload through this target for a capability the provider may not have, \
                         and that cannot be undone without re-uploading every object."
                    ),
                ));
            }
        }
        let cfg: S3TargetConfig = serde_json::from_value(config.clone()).map_err(|e| {
            RpcError::new(
                ErrorCode::Invalid,
                format!("`config` is not a valid s3 target configuration: {e}"),
            )
        })?;
        if cfg.bucket.trim().is_empty() {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                "`config.bucket` must not be empty",
            ));
        }
        Ok(cfg)
    }

    /// Parse the **stored** form back out of `target.config_json`.
    ///
    /// Separate from [`parse_request`](Self::parse_request) only in that the
    /// measured fields are permitted here — this side is reading what
    /// registration wrote. Same struct, same `deny_unknown_fields`, so a stored
    /// config that this build cannot fully understand is a loud failure rather
    /// than a silently narrowed one.
    pub fn parse_stored(config: &serde_json::Value) -> Result<Self, RpcError> {
        serde_json::from_value(config.clone()).map_err(|e| {
            RpcError::new(
                ErrorCode::Invalid,
                format!("stored target config is not readable by this build: {e}"),
            )
        })
    }

    /// The connection config the probe and every later upload use.
    ///
    /// Takes the credentials by value and does not retain them anywhere else:
    /// the returned [`S3Config`] is the only thing that holds them, and it is
    /// dropped when registration ends.
    pub fn to_s3_config(&self, credentials: Option<StaticCredentials>) -> S3Config {
        S3Config {
            bucket: self.bucket.clone(),
            endpoint_url: self.endpoint_url.clone(),
            region: self.region.clone(),
            force_path_style: self.force_path_style,
            credentials,
            multipart_checksum: self.multipart_checksum,
        }
    }

    /// Fold a completed probe into the config that gets stored.
    pub fn with_probe(mut self, probe: &ChecksumProbe) -> Result<Self, RpcError> {
        self.multipart_checksum = probe.adopted;
        self.checksum_probe = Some(serde_json::to_value(probe).map_err(|e| {
            RpcError::new(
                ErrorCode::InternalError,
                format!("the checksum probe record could not be serialized: {e}"),
            )
        })?);
        Ok(self)
    }
}

/// The credential material a `credentials_ref` resolves to.
///
/// Deliberately has no `Debug`, no `Serialize` and no `Clone`: it exists for
/// the few lines between the secret store and [`StaticCredentials`], whose own
/// `Debug` redacts the secret half. A derive here would put the material one
/// `{:?}` away from a log line.
#[derive(Deserialize)]
struct CredentialMaterial {
    access_key_id: String,
    secret_access_key: String,
}

/// Resolve `credentials_ref` into static credentials, or refuse.
///
/// `None` returns `None`, which [`S3Config`] documents as "use the ambient
/// credential chain" — an operator on an EC2 instance role has no reference to
/// give and is not misconfigured. Every other outcome is a refusal:
///
/// * a malformed reference — rejected by [`SecretRef`] before any lookup;
/// * a reference that resolves to nothing — the operator named a secret that is
///   not there, and registering against ambient credentials instead would bind
///   the target to authority they did not ask for;
/// * a value that is not the documented two-field object.
///
/// **No error here quotes the stored value.** `serde_json`'s own message
/// includes surrounding input, so the parse error is discarded and replaced
/// with fixed text naming only the reference.
pub fn resolve_credentials(
    store: &SecretStore,
    credentials_ref: Option<&str>,
) -> Result<Option<StaticCredentials>, RpcError> {
    let Some(raw) = credentials_ref else {
        return Ok(None);
    };
    let key = SecretRef::new(raw).map_err(|e| {
        RpcError::new(
            ErrorCode::Invalid,
            format!("`credentials_ref` is not a usable secret reference: {e}"),
        )
    })?;
    let secret = store
        .get(&key)
        .map_err(|e| {
            RpcError::new(
                ErrorCode::Io,
                format!("could not read the secret store while resolving `{key}`: {e}"),
            )
        })?
        .ok_or_else(|| {
            RpcError::new(
                ErrorCode::NotFound,
                format!(
                    "no secret is stored under `{key}`. Store the target's credentials there \
                     before registering it — registration will not fall back to the ambient \
                     credential chain, because that would bind the target to whatever authority \
                     the daemon's environment happens to carry."
                ),
            )
        })?;

    // The stored value's shape, documented here because this is the only place
    // that reads it: a JSON object with exactly the two fields an S3-family
    // provider needs.
    //
    //     {"access_key_id": "...", "secret_access_key": "..."}
    let material: CredentialMaterial = serde_json::from_str(secret.expose()).map_err(|_| {
        RpcError::new(
            ErrorCode::Invalid,
            format!(
                "the secret stored under `{key}` is not an s3 credential. Expected a JSON object \
                 with `access_key_id` and `secret_access_key`. The stored value is not quoted \
                 here, deliberately."
            ),
        )
    })?;

    Ok(Some(StaticCredentials {
        access_key_id: material.access_key_id,
        secret_access_key: material.secret_access_key,
    }))
}

/// Run the registration-time whole-object-checksum probe to completion.
///
/// # The runtime
///
/// One current-thread runtime, built here and dropped here. See this module's
/// docs for why it is not owned by the daemon and not built inside the catalog
/// writer's closure. The short version, which is the part that must survive a
/// later refactor: **the catalog's single-writer discipline is enforced by one
/// actor thread and by `&mut self`, and nothing in this file may hand a future
/// a path to either.** The probe finishes before the caller touches the
/// catalog.
///
/// # The two failure directions are not symmetric
///
/// * `Ok(probe)` with `adopted: None` — the provider answered, and its answer
///   was that it supports none of the three. Legitimate; scrub degrades to full
///   reads, which is expensive and never wrong.
/// * `Err(_)` — the provider was never reached. This proves nothing about the
///   provider, so it fails the registration. Storing it as "supports nothing"
///   would be silent, permanent, and indistinguishable from a real measurement.
pub fn probe_multipart_checksum_blocking(cfg: &S3Config) -> Result<ChecksumProbe, RpcError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            RpcError::new(
                ErrorCode::InternalError,
                format!("could not build the runtime the registration probe needs: {e}"),
            )
        })?;
    rt.block_on(probe_multipart_checksum(cfg)).map_err(|e| {
        RpcError::new(
            ErrorCode::TargetUnreachable,
            format!(
                "the registration probe could not reach the target, so this build cannot tell \
                 whether it supports whole-object multipart checksums: {e}"
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shepherd_secrets::{Backend, Secret, SecretStore};
    use std::collections::BTreeMap;

    /// A writable backend that lives for one test.
    ///
    /// `EnvStore` would need `set_var` — unsafe under the 2024 edition and
    /// shared across the test binary's threads — and `KeyfileStore` would need
    /// a temp directory dependency for a five-line fixture.
    #[derive(Default)]
    struct MemBackend(BTreeMap<String, String>);

    impl Backend for MemBackend {
        fn name(&self) -> &'static str {
            "memory"
        }
        fn get(&self, key: &SecretRef) -> shepherd_secrets::Result<Option<Secret>> {
            Ok(self.0.get(key.as_str()).cloned().map(Secret::new))
        }
        fn put(&mut self, key: &SecretRef, secret: &Secret) -> shepherd_secrets::Result<()> {
            self.0
                .insert(key.as_str().to_string(), secret.expose().to_string());
            Ok(())
        }
        fn delete(&mut self, key: &SecretRef) -> shepherd_secrets::Result<()> {
            self.0.remove(key.as_str());
            Ok(())
        }
    }

    fn store_with(key: &str, value: &str) -> SecretStore {
        let mut s = SecretStore::new(vec![Box::new(MemBackend::default())]);
        s.put(&SecretRef::new(key).unwrap(), &Secret::new(value))
            .unwrap();
        s
    }

    fn code(e: &RpcError) -> ErrorCode {
        e.kind().expect("this build issued the code")
    }

    #[test]
    fn a_config_with_an_unknown_key_is_refused_rather_than_defaulted() {
        let err = S3TargetConfig::parse_request(&serde_json::json!({
            "bucket": "archive",
            "endpoint_ur1": "http://127.0.0.1:9000",
        }))
        .unwrap_err();
        assert_eq!(code(&err), ErrorCode::Invalid);
        // The point of `deny_unknown_fields`: a typo'd endpoint must not
        // silently become "no endpoint", which means "talk to real AWS".
        assert!(err.message.contains("endpoint_ur1"), "{}", err.message);
    }

    /// The front-door version of the failure the probe exists to prevent.
    #[test]
    fn a_caller_cannot_assert_a_checksum_algorithm_the_provider_never_gave() {
        for measured in ["multipart_checksum", "checksum_probe"] {
            let err = S3TargetConfig::parse_request(&serde_json::json!({
                "bucket": "archive",
                measured: "crc64-nvme",
            }))
            .unwrap_err();
            assert_eq!(code(&err), ErrorCode::Invalid);
            assert!(err.message.contains(measured), "{}", err.message);
        }
    }

    #[test]
    fn the_probed_algorithm_is_what_a_later_upload_reads() {
        let cfg = S3TargetConfig::parse_request(&serde_json::json!({"bucket": "archive"})).unwrap();
        let probe = ChecksumProbe {
            adopted: Some(ChecksumAlgorithm::Crc64Nvme),
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "archive".into(),
            attempts: vec![],
        };
        let stored = cfg.with_probe(&probe).unwrap();
        assert_eq!(
            stored.to_s3_config(None).multipart_checksum,
            Some(ChecksumAlgorithm::Crc64Nvme),
            "the whole point of the registration probe is that this field is set from it"
        );

        // And the stored form round-trips through the same type, so a later
        // phase hydrating a target does not need a second parser.
        let json = serde_json::to_value(&stored).unwrap();
        assert_eq!(S3TargetConfig::parse_stored(&json).unwrap(), stored);
    }

    #[test]
    fn an_absent_credentials_ref_means_the_ambient_chain_and_not_an_error() {
        let store = SecretStore::new(vec![]);
        assert!(resolve_credentials(&store, None).unwrap().is_none());
    }

    /// The fail-closed direction. A named-but-missing secret must not degrade
    /// into "use whatever this machine has".
    #[test]
    fn a_credentials_ref_that_resolves_to_nothing_refuses_the_registration() {
        let store = SecretStore::new(vec![]);
        let err = resolve_credentials(&store, Some("target/archive")).unwrap_err();
        assert_eq!(code(&err), ErrorCode::NotFound);
    }

    #[test]
    fn a_stored_credential_of_the_wrong_shape_is_refused_without_quoting_it() {
        let store = store_with("target/archive", "AKIAsecretlookingthing");
        let err = resolve_credentials(&store, Some("target/archive")).unwrap_err();
        assert_eq!(code(&err), ErrorCode::Invalid);
        assert!(
            !err.message.contains("AKIAsecretlookingthing"),
            "the refusal quoted the stored secret back at the caller: {}",
            err.message
        );
    }

    #[test]
    fn a_well_formed_credential_resolves_and_its_debug_stays_redacted() {
        let store = store_with(
            "target/archive",
            r#"{"access_key_id":"AKIAEXAMPLE","secret_access_key":"s3cr3t-material"}"#,
        );
        let creds = resolve_credentials(&store, Some("target/archive"))
            .unwrap()
            .unwrap();
        assert_eq!(creds.access_key_id, "AKIAEXAMPLE");
        assert_eq!(creds.secret_access_key, "s3cr3t-material");
        assert!(
            !format!("{creds:?}").contains("s3cr3t-material"),
            "credentials rendered their secret half in Debug"
        );
    }
}
