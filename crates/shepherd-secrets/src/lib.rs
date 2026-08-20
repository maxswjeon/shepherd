//! Secret storage: a backend trait, an environment backend, and a
//! permission-checked keyfile backend.
//!
//! # What crosses the IPC boundary is a *handle*, never a secret
//!
//! `target.credentials_ref` in the catalog and `credentials_ref` in
//! `shepherd_proto::request::TargetAddRequest` are both [`SecretRef`] strings —
//! names that mean "look this up". No secret value is ever a field of a wire
//! type, is ever written to the catalog, or is ever returned by an IPC method.
//! That is why `shepherd-proto` has no dependency on this crate and never will.
//!
//! # Backends, and which one is missing
//!
//! | backend | status | for |
//! |---|---|---|
//! | [`EnvStore`] | here | headless servers, CI, containers |
//! | [`KeyfileStore`] | here | headless boxes with no session keyring |
//! | OS keychain | **not here** | desktop macOS / Windows / Linux-with-session |
//!
//! The keychain backend is deliberately absent at Phase 1 rather than stubbed.
//! Phase 1 stores no secret: `target.*` is the only method family that would,
//! and it is not served until Phase 2. The `keyring` crate's Linux backend is
//! secret-service over D-Bus, which is exactly absent on the headless
//! deployment AC-55 exercises, so it needs per-target feature selection and a
//! dependency-trust assessment of the kind §4.5 applies to every other
//! third-party crate — not a version number added in a hurry. [`Backend`] is
//! the seam it plugs into.
//!
//! # The keyfile is permission-checked, not encrypted, and says so
//!
//! The crate description says "encrypted-file fallback". It is not encrypted,
//! and calling it encrypted would be worse than not encrypting it. Encryption
//! needs a key, a daemon that starts unattended on a headless box has nowhere
//! to get a passphrase, and a key stored beside the ciphertext under the same
//! permissions protects against nothing while *looking* like it protects
//! against something. What actually defends the file is `0600` plus the
//! directory it sits in — so that is enforced, on write **and on read**, and
//! [`KeyfileStore`] refuses to load a group- or world-readable file rather than
//! reading it with a warning.
//!
//! Real at-rest encryption needs a decided key source — an OS keychain item, a
//! TPM, or an operator-supplied passphrase with a KDF. That is a design
//! decision, not an implementation gap, and it belongs with the keychain
//! backend.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("no secret stored under `{0}`")]
    NotFound(SecretRef),
    #[error("`{0}` is not a valid secret reference: {1}")]
    InvalidRef(String, &'static str),
    #[error("{backend} is read-only; it cannot store secrets")]
    ReadOnly { backend: &'static str },
    #[error(
        "refusing to read `{path}`: mode is {mode:04o}, which is readable by group or other. \
         Secrets in this file are exposed to every account on the machine. \
         Fix it with `chmod 600 {path}` and rotate anything it held."
    )]
    Permissions { path: String, mode: u32 },
    #[error("secret store I/O at {path}: {detail}")]
    Io { path: String, detail: String },
    #[error("secret store at {path} is corrupt: {detail}")]
    Corrupt { path: String, detail: String },
}

pub type Result<T> = std::result::Result<T, SecretError>;

/// fsync a directory, so a rename into it survives a crash.
///
/// POSIX-only, and a no-op elsewhere rather than an error: opening a directory
/// as a file is not something the Windows API permits, so the durability this
/// buys on unix is not expressible there.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// A name for a secret. Safe to store in the catalog and to send over IPC.
///
/// Constrained to `[a-z0-9._/-]` so it can be embedded in an environment
/// variable name and used as a map key without escaping, and so a caller cannot
/// smuggle a path traversal or a newline through it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(SecretError::InvalidRef(s, "must not be empty"));
        }
        if s.len() > 200 {
            return Err(SecretError::InvalidRef(
                s,
                "must be 200 characters or fewer",
            ));
        }
        if !s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-')
        }) {
            return Err(SecretError::InvalidRef(
                s,
                "may contain only lowercase letters, digits, and `.`, `_`, `/`, `-`",
            ));
        }
        if s.contains("..") {
            return Err(SecretError::InvalidRef(s, "may not contain `..`"));
        }
        Ok(Self(s))
    }

    /// The conventional reference for a storage target's credentials.
    pub fn for_target(target_id: i64) -> Self {
        Self(format!("target/{target_id}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The environment variable [`EnvStore`] looks this up in, or `None` when
    /// this reference has no unambiguous one.
    ///
    /// `target/7` becomes `SHEPHERD_SECRET_TARGET_7`.
    ///
    /// # Why this is `Option`, and why only `/` survives
    ///
    /// An environment variable name is `[A-Z0-9_]`, so every separator this
    /// reference alphabet allows — `/`, `.`, `-`, `_` — has to become `_`. That
    /// map is **not injective**: `target/a-b`, `target/a_b` and `target.a/b`
    /// all named `SHEPHERD_SECRET_TARGET_A_B`, so two targets could read each
    /// other's credentials, and the one that was misconfigured would get a
    /// working secret rather than the "missing" it deserved. A credential
    /// silently resolving to the wrong value is the worst shape this module
    /// has.
    ///
    /// Restricted rather than escaped. An escaping scheme (`_` doubled, or
    /// hex-encoded separators) buys the full alphabet at the cost of variable
    /// names an operator cannot guess, and would change the one spelling the
    /// docs promise — `SHEPHERD_SECRET_TARGET_7`. Over `[a-z0-9/]` the map is
    /// injective as it stands, because nothing but `/` produces `_`, and
    /// [`SecretRef::for_target`] — the reference this project actually mints —
    /// is always of that shape.
    ///
    /// The other three characters remain legal in a `SecretRef`: they are fine
    /// as [`KeyfileStore`] keys, which are the reference itself. It is only the
    /// environment that cannot address them apart.
    pub fn env_var(&self) -> Option<String> {
        if self.0.contains(['.', '-', '_']) {
            return None;
        }
        let mut s = String::from(ENV_PREFIX);
        for c in self.0.chars() {
            s.push(match c {
                '/' => '_',
                other => other.to_ascii_uppercase(),
            });
        }
        Some(s)
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Prefix for [`EnvStore`] lookups.
pub const ENV_PREFIX: &str = "SHEPHERD_SECRET_";

/// A secret value.
///
/// `Debug` and `Display` are redacted. That is the point of the newtype: the
/// most likely way a credential escapes is not an attacker, it is a
/// `tracing::info!(?config)` on a struct that happens to contain one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext. Every call site is a place a secret can leak, so this is
    /// deliberately verbose to type and easy to grep for.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Secret {
    /// Overwrite the buffer on drop.
    ///
    /// **Best-effort, and worth being precise about what it is not.** A `String`
    /// may have been reallocated or copied while it was alive, and this cannot
    /// reach those earlier buffers; the compiler is also entitled to elide a
    /// write nothing reads, which is what the `zeroize` crate exists to prevent.
    /// This closes the common case — a heap block returned to the allocator
    /// still holding a credential — and does not claim to close the general one.
    fn drop(&mut self) {
        // SAFETY-adjacent note: this is safe code. `as_mut_vec` is unsafe, so
        // instead the string is overwritten through its own API.
        let len = self.0.len();
        self.0.clear();
        self.0.push_str(&"\0".repeat(len));
        self.0.clear();
    }
}

/// A place secrets live.
pub trait Backend: Send + Sync {
    /// A short name, used in errors and by `doctor`.
    fn name(&self) -> &'static str;
    fn get(&self, key: &SecretRef) -> Result<Option<Secret>>;
    fn put(&mut self, key: &SecretRef, secret: &Secret) -> Result<()>;
    fn delete(&mut self, key: &SecretRef) -> Result<()>;
    /// Whether this backend can store as well as read.
    fn writable(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// Reads secrets from the process environment. Read-only.
///
/// The backend that makes a container or a CI runner work without a keyring or
/// a file on disk. Deliberately first in [`SecretStore`]'s chain so an operator
/// can override a stored credential for one run without editing anything.
#[derive(Debug, Default)]
pub struct EnvStore;

impl Backend for EnvStore {
    fn name(&self) -> &'static str {
        "environment"
    }

    /// A reference with no unambiguous variable name is **not found here**, not
    /// resolved to whatever happens to share its spelling.
    ///
    /// `Ok(None)` rather than an error: this backend is first in the chain, and
    /// an error here would refuse a reference the keyfile store can resolve
    /// perfectly well. Missing-from-the-environment is exactly what it is, and
    /// the chain moves on. See [`SecretRef::env_var`].
    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        let Some(var) = key.env_var() else {
            return Ok(None);
        };
        Ok(std::env::var(var).ok().map(Secret::new))
    }

    fn put(&mut self, _key: &SecretRef, _secret: &Secret) -> Result<()> {
        Err(SecretError::ReadOnly {
            backend: "environment",
        })
    }

    fn delete(&mut self, _key: &SecretRef) -> Result<()> {
        Err(SecretError::ReadOnly {
            backend: "environment",
        })
    }

    fn writable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Keyfile
// ---------------------------------------------------------------------------

/// A `0600` JSON file. See the module docs for why it is not encrypted.
#[derive(Debug)]
pub struct KeyfileStore {
    path: PathBuf,
}

impl KeyfileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<BTreeMap<String, String>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        check_permissions(&self.path)?;
        let text = std::fs::read_to_string(&self.path).map_err(|e| SecretError::Io {
            path: self.path.display().to_string(),
            detail: e.to_string(),
        })?;
        if text.trim().is_empty() {
            return Ok(BTreeMap::new());
        }
        serde_json::from_str(&text).map_err(|e| SecretError::Corrupt {
            path: self.path.display().to_string(),
            detail: e.to_string(),
        })
    }

    /// Write the map back at `0600`.
    ///
    /// Written to a sibling temp file and renamed, so a crash mid-write leaves
    /// the previous file intact rather than a truncated one. The temp file is
    /// created with the restrictive mode *before* any secret is written to it —
    /// creating it world-readable and chmod'ing afterwards leaves a window in
    /// which the plaintext is readable.
    fn store(&self, map: &BTreeMap<String, String>) -> Result<()> {
        let io = |e: std::io::Error| SecretError::Io {
            path: self.path.display().to_string(),
            detail: e.to_string(),
        };
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let tmp = self.path.with_extension("tmp");
        let json = serde_json::to_string_pretty(map).map_err(|e| SecretError::Corrupt {
            path: self.path.display().to_string(),
            detail: e.to_string(),
        })?;
        write_private(&tmp, &json).map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)?;

        // The RENAME, made durable. `write_private` fsyncs the temp file, which
        // makes its contents survive and says nothing about the directory entry
        // that replaces the old name with it. A power loss here has three
        // shapes and all of them are wrong for a credential store: a first
        // write disappears, an update reverts to the previous credential, and a
        // deleted secret comes back.
        //
        // The last is the one that decides it. `delete` goes through here too,
        // so without this a secret the user removed can reappear after a crash
        // — a credential outliving its own revocation.
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            sync_dir(parent).map_err(io)?;
        }
        Ok(())
    }
}

impl Backend for KeyfileStore {
    fn name(&self) -> &'static str {
        "keyfile"
    }

    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        // `remove` rather than `get`, so the plaintext is *moved* into the
        // `Secret` instead of copied beside it. Cloning left two buffers for one
        // credential and only the `Secret` got [`Secret::drop`]'s overwrite; the
        // map's own `String` went back to the allocator intact. The map is a
        // transient built by `load` and is never written back, so removing from
        // it cannot affect the file.
        let mut map = self.load()?;
        Ok(map.remove(key.as_str()).map(Secret::new))
    }

    fn put(&mut self, key: &SecretRef, secret: &Secret) -> Result<()> {
        let mut map = self.load()?;
        map.insert(key.as_str().to_string(), secret.expose().to_string());
        self.store(&map)
    }

    fn delete(&mut self, key: &SecretRef) -> Result<()> {
        let mut map = self.load()?;
        map.remove(key.as_str());
        self.store(&map)
    }
}

/// Create-or-truncate `path` with owner-only permissions and write `contents`.
#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

/// Windows has no mode bits; the file inherits the directory's ACL.
///
/// `shepherdd` runs as a per-user agent (§4.2) and its state directory is under
/// the user profile, which is not readable by other standard users by default.
/// A real ACL assertion belongs with the rest of the Windows platform work in
/// Phase 3, alongside the named-pipe DACL, and [`check_permissions`] says so
/// rather than silently returning success as though it had checked.
#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Refuse a keyfile that anyone but the owner can read.
#[cfg(unix)]
pub fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| SecretError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretError::Permissions {
            path: path.display().to_string(),
            mode,
        });
    }
    Ok(())
}

/// See [`write_private`]'s note. Not implemented on Windows; returns `Ok` and
/// the gap is documented rather than presented as a passing check.
#[cfg(not(unix))]
pub fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

/// Reads through an ordered list of backends; writes to the first writable one.
///
/// The order is the policy: environment first so an operator can override for a
/// single run, then persistent storage. A `get` returns the first hit, so an
/// env var shadows a stored secret without destroying it.
pub struct SecretStore {
    backends: Vec<Box<dyn Backend>>,
}

impl SecretStore {
    pub fn new(backends: Vec<Box<dyn Backend>>) -> Self {
        Self { backends }
    }

    /// The Phase 1 default: environment, then a keyfile in the state directory.
    pub fn with_keyfile(path: impl Into<PathBuf>) -> Self {
        Self::new(vec![Box::new(EnvStore), Box::new(KeyfileStore::new(path))])
    }

    /// Backend names, in order. For `doctor`, so an operator can see where a
    /// lookup would land.
    pub fn chain(&self) -> Vec<&'static str> {
        self.backends.iter().map(|b| b.name()).collect()
    }

    pub fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        for b in &self.backends {
            if let Some(s) = b.get(key)? {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    pub fn require(&self, key: &SecretRef) -> Result<Secret> {
        self.get(key)?
            .ok_or_else(|| SecretError::NotFound(key.clone()))
    }

    /// Store into the first writable backend.
    pub fn put(&mut self, key: &SecretRef, secret: &Secret) -> Result<()> {
        for b in self.backends.iter_mut() {
            if b.writable() {
                return b.put(key, secret);
            }
        }
        Err(SecretError::ReadOnly {
            backend: "every configured backend",
        })
    }

    /// Delete from every writable backend, so a secret cannot survive in a
    /// lower-priority one and reappear when the top backend is removed.
    pub fn delete(&mut self, key: &SecretRef) -> Result<()> {
        for b in self.backends.iter_mut() {
            if b.writable() {
                b.delete(key)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "shepherd-secrets-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn refs_reject_anything_that_could_escape_their_context() {
        assert!(SecretRef::new("target/7").is_ok());
        assert!(SecretRef::new("s3.prod_key-1").is_ok());
        for bad in [
            "",
            "Target/7",         // uppercase
            "target 7",         // space
            "../../etc/passwd", // traversal
            "target/../root",   // traversal
            "a\nb",             // newline
            "tar$get",
        ] {
            assert!(SecretRef::new(bad).is_err(), "accepted `{bad}`");
        }
        assert!(SecretRef::new("x".repeat(201)).is_err());
    }

    #[test]
    fn env_var_names_are_derived_predictably() {
        assert_eq!(
            SecretRef::for_target(7).env_var().as_deref(),
            Some("SHEPHERD_SECRET_TARGET_7"),
            "the documented spelling, and the only one this project mints"
        );
        assert_eq!(
            SecretRef::new("a/b/c").unwrap().env_var().as_deref(),
            Some("SHEPHERD_SECRET_A_B_C")
        );
    }

    /// Two different references must never name one environment variable.
    ///
    /// `/`, `.`, `-` and `_` all had to become `_` — an environment variable
    /// name has nothing else — so `target/a-b` and `target/a_b` both read
    /// `SHEPHERD_SECRET_TARGET_A_B`. One target would receive the other's
    /// credentials, and the misconfigured one would get a WORKING secret rather
    /// than the "missing" that would have told its operator what was wrong.
    ///
    /// The three ambiguous separators stay legal in a `SecretRef` — they are
    /// fine as keyfile keys, which are the reference itself — and simply have
    /// no environment name.
    #[test]
    fn references_that_would_collide_have_no_environment_name() {
        for r in ["target/a-b", "target/a_b", "s3.prod-key", "a_b"] {
            assert_eq!(
                SecretRef::new(r).unwrap().env_var(),
                None,
                "`{r}` shares an environment spelling with other references, so it must \
                 have none rather than read one of theirs"
            );
        }

        // The restriction did not simply turn the backend off: the shape this
        // project mints is still addressable, and the environment is still
        // where `e2e::a_target_credential_comes_from_the_environment` supplies
        // it from.
        assert!(SecretRef::for_target(91).env_var().is_some());

        // And a colliding sibling reads NOTHING from the environment rather
        // than reading `SHEPHERD_SECRET_TARGET_91`.
        assert_eq!(
            EnvStore.get(&SecretRef::new("target_91").unwrap()).unwrap(),
            None
        );
    }

    /// The leak this newtype exists to prevent.
    #[test]
    fn secrets_are_redacted_in_debug_and_display() {
        let s = Secret::new("hunter2-aws-secret-access-key");
        assert!(!format!("{s:?}").contains("hunter2"), "{s:?}");
        assert!(!format!("{s}").contains("hunter2"));
        assert!(!format!("{:#?}", vec![&s]).contains("hunter2"));
        assert_eq!(s.expose(), "hunter2-aws-secret-access-key");
    }

    #[test]
    fn a_keyfile_round_trips() {
        let dir = tmpdir("roundtrip");
        let mut ks = KeyfileStore::new(dir.join("secrets.json"));
        let k = SecretRef::for_target(1);
        assert!(ks.get(&k).unwrap().is_none(), "absent before it is written");

        ks.put(&k, &Secret::new("s3-key")).unwrap();
        assert_eq!(ks.get(&k).unwrap().unwrap().expose(), "s3-key");

        ks.put(&k, &Secret::new("rotated")).unwrap();
        assert_eq!(ks.get(&k).unwrap().unwrap().expose(), "rotated");

        ks.delete(&k).unwrap();
        assert!(ks.get(&k).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_written_keyfile_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let path = dir.join("secrets.json");
        let mut ks = KeyfileStore::new(&path);
        ks.put(&SecretRef::for_target(1), &Secret::new("v"))
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "written as {mode:04o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The trust boundary. A keyfile anyone can read is refused, not read with
    /// a warning — a warning in a daemon log is not a control.
    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_keyfile_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perm");
        let path = dir.join("secrets.json");
        let mut ks = KeyfileStore::new(&path);
        ks.put(&SecretRef::for_target(1), &Secret::new("v"))
            .unwrap();

        for bad in [0o640, 0o604, 0o644, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bad)).unwrap();
            let err = ks.get(&SecretRef::for_target(1)).unwrap_err();
            match err {
                SecretError::Permissions { mode, .. } => assert_eq!(mode, bad),
                other => panic!("mode {bad:04o} was accepted: {other}"),
            }
            // The message has to be actionable, and has to say to rotate: the
            // secret was exposed, and fixing the mode does not un-expose it.
            let text = ks.get(&SecretRef::for_target(1)).unwrap_err().to_string();
            assert!(text.contains("chmod 600"), "{text}");
            assert!(text.contains("rotate"), "{text}");
        }

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ks.get(&SecretRef::for_target(1)).unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_keyfile_is_reported_not_silently_treated_as_empty() {
        let dir = tmpdir("corrupt");
        let path = dir.join("secrets.json");
        std::fs::write(&path, "{not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let ks = KeyfileStore::new(&path);
        assert!(matches!(
            ks.get(&SecretRef::for_target(1)),
            Err(SecretError::Corrupt { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A stand-in for [`EnvStore`]: read-only, backed by a fixed map.
    ///
    /// The chain's ordering is tested against this rather than against the real
    /// process environment for two reasons. `std::env::set_var` is `unsafe` in
    /// the 2024 edition and this crate is `#![forbid(unsafe_code)]`; and the
    /// environment is process-global, so a test that mutates it races every
    /// other test in the binary. What is specific to `EnvStore` — that it
    /// refuses writes, and how it derives a variable name — is tested directly
    /// elsewhere.
    struct FakeReadOnly(BTreeMap<String, String>);

    impl Backend for FakeReadOnly {
        fn name(&self) -> &'static str {
            "environment"
        }
        fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
            Ok(self.0.get(key.as_str()).map(|v| Secret::new(v.clone())))
        }
        fn put(&mut self, _: &SecretRef, _: &Secret) -> Result<()> {
            Err(SecretError::ReadOnly {
                backend: "environment",
            })
        }
        fn delete(&mut self, _: &SecretRef) -> Result<()> {
            Err(SecretError::ReadOnly {
                backend: "environment",
            })
        }
        fn writable(&self) -> bool {
            false
        }
    }

    #[test]
    fn a_read_only_backend_shadows_the_keyfile_without_destroying_it() {
        let dir = tmpdir("chain");
        let key = SecretRef::for_target(9911);

        // Seed the keyfile first, through a store with no shadowing backend.
        let mut plain = SecretStore::new(vec![Box::new(KeyfileStore::new(dir.join("s.json")))]);
        plain.put(&key, &Secret::new("from-keyfile")).unwrap();
        assert_eq!(plain.get(&key).unwrap().unwrap().expose(), "from-keyfile");

        // Now the same keyfile behind a read-only backend that also has it.
        let shadowed = SecretStore::new(vec![
            Box::new(FakeReadOnly(BTreeMap::from([(
                key.as_str().to_string(),
                "from-env".to_string(),
            )]))),
            Box::new(KeyfileStore::new(dir.join("s.json"))),
        ]);
        assert_eq!(
            shadowed.get(&key).unwrap().unwrap().expose(),
            "from-env",
            "the first backend must win, so an operator can override for one run"
        );

        // And the stored secret survived being shadowed.
        assert_eq!(
            plain.get(&key).unwrap().unwrap().expose(),
            "from-keyfile",
            "shadowing must not destroy what it shadows"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writes_skip_a_read_only_backend_and_land_in_the_next_one() {
        let dir = tmpdir("write-through");
        let path = dir.join("s.json");
        let key = SecretRef::for_target(3);
        let mut store = SecretStore::new(vec![
            Box::new(FakeReadOnly(BTreeMap::new())),
            Box::new(KeyfileStore::new(&path)),
        ]);
        store.put(&key, &Secret::new("v")).unwrap();

        // It really landed in the keyfile, not nowhere.
        assert_eq!(
            KeyfileStore::new(&path)
                .get(&key)
                .unwrap()
                .unwrap()
                .expose(),
            "v"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_store_with_no_writable_backend_refuses_to_put() {
        let mut store = SecretStore::new(vec![Box::new(FakeReadOnly(BTreeMap::new()))]);
        assert!(matches!(
            store.put(&SecretRef::for_target(1), &Secret::new("v")),
            Err(SecretError::ReadOnly { .. })
        ));
    }

    #[test]
    fn an_absent_environment_variable_reads_as_absent() {
        // Reading is safe; only mutating is not. This pins that `EnvStore`
        // reports absence rather than erroring or panicking.
        let e = EnvStore;
        let key = SecretRef::new("target/does-not-exist-4242").unwrap();
        assert!(e.get(&key).unwrap().is_none());
    }

    #[test]
    fn the_environment_backend_refuses_to_store() {
        let mut e = EnvStore;
        assert!(!e.writable());
        assert!(matches!(
            e.put(&SecretRef::for_target(1), &Secret::new("v")),
            Err(SecretError::ReadOnly { .. })
        ));
    }

    #[test]
    fn a_missing_secret_names_the_reference() {
        let dir = tmpdir("missing");
        let store = SecretStore::with_keyfile(dir.join("s.json"));
        let key = SecretRef::new("target/4242").unwrap();
        let err = store.require(&key).unwrap_err();
        assert!(err.to_string().contains("target/4242"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_chain_is_inspectable_for_doctor() {
        let store = SecretStore::with_keyfile("/tmp/x.json");
        assert_eq!(store.chain(), vec!["environment", "keyfile"]);
    }

    #[test]
    fn a_partially_written_keyfile_does_not_replace_a_good_one() {
        // The rename-based write, asserted from the outside: after a successful
        // put there is no leftover temp file, and the real file parses.
        let dir = tmpdir("atomic");
        let path = dir.join("secrets.json");
        let mut ks = KeyfileStore::new(&path);
        ks.put(&SecretRef::for_target(1), &Secret::new("v"))
            .unwrap();
        assert!(
            !path.with_extension("tmp").exists(),
            "temp file left behind"
        );
        assert!(ks.get(&SecretRef::for_target(1)).unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }
}
