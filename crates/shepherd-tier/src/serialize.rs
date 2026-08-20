//! Per-file serialization of the destroy path (§4.10, Phase-2 gate).
//!
//! The Phase 2 gate lists "per-file serialization" among the §4.10 invariants
//! it demonstrates. The reason is narrow and worth stating: two destroy
//! attempts for the same file, interleaved, can both pass their checks against
//! the *same* pre-state and then both act. The first stages and unlinks; the
//! second finds the original path gone, or worse, finds a **new** file the user
//! created at that path and stages that.
//!
//! # Two keyspaces, because there are two resources
//!
//! Local destruction is keyed on **`fs_id`, not path**. A path is a name that
//! can come to mean a different file; `fs_id` is the file. Keying on path would
//! let two attempts against the same inode under different names — a hard link,
//! a rename mid-flight — run concurrently, which is exactly the case the lock
//! exists for.
//!
//! Remote work is keyed on the **object key**, which is a *different resource*.
//! §4.9's content addressing makes the mapping many-to-one **by design**: two
//! files with identical content legitimately share one object, and that dedup is
//! a feature (AC-47), not an edge case. So `fs_id` does not serialize two
//! sessions at one key, and a caller holding a file lock is **not** protected
//! against a concurrent `adopt_or_reap` that aborts every live session at that
//! key.
//!
//! The first version of this module had only the `fs_id` keyspace while a
//! consumer relied on the key one. The lock looked present and was not.
//!
//! # You cannot acquire the wrong lock and believe you are protected
//!
//! The two keyspaces take *different types* — [`FsId`] and [`ObjectKey`] — so a
//! caller cannot pass one where the other is meant. Same discipline as
//! `ScanRoot::destroy_refusal()`: make the mistake unrepresentable rather than
//! documenting which call to make.
//!
//! This is a *liveness* guard, not the safety property. Even a perfectly
//! serialized destroy still faces §4.10.1's residual, because the hazard there
//! is another *process*, not another Shepherd task.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use shepherd_core::{FsId, ObjectKey};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// One keyspace: a map from identity string to its async lock.
type LockMap = Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>;

/// One async lock per file identity.
///
/// The map is behind a sync `Mutex` because it is only ever held long enough to
/// clone an `Arc`; the *file* lock is async because the destroy path awaits
/// storage calls while holding it.
#[derive(Debug, Default, Clone)]
pub struct FileLocks {
    files: LockMap,
    keys: LockMap,
}

impl FileLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the lock for `fs_id`, waiting if another task holds it.
    ///
    /// Returns an owned guard so the caller can hold it across `.await` points
    /// — which the destroy path must, since steps 4–6 span a remote HEAD.
    pub async fn acquire(&self, fs_id: &FsId) -> OwnedMutexGuard<()> {
        Self::lock_in(&self.files, fs_id.as_str()).await
    }

    /// Acquire the lock for one **remote object key**.
    ///
    /// A different resource from [`FileLocks::acquire`], and deliberately a
    /// different method taking a different type. `adopt_or_reap` aborts every
    /// live transfer session at a key, which is safe only underneath this.
    pub async fn acquire_key(&self, key: &ObjectKey) -> OwnedMutexGuard<()> {
        Self::lock_in(&self.keys, key.as_str()).await
    }

    /// Both locks, for an operation that touches one file *and* its object.
    ///
    /// Always in the same order — file, then key — because two call sites
    /// taking them in opposite orders is a deadlock, and the way to prevent
    /// that is to offer one function rather than a convention.
    pub async fn acquire_both(
        &self,
        fs_id: &FsId,
        key: &ObjectKey,
    ) -> (OwnedMutexGuard<()>, OwnedMutexGuard<()>) {
        let f = self.acquire(fs_id).await;
        let k = self.acquire_key(key).await;
        (f, k)
    }

    async fn lock_in(map: &LockMap, id: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut m = map.lock().expect("lock map poisoned");
            let entry = m
                .entry(id.to_string())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())));
            // `Arc::clone`, spelled out. Written as a trailing `.clone()` this
            // read like "copy the mutex", which is the one reading that must
            // never be true here: a copied `AsyncMutex` would give each caller
            // its own lock and silently turn this whole map into a no-op. What
            // is copied is the refcount; every caller for `id` gets a handle to
            // the *same* mutex, which is the entire point.
            Arc::clone(entry)
        };
        lock.lock_owned().await
    }

    /// How many distinct files have locks. Diagnostic only.
    pub fn tracked(&self) -> usize {
        self.files.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// How many distinct object keys have locks. Diagnostic only.
    pub fn tracked_keys(&self) -> usize {
        self.keys.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn two_attempts_on_one_file_do_not_overlap() {
        let locks = FileLocks::new();
        let id = FsId::new("uuid:abc:12345");
        let overlapping = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let locks = locks.clone();
            let id = id.clone();
            let overlapping = overlapping.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _g = locks.acquire(&id).await;
                let n = overlapping.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                // Yield across an await point, as the real path does over a
                // remote HEAD.
                tokio::time::sleep(Duration::from_millis(1)).await;
                overlapping.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two destroy attempts for one file must never be in flight together"
        );
    }

    /// Different files must not block each other — a global lock would make a
    /// 10M-file corpus destroy one file at a time.
    #[tokio::test]
    async fn different_files_proceed_concurrently() {
        let locks = FileLocks::new();
        let a = locks.acquire(&FsId::new("uuid:abc:1")).await;
        // If this blocked, the test would hang rather than fail — so bound it.
        let b = tokio::time::timeout(
            Duration::from_millis(500),
            locks.acquire(&FsId::new("uuid:abc:2")),
        )
        .await;
        assert!(b.is_ok(), "a different file must not wait on this one");
        drop(a);
    }

    /// Keyed on identity, not path: two names for one inode must serialize.
    #[tokio::test]
    async fn one_identity_serializes_regardless_of_how_many_names_it_has() {
        let locks = FileLocks::new();
        let id = FsId::new("uuid:abc:777");
        let held = locks.acquire(&id).await;
        let second = tokio::time::timeout(Duration::from_millis(100), locks.acquire(&id)).await;
        assert!(
            second.is_err(),
            "the same fs_id must block, however it was reached"
        );
        drop(held);
        assert!(
            tokio::time::timeout(Duration::from_millis(500), locks.acquire(&id))
                .await
                .is_ok(),
            "and must be acquirable once released"
        );
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use std::time::Duration;

    /// **The gap this keyspace closes.** Two DIFFERENT files with identical
    /// content share one object key — §4.9's dedup, working as designed. The
    /// file lock does not serialize them, because they are not the same file.
    /// Only the key lock does.
    #[tokio::test]
    async fn two_files_sharing_one_key_serialize_on_the_key_not_the_file() {
        let locks = FileLocks::new();
        let key = ObjectKey::new("p/objects/aa/bb/deadbeef");

        // Distinct files: the file lock lets them both proceed.
        let _a = locks.acquire(&FsId::new("uuid:v:1")).await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                locks.acquire(&FsId::new("uuid:v:2"))
            )
            .await
            .is_ok(),
            "two distinct files must not block each other"
        );

        // Same key: the key lock blocks, which is the protection
        // `adopt_or_reap` actually needs.
        let _held = locks.acquire_key(&key).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), locks.acquire_key(&key))
                .await
                .is_err(),
            "two sessions at one key must serialize"
        );
    }

    #[tokio::test]
    async fn the_two_keyspaces_are_independent() {
        let locks = FileLocks::new();
        let _f = locks.acquire(&FsId::new("uuid:v:9")).await;
        // Holding a file lock must not block unrelated remote work, or a
        // 10M-file corpus would upload one object at a time.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                locks.acquire_key(&ObjectKey::new("p/objects/00/11/abc"))
            )
            .await
            .is_ok()
        );
        assert_eq!(locks.tracked(), 1);
        assert_eq!(locks.tracked_keys(), 1);
    }

    /// `acquire_both` exists so two call sites cannot take the locks in
    /// opposite orders and deadlock. Taking them in a fixed order is a
    /// convention; offering one function is a guarantee.
    #[tokio::test]
    async fn acquire_both_takes_them_in_a_fixed_order() {
        let locks = FileLocks::new();
        let id = FsId::new("uuid:v:5");
        let key = ObjectKey::new("p/objects/aa/bb/cc");

        let (f, k) = locks.acquire_both(&id, &key).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), locks.acquire(&id))
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), locks.acquire_key(&key))
                .await
                .is_err()
        );
        drop((f, k));
        assert!(
            tokio::time::timeout(Duration::from_millis(500), locks.acquire_both(&id, &key))
                .await
                .is_ok()
        );
    }
}
