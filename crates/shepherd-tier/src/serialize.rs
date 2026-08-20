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

/// A held lock that gives its map entry back when it is dropped.
///
/// # Why the map cannot just keep the entry
///
/// It did, and that was a leak with a designed-for size. Every first
/// acquisition inserted a `String` and an `Arc<AsyncMutex<()>>` and nothing
/// ever removed either: dropping the returned guard released the *mutex*, not
/// the map's reference. §1's target is ten million files, `upload_item` takes
/// a file lock and usually a distinct object-key lock, and the two maps
/// therefore grew towards twenty million live entries — gigabytes of resident
/// memory in a daemon meant to run for months, and nothing to reclaim it short
/// of a restart.
///
/// # Why reclaiming is safe
///
/// The check is `strong_count == 1` **under the map lock, after this guard's
/// own `Arc` is gone**: one reference means the map holds the only one, so no
/// task holds the lock and none is waiting on it, and removing the entry
/// cannot hand a second task a different mutex for the same identity. A waiter
/// necessarily cloned the `Arc` under that same map lock before awaiting, so
/// it is counted. If the entry is removed and a later caller creates a fresh
/// mutex for that identity, that is correct — nobody was holding the old one.
pub struct FileLockGuard {
    /// `Option` so [`Drop`] can drop it EXPLICITLY, before taking the map lock.
    ///
    /// This is the load-bearing line of the whole type. `OwnedMutexGuard` holds
    /// an `Arc` to the same mutex the map does, so reading `strong_count` while
    /// still holding it would see 2 forever, reclaim nothing, and leave every
    /// test green. Field drop order would not save it either: `Drop::drop` runs
    /// before any field is dropped.
    guard: Option<OwnedMutexGuard<()>>,
    map: LockMap,
    id: String,
}

impl std::fmt::Debug for FileLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLockGuard")
            .field("id", &self.id)
            .finish()
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        // `into_inner` rather than `expect`: a panic inside a `Drop` running
        // during an unwind aborts the process, and a poisoned map is a
        // `HashMap` that was mid-clone, not a torn one.
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = m.get(&self.id)
            && Arc::strong_count(entry) == 1
        {
            m.remove(&self.id);
        }
    }
}

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
    pub async fn acquire(&self, fs_id: &FsId) -> FileLockGuard {
        Self::lock_in(&self.files, fs_id.as_str()).await
    }

    /// Acquire the lock for one **remote object key**.
    ///
    /// A different resource from [`FileLocks::acquire`], and deliberately a
    /// different method taking a different type. `adopt_or_reap` aborts every
    /// live transfer session at a key, which is safe only underneath this.
    pub async fn acquire_key(&self, key: &ObjectKey) -> FileLockGuard {
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
    ) -> (FileLockGuard, FileLockGuard) {
        let f = self.acquire(fs_id).await;
        let k = self.acquire_key(key).await;
        (f, k)
    }

    async fn lock_in(map: &LockMap, id: &str) -> FileLockGuard {
        let lock = {
            // `into_inner` on poison, matching [`FileLockGuard::drop`], which
            // cannot afford to panic at all. Refusing here while tolerating it
            // there would mean the reclaim path outlived the acquire path.
            let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = lock.lock_owned().await;
        FileLockGuard {
            guard: Some(guard),
            map: Arc::clone(map),
            id: id.to_string(),
        }
    }

    /// How many file identities are locked **right now**. Diagnostic only.
    ///
    /// Not "how many have ever been locked": entries are reclaimed when their
    /// last holder drops, so this is bounded by concurrency rather than by the
    /// number of files the daemon has processed. That is the property
    /// `a_released_lock_is_reclaimed` asserts.
    pub fn tracked(&self) -> usize {
        self.files.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// How many object keys are locked right now. Diagnostic only.
    pub fn tracked_keys(&self) -> usize {
        self.keys.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// The entry goes back when the last holder lets go.
    ///
    /// The map used to keep every identity it had ever seen. At §1's ten
    /// million files, with `upload_item` taking a file lock and usually a
    /// distinct key lock, that is twenty million live entries the daemon never
    /// reclaims.
    #[tokio::test]
    async fn a_released_lock_is_reclaimed() {
        let locks = FileLocks::new();
        for n in 0..1_000 {
            let id = FsId::new(format!("uuid:abc:{n}"));
            let key = ObjectKey::new(format!("blake3/{n}"));
            let _guards = locks.acquire_both(&id, &key).await;
            assert_eq!(locks.tracked(), 1, "one held file lock at a time");
            assert_eq!(locks.tracked_keys(), 1, "one held key lock at a time");
        }
        assert_eq!(
            (locks.tracked(), locks.tracked_keys()),
            (0, 0),
            "a thousand completed operations left entries behind; at ten million \
             files that is the leak this reclaim exists to close"
        );
    }

    /// And it does NOT go back while somebody is waiting for it.
    ///
    /// The dangerous half of reclaiming: if the entry were removed while a
    /// waiter held the same `Arc`, the next caller for that identity would mint
    /// a *different* mutex and the two would run concurrently — the lock
    /// present, and a no-op. Asserted through the map, and through
    /// `two_attempts_on_one_file_do_not_overlap`, which fails outright if a
    /// handoff ever produces two mutexes.
    #[tokio::test]
    async fn an_entry_under_a_waiter_is_not_reclaimed() {
        let locks = FileLocks::new();
        let id = FsId::new("uuid:abc:handoff");

        let a = locks.acquire(&id).await;
        assert_eq!(locks.tracked(), 1);

        let waiting = {
            let locks = locks.clone();
            let id = id.clone();
            tokio::spawn(async move { locks.acquire(&id).await })
        };
        // Let the waiter reach `lock_owned`, so its `Arc` is counted.
        while locks.tracked() != 1 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;

        drop(a);
        let b = waiting.await.expect("the waiter takes the lock");
        assert_eq!(
            locks.tracked(),
            1,
            "the entry was reclaimed out from under the task that now holds it"
        );
        drop(b);
        assert_eq!(locks.tracked(), 0, "and released once nobody holds it");
    }

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
        let taken = tokio::time::timeout(
            Duration::from_millis(200),
            locks.acquire_key(&ObjectKey::new("p/objects/00/11/abc")),
        )
        .await;
        assert!(taken.is_ok(), "a held file lock blocked an unrelated key");

        // BOUND, not dropped at the end of the statement above. Entries are
        // reclaimed the moment their last holder lets go, so a key guard left
        // as a temporary would be gone before the count below reads it — and
        // the count is what says both keyspaces are populated and separate.
        let _key_guard = taken.expect("the key lock is free");
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
