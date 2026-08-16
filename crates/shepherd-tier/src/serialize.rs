//! Per-file serialization of the destroy path (§4.10, Phase-2 gate).
//!
//! The Phase 2 gate lists "per-file serialization" among the §4.10 invariants
//! it demonstrates. The reason is narrow and worth stating: two destroy
//! attempts for the same file, interleaved, can both pass their checks against
//! the *same* pre-state and then both act. The first stages and unlinks; the
//! second finds the original path gone, or worse, finds a **new** file the user
//! created at that path and stages that.
//!
//! Serialization is keyed on **`fs_id`, not path**. A path is a name that can
//! come to mean a different file; `fs_id` is the file. Keying on path would let
//! two attempts against the same inode under different names — a hard link, a
//! rename mid-flight — run concurrently, which is exactly the case the lock
//! exists for.
//!
//! This is a *liveness* guard, not the safety property. Even a perfectly
//! serialized destroy still faces §4.10.1's residual, because the hazard there
//! is another *process*, not another Shepherd task.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use shepherd_core::FsId;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// One async lock per file identity.
///
/// The map is behind a sync `Mutex` because it is only ever held long enough to
/// clone an `Arc`; the *file* lock is async because the destroy path awaits
/// storage calls while holding it.
#[derive(Debug, Default, Clone)]
pub struct FileLocks {
    inner: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
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
        let lock = {
            let mut map = self.inner.lock().expect("file-lock map poisoned");
            map.entry(fs_id.as_str().to_string())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// How many distinct files have locks. Diagnostic only.
    pub fn tracked(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
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
