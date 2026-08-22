//! A small in-process metrics registry.
//!
//! Counters are monotonic; gauges are not. Both are `AtomicU64`/`AtomicI64` so
//! any thread may record without holding the registry lock — the lock is taken
//! only to *find* or *create* an instrument, which happens once per name.
//!
//! [`Registry::snapshot`] exists because §9's gates assert on metric values
//! ("zero content bytes uploaded", "processes zero absences", "N bound per
//! platform and the gate FAILS above it"). A metric that could only be scraped
//! over a network endpoint would make those assertions harder to write than
//! they need to be.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// A monotonically increasing count.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn incr(&self) {
        self.add(1);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A value that may move in either direction.
#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    pub fn set(&self, v: i64) {
        self.0.store(v, Ordering::Relaxed);
    }

    pub fn add(&self, delta: i64) {
        self.0.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A point-in-time read of every instrument.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub counters: BTreeMap<String, u64>,
    pub gauges: BTreeMap<String, i64>,
}

/// The process-wide instrument registry.
#[derive(Debug, Default, Clone)]
pub struct Registry {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    counters: RwLock<BTreeMap<String, Arc<Counter>>>,
    gauges: RwLock<BTreeMap<String, Arc<Gauge>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the counter named `name`.
    pub fn counter(&self, name: &str) -> Arc<Counter> {
        if let Some(c) = self
            .inner
            .counters
            .read()
            .ok()
            .and_then(|m| m.get(name).map(Arc::clone))
        {
            return c;
        }
        let mut m = self
            .inner
            .counters
            .write()
            .expect("metrics registry lock poisoned");
        // `Arc::clone`: the registry keeps the counter and hands out handles
        // to the same one — a copy here would be a metric nobody can see.
        Arc::clone(m.entry(name.to_string()).or_default())
    }

    /// Get or create the gauge named `name`.
    pub fn gauge(&self, name: &str) -> Arc<Gauge> {
        if let Some(g) = self
            .inner
            .gauges
            .read()
            .ok()
            .and_then(|m| m.get(name).map(Arc::clone))
        {
            return g;
        }
        let mut m = self
            .inner
            .gauges
            .write()
            .expect("metrics registry lock poisoned");
        Arc::clone(m.entry(name.to_string()).or_default())
    }

    pub fn snapshot(&self) -> Snapshot {
        let counters = self
            .inner
            .counters
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.get())).collect())
            .unwrap_or_default();
        let gauges = self
            .inner
            .gauges
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.get())).collect())
            .unwrap_or_default();
        Snapshot { counters, gauges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_name_returns_the_same_instrument() {
        let r = Registry::new();
        r.counter("scan.files").add(3);
        r.counter("scan.files").add(4);
        assert_eq!(r.counter("scan.files").get(), 7);
    }

    #[test]
    fn snapshot_reads_every_instrument() {
        let r = Registry::new();
        r.counter("upload.bytes").add(1024);
        r.gauge("queue.depth").set(5);
        r.gauge("queue.depth").add(-2);
        let s = r.snapshot();
        assert_eq!(s.counters.get("upload.bytes"), Some(&1024));
        assert_eq!(s.gauges.get("queue.depth"), Some(&3));
    }

    #[test]
    fn registry_clones_share_state() {
        let a = Registry::new();
        let b = a.clone();
        b.counter("x").incr();
        assert_eq!(a.counter("x").get(), 1);
    }

    #[test]
    fn counters_are_shared_across_threads() {
        let r = Registry::new();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let r = r.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    r.counter("hits").incr();
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(r.counter("hits").get(), 8000);
    }
}
