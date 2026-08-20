//! The event hub: the daemon-side half of `shepherd_proto::event`.
//!
//! `shepherd-proto` owns the *contract* — sequence numbers, the bounded
//! [`EventBuffer`], the resume outcomes — and it is pure data with no I/O. This
//! is the part that has connections in it: fan-out to subscribers, and the
//! per-run epoch.
//!
//! # The epoch
//!
//! Sequence numbers restart at 1 every time the daemon starts, so a cursor from
//! a previous run names a *different* event under the same number. The epoch is
//! what makes that detectable: a client resuming with a cursor from another
//! epoch is told [`SnapshotReason::EpochChanged`] and re-reads state, rather
//! than being replayed the wrong events with the right numbers.
//!
//! # Slow subscribers do not block the daemon — they are disconnected
//!
//! Each subscription gets a bounded channel. A subscriber that stops draining
//! it fills up, and the publisher must not block on it — one stalled UI would
//! otherwise stall a scan.
//!
//! It used to keep the subscription alive and drop the frame, on the reasoning
//! that sequence numbers make the loss detectable: the client sees a gap and
//! its next resume gets `SnapshotRequired`. **That reasoning does not hold for
//! a filtered subscription**, which is most of them. Sequence numbers are
//! global, so a client subscribed to `scan` alone sees gaps whenever anything
//! else is published — that is normal, and documented as normal in
//! `shepherd_proto::event`. It therefore cannot tell "I lost frames" from "the
//! daemon published something I filtered out". And if the burst ends after the
//! drop there may be no later frame to expose the gap at all, so the client sits
//! connected, indefinitely, believing stale state.
//!
//! So overflow **ends the subscription**. The hub drops the subscriber, which
//! closes its channel; the connection's pump drains what is still queued,
//! writes it, and then shuts the socket down. The client observes EOF — an
//! unambiguous signal, unlike a gap — and recovers by subscribing again with
//! its cursor. That path works where gap-detection could not: at the default
//! capacity the buffer (`DEFAULT_EVENT_BUFFER_FRAMES`, 4096) holds sixteen
//! times the per-subscriber queue, so a reconnect usually replays every missed
//! frame losslessly, and `EventBuffer::resume` filters by the streams the
//! client asked for. When it cannot — the buffer is a constructor parameter,
//! and a small one narrows this — the client is told `SnapshotRequired`
//! outright. Either way it is told something.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use shepherd_proto::event::{
    EventBuffer, EventFrame, EventPayload, EventStream, ResumeOutcome, Seq, SnapshotReason,
    SubscribeResult,
};

/// Frames buffered per subscriber before the daemon starts dropping for them.
pub const SUBSCRIBER_QUEUE: usize = 256;

struct Subscriber {
    id: u64,
    streams: Vec<EventStream>,
    tx: SyncSender<EventFrame>,
    /// Set when this subscriber's queue overflowed, immediately before it is
    /// unregistered. Shared with the connection's pump, which is otherwise
    /// unable to tell an overflow from an ordinary shutdown — both reach it as
    /// a closed channel, and only one of them should shut the socket down.
    overflowed: Arc<AtomicBool>,
}

impl Subscriber {
    fn wants(&self, stream: EventStream) -> bool {
        self.streams.is_empty() || self.streams.contains(&stream)
    }
}

struct Inner {
    buffer: EventBuffer,
    subscribers: Vec<Subscriber>,
}

/// Fan-out over one [`EventBuffer`].
pub struct EventHub {
    /// `Arc` so a [`SubscriptionGuard`] can hold a `Weak` to it and unregister
    /// without a lifetime tying every connection to the hub's borrow.
    inner: Arc<Mutex<Inner>>,
    epoch: String,
    next_id: AtomicU64,
}

/// What [`EventHub::subscribe`] hands back.
///
/// A struct rather than a tuple because of `guard`: in a tuple it is one `_`
/// away from being dropped at the end of the statement that created it, which
/// unregisters the subscription the caller just made and reads like nothing.
pub struct Subscription {
    pub result: SubscribeResult,
    /// Frames to write before live delivery begins.
    pub replay: Vec<EventFrame>,
    pub rx: Receiver<EventFrame>,
    /// Set if this subscriber is unregistered for falling behind, so the pump
    /// can tell that from an ordinary shutdown.
    pub overflowed: Arc<AtomicBool>,
    /// **Keep this for as long as the connection lives.** See
    /// [`SubscriptionGuard`].
    pub guard: SubscriptionGuard,
}

/// Unregisters its subscription from the hub when dropped.
///
/// The connection that made the subscription holds it; when that connection
/// ends — EOF, a write error, an oversized frame — the guard drops and the
/// subscriber goes with it.
///
/// Without one, nothing ever removed a subscriber whose client had gone away
/// while its streams were quiet. [`EventHub::publish`] only probes the senders
/// of subscribers that WANT the stream being published, so a client subscribed
/// to `target` alone is untouched by an hour of scan traffic: its pump stays
/// parked on `recv`, and the thread, the channel, the subscriber entry and the
/// socket handle all outlive the connection. Ordinary reconnects then grow the
/// daemon without bound.
///
/// Dropping closes the channel, which is the signal the pump already
/// understands as "stop" — and with `overflowed` still false, so it exits
/// quietly instead of shutting down a socket that has already gone.
pub struct SubscriptionGuard {
    /// `Weak`, so a guard outliving its hub — a connection thread still
    /// unwinding as the daemon shuts down — neither keeps the buffer alive nor
    /// panics.
    inner: std::sync::Weak<Mutex<Inner>>,
    id: u64,
}

impl SubscriptionGuard {
    /// The subscription this guard ends; the same id the client was told.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut inner = inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.subscribers.retain(|s| s.id != self.id);
    }
}

impl EventHub {
    /// `epoch` must differ between daemon runs. [`Self::new_for_run`] derives
    /// one; tests pass a fixed value.
    pub fn new(capacity: usize, epoch: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                buffer: EventBuffer::new(capacity),
                subscribers: Vec::new(),
            })),
            epoch: epoch.into(),
            next_id: AtomicU64::new(1),
        }
    }

    /// An epoch for this process: start time plus pid.
    ///
    /// Not a UUID — no dependency, and uniqueness only has to hold against
    /// *this machine's previous runs*, which a nanosecond start time plus a pid
    /// already gives. A client only ever compares it for equality.
    pub fn new_for_run(capacity: usize) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self::new(capacity, format!("{nanos:x}-{}", std::process::id()))
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// Record an event and fan it out. Never blocks on a slow subscriber.
    pub fn publish(&self, stream: EventStream, payload: EventPayload) -> Seq {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = inner.buffer.push(stream, now, payload.clone());
        let frame = EventFrame {
            seq,
            stream,
            emitted_at: now,
            payload,
        };

        inner.subscribers.retain_mut(|s| {
            if !s.wants(stream) {
                return true;
            }
            match s.tx.try_send(frame.clone()) {
                Ok(()) => true,
                // Not keeping up. The frame is lost either way — the queue is
                // full and the publisher will not block. What is NOT lost is
                // the client's knowledge that it happened: the subscription
                // ends here, the flag tells the pump to shut the socket, and
                // EOF is a signal a filtered subscriber can actually act on
                // where a sequence gap is not. See the module docs.
                //
                // Set before the subscriber is dropped, so the pump cannot
                // observe the closed channel while the flag still reads false.
                Err(TrySendError::Full(_)) => {
                    s.overflowed.store(true, Ordering::SeqCst);
                    tracing::warn!(
                        subscription = s.id,
                        "subscriber is not keeping up; ending its subscription. It will see \
                         EOF and can resume from its cursor."
                    );
                    false
                }
                // Receiver gone: the connection closed. Reap it.
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
        seq
    }

    /// Register a subscription.
    ///
    /// The caller must keep [`Subscription::guard`] alive for exactly as long
    /// as the connection: dropping it is what unregisters the subscriber, and
    /// it is the only thing that does so for a subscription whose streams stay
    /// quiet.
    pub fn subscribe(
        &self,
        streams: Vec<EventStream>,
        resume_from: Option<Seq>,
        client_epoch: Option<&str>,
    ) -> Subscription {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // A cursor from another run names a different event under the same
        // number, so it is rejected before the buffer is even consulted.
        let stale_epoch = client_epoch.is_some_and(|e| e != self.epoch);
        let (resume, replay) = if stale_epoch {
            (
                ResumeOutcome::SnapshotRequired {
                    reason: SnapshotReason::EpochChanged,
                    oldest_available: inner.buffer.oldest_available(),
                },
                Vec::new(),
            )
        } else {
            inner.buffer.resume(resume_from, &streams)
        };

        let (tx, rx) = sync_channel(SUBSCRIBER_QUEUE);
        let overflowed = Arc::new(AtomicBool::new(false));
        inner.subscribers.push(Subscriber {
            id,
            streams: streams.clone(),
            tx,
            overflowed: Arc::clone(&overflowed),
        });

        let result = SubscribeResult {
            subscription_id: id,
            epoch: self.epoch.clone(),
            resume,
            next_seq: inner.buffer.next_seq(),
            streams: if streams.is_empty() {
                EventStream::ALL.to_vec()
            } else {
                streams
            },
        };
        Subscription {
            result,
            replay,
            rx,
            overflowed,
            guard: SubscriptionGuard {
                inner: Arc::downgrade(&self.inner),
                id,
            },
        }
    }

    /// Live subscriber count, for `status` and tests.
    pub fn subscriber_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subscribers
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(n: u64) -> EventPayload {
        EventPayload::ScanProgress {
            root_id: 1,
            files_seen: n,
            bytes_seen: n,
            current_path: None,
            done: false,
        }
    }

    #[test]
    fn a_subscriber_receives_what_it_asked_for_and_nothing_else() {
        let hub = EventHub::new(64, "e1");
        let sub = hub.subscribe(vec![EventStream::Scan], None, None);
        let rx = &sub.rx;

        hub.publish(EventStream::Scan, scan(1));
        hub.publish(EventStream::Job, scan(2));
        hub.publish(EventStream::Scan, scan(3));

        let a = rx.try_recv().unwrap();
        let b = rx.try_recv().unwrap();
        assert!(
            rx.try_recv().is_err(),
            "the job frame must not be delivered"
        );
        assert_eq!((a.seq, b.seq), (Seq(1), Seq(3)));
        assert_eq!((a.stream, b.stream), (EventStream::Scan, EventStream::Scan));
    }

    #[test]
    fn an_empty_stream_list_subscribes_to_everything() {
        let hub = EventHub::new(64, "e1");
        let sub = hub.subscribe(vec![], None, None);
        let rx = &sub.rx;
        assert_eq!(sub.result.streams, EventStream::ALL.to_vec());
        hub.publish(EventStream::Power, scan(1));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn resuming_replays_only_what_was_missed() {
        let hub = EventHub::new(64, "e1");
        for i in 1..=5 {
            hub.publish(EventStream::Scan, scan(i));
        }
        let sub = hub.subscribe(vec![], Some(Seq(3)), Some("e1"));
        let (result, replay) = (&sub.result, &sub.replay);
        assert!(matches!(
            result.resume,
            ResumeOutcome::Resumed { replayed: 2, .. }
        ));
        assert_eq!(
            replay.iter().map(|f| f.seq.0).collect::<Vec<_>>(),
            vec![4, 5]
        );
        assert_eq!(result.next_seq, Seq(6));
    }

    /// The reason the epoch exists. A cursor from a previous run must not be
    /// honoured against this run's numbering.
    #[test]
    fn a_cursor_from_another_epoch_demands_a_snapshot() {
        let hub = EventHub::new(64, "run-2");
        for i in 1..=5 {
            hub.publish(EventStream::Scan, scan(i));
        }
        let sub = hub.subscribe(vec![], Some(Seq(3)), Some("run-1"));
        let (result, replay) = (&sub.result, &sub.replay);
        assert!(
            matches!(
                result.resume,
                ResumeOutcome::SnapshotRequired {
                    reason: SnapshotReason::EpochChanged,
                    ..
                }
            ),
            "{:?}",
            result.resume
        );
        assert!(replay.is_empty());
        assert_eq!(result.epoch, "run-2");
    }

    #[test]
    fn each_run_gets_a_distinct_epoch() {
        let a = EventHub::new_for_run(8);
        let b = EventHub::new_for_run(8);
        assert_ne!(a.epoch(), b.epoch());
        assert!(!a.epoch().is_empty());
    }

    /// A stalled subscriber must not stall the publisher, and must not stall
    /// the *other subscribers* either.
    ///
    /// ORACLE CHANGED. This test used to end on `subscriber_count() == 2` under
    /// the comment "it lost frames, it was not disconnected" — it asserted, as
    /// the desired outcome, precisely the behaviour the review found to be the
    /// defect. What it was actually guarding is kept and sharpened here: the
    /// publisher completes without blocking, and the subscriber that kept up
    /// loses nothing to its neighbour's stall. Whether the stalled one survives
    /// is now the subject of its own test, with the opposite answer.
    ///
    /// So: if you are here because a subscriber vanished and you are wondering
    /// whether that was intended — it was. See the module docs for why a
    /// sequence gap could not carry that news to a filtered subscriber.
    #[test]
    fn a_slow_subscriber_does_not_stall_the_publisher_or_its_peers() {
        let hub = EventHub::new(4096, "e1");
        let slow = hub.subscribe(vec![], None, None);
        let fast_sub = hub.subscribe(vec![], None, None);
        let (fast, fast_overflowed) = (&fast_sub.rx, &fast_sub.overflowed);

        let total = SUBSCRIBER_QUEUE as u64 + 50;
        let mut delivered = 0;
        for i in 0..total {
            hub.publish(EventStream::Scan, scan(i));
            // Keep the fast one drained.
            if fast.try_recv().is_ok() {
                delivered += 1;
            }
        }
        // Reaching here at all is the never-blocked assertion.
        assert_eq!(
            delivered, total,
            "a stalled peer must not cost a healthy subscriber a single frame"
        );
        assert!(!fast_overflowed.load(Ordering::SeqCst));
        drop(slow);
    }

    /// A subscriber whose queue overflows is **disconnected**, not left behind.
    ///
    /// The old behaviour kept it registered and relied on the client noticing a
    /// sequence gap. That recovery cannot work for a filtered subscription:
    /// sequence numbers are global, so gaps caused by streams the client did
    /// not request are normal and documented as such — the client has no way to
    /// tell "I lost frames" from "the daemon published something I filtered
    /// out". And if the burst ends after the drop, there may be no later frame
    /// to expose the gap at all. So the subscription is ended, the client sees
    /// EOF, and it recovers through `subscribe` with its cursor — the path that
    /// actually works, because `EventBuffer::resume` is filter-aware.
    #[test]
    fn a_subscriber_whose_queue_overflows_is_disconnected() {
        let hub = EventHub::new(4096, "e1");
        let slow = hub.subscribe(vec![], None, None);
        let slow_overflowed = Arc::clone(&slow.overflowed);
        let fast_sub = hub.subscribe(vec![], None, None);
        let fast = &fast_sub.rx;

        for i in 0..(SUBSCRIBER_QUEUE as u64 + 50) {
            hub.publish(EventStream::Scan, scan(i));
            // Keep the fast one drained.
            let _ = fast.try_recv();
        }

        assert!(
            slow_overflowed.load(Ordering::SeqCst),
            "the overflow must be recorded, or the pump cannot tell this from a clean shutdown"
        );
        assert_eq!(
            hub.subscriber_count(),
            1,
            "the overflowing subscriber must be gone; leaving it registered is the defect"
        );
        drop(slow);
    }

    /// The accepting direction, so "disconnect everyone" cannot pass.
    ///
    /// A subscriber that keeps up stays registered and keeps receiving. Without
    /// this, a `publish` that dropped every subscriber on the first `try_send`
    /// would satisfy the test above and deliver no events at all.
    #[test]
    fn a_subscriber_that_keeps_up_is_never_disconnected() {
        let hub = EventHub::new(4096, "e1");
        let sub = hub.subscribe(vec![], None, None);
        let (rx, overflowed) = (&sub.rx, &sub.overflowed);

        for i in 0..(SUBSCRIBER_QUEUE as u64 * 4) {
            hub.publish(EventStream::Scan, scan(i));
            rx.try_recv().expect("a drained subscriber loses nothing");
        }

        assert!(
            !overflowed.load(Ordering::SeqCst),
            "nothing was ever dropped"
        );
        assert_eq!(
            hub.subscriber_count(),
            1,
            "a subscriber that kept up must still be subscribed"
        );
    }

    /// A receiver that goes away is noticed by the next publish **on a stream
    /// that subscriber wanted**. That qualifier is why the guard below exists.
    #[test]
    fn a_disconnected_subscriber_is_reaped_by_the_next_publish() {
        let hub = EventHub::new(64, "e1");
        let sub = hub.subscribe(vec![], None, None);
        // The guard is held deliberately: this test is about the OTHER
        // mechanism, so the receiver alone is dropped.
        let _guard = sub.guard;
        drop(sub.rx);
        assert_eq!(hub.subscriber_count(), 1, "nothing has published yet");

        hub.publish(EventStream::Scan, scan(1));
        assert_eq!(hub.subscriber_count(), 0);
    }

    /// The guard, and the leak it closes.
    ///
    /// A client subscribed to `target` alone hangs up. `publish` only probes
    /// the senders of subscribers that WANT the stream being published, so no
    /// amount of scan traffic touches it: before the guard, this subscriber
    /// stayed registered indefinitely, its connection's pump stayed parked on
    /// `recv`, and the thread, channel, subscriber entry and socket handle went
    /// with it. Ordinary reconnects grew the daemon without bound.
    ///
    /// The publishes are the load-bearing part of this test. Without them it
    /// would pass on the reaping path above and prove nothing.
    #[test]
    fn dropping_the_guard_unregisters_a_subscriber_no_publish_would_reach() {
        let hub = EventHub::new(64, "e1");
        let sub = hub.subscribe(vec![EventStream::Target], None, None);
        assert_eq!(hub.subscriber_count(), 1);

        // Traffic on a stream it did not ask for: the sender is never probed.
        for i in 1..=10 {
            hub.publish(EventStream::Scan, scan(i));
        }
        assert_eq!(
            hub.subscriber_count(),
            1,
            "precondition: publishing an unwanted stream must not reap it, or \
             this test would be measuring the wrong mechanism"
        );

        // The connection ends.
        drop(sub);
        assert_eq!(
            hub.subscriber_count(),
            0,
            "the subscriber outlived its connection; only the guard can end a \
             subscription whose streams stay quiet"
        );
    }

    #[test]
    fn subscription_ids_are_distinct() {
        let hub = EventHub::new(64, "e1");
        let a = hub.subscribe(vec![], None, None);
        let b = hub.subscribe(vec![], None, None);
        assert_ne!(a.result.subscription_id, b.result.subscription_id);
    }
}
