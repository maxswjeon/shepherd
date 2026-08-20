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
    inner: Mutex<Inner>,
    epoch: String,
    next_id: AtomicU64,
}

impl EventHub {
    /// `epoch` must differ between daemon runs. [`Self::new_for_run`] derives
    /// one; tests pass a fixed value.
    pub fn new(capacity: usize, epoch: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                buffer: EventBuffer::new(capacity),
                subscribers: Vec::new(),
            }),
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
    /// Returns the result frame, the frames to replay before live delivery, the
    /// receiver the connection pumps, and the overflow flag.
    ///
    /// The flag is what the pump reads once the channel closes, to distinguish
    /// "this subscriber fell behind and was cut off" — where the socket must be
    /// shut down so the client learns of it — from an ordinary shutdown, where
    /// it must not be.
    pub fn subscribe(
        &self,
        streams: Vec<EventStream>,
        resume_from: Option<Seq>,
        client_epoch: Option<&str>,
    ) -> (
        SubscribeResult,
        Vec<EventFrame>,
        Receiver<EventFrame>,
        Arc<AtomicBool>,
    ) {
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
        (result, replay, rx, overflowed)
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
        let (_, _, rx, _) = hub.subscribe(vec![EventStream::Scan], None, None);

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
        let (result, _, rx, _) = hub.subscribe(vec![], None, None);
        assert_eq!(result.streams, EventStream::ALL.to_vec());
        hub.publish(EventStream::Power, scan(1));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn resuming_replays_only_what_was_missed() {
        let hub = EventHub::new(64, "e1");
        for i in 1..=5 {
            hub.publish(EventStream::Scan, scan(i));
        }
        let (result, replay, _rx, _) = hub.subscribe(vec![], Some(Seq(3)), Some("e1"));
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
        let (result, replay, _rx, _) = hub.subscribe(vec![], Some(Seq(3)), Some("run-1"));
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
        let (_, _, slow, _) = hub.subscribe(vec![], None, None);
        let (_, _, fast, fast_overflowed) = hub.subscribe(vec![], None, None);

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
        let (_, _, slow, slow_overflowed) = hub.subscribe(vec![], None, None);
        let (_, _, fast, _) = hub.subscribe(vec![], None, None);

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
        let (_, _, rx, overflowed) = hub.subscribe(vec![], None, None);

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

    #[test]
    fn a_disconnected_subscriber_is_reaped() {
        let hub = EventHub::new(64, "e1");
        {
            let (_, _, _rx, _) = hub.subscribe(vec![], None, None);
            assert_eq!(hub.subscriber_count(), 1);
        }
        // The receiver dropped with the scope; the next publish notices.
        hub.publish(EventStream::Scan, scan(1));
        assert_eq!(hub.subscriber_count(), 0);
    }

    #[test]
    fn subscription_ids_are_distinct() {
        let hub = EventHub::new(64, "e1");
        let (a, _, _ra, _) = hub.subscribe(vec![], None, None);
        let (b, _, _rb, _) = hub.subscribe(vec![], None, None);
        assert_ne!(a.subscription_id, b.subscription_id);
    }
}
