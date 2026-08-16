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
//! # Slow subscribers do not block the daemon
//!
//! Each subscription gets a bounded channel. A subscriber that stops draining
//! it fills up, and further sends to it are **dropped** rather than blocking
//! the publisher — which would let one stalled UI stall a scan. Dropping is
//! safe precisely because the sequence numbers make it detectable: the client
//! sees a gap, and its next resume gets `SnapshotRequired`. A silent drop with
//! no numbering would be the unsafe version.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Frames dropped because this subscriber was not keeping up. Diagnostic:
    /// a nonzero value explains a gap the client will otherwise report as
    /// corruption.
    dropped: u64,
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
                Err(TrySendError::Full(_)) => {
                    s.dropped += 1;
                    if s.dropped == 1 {
                        tracing::warn!(
                            subscription = s.id,
                            "subscriber is not keeping up; dropping frames. It will see a \
                             sequence gap and can recover with a snapshot."
                        );
                    }
                    true
                }
                // Receiver gone: the connection closed. Reap it.
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
        seq
    }

    /// Register a subscription.
    ///
    /// Returns the result frame, the frames to replay before live delivery, and
    /// the receiver the connection pumps.
    pub fn subscribe(
        &self,
        streams: Vec<EventStream>,
        resume_from: Option<Seq>,
        client_epoch: Option<&str>,
    ) -> (SubscribeResult, Vec<EventFrame>, Receiver<EventFrame>) {
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
        inner.subscribers.push(Subscriber {
            id,
            streams: streams.clone(),
            tx,
            dropped: 0,
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
        (result, replay, rx)
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
        let (_, _, rx) = hub.subscribe(vec![EventStream::Scan], None, None);

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
        let (result, _, rx) = hub.subscribe(vec![], None, None);
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
        let (result, replay, _rx) = hub.subscribe(vec![], Some(Seq(3)), Some("e1"));
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
        let (result, replay, _rx) = hub.subscribe(vec![], Some(Seq(3)), Some("run-1"));
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

    /// A stalled subscriber must not stall the publisher. Dropping is safe
    /// because the sequence numbers make the gap detectable.
    #[test]
    fn a_slow_subscriber_is_dropped_from_not_blocking_everyone_else() {
        let hub = EventHub::new(4096, "e1");
        let (_, _, slow) = hub.subscribe(vec![], None, None);
        let (_, _, fast) = hub.subscribe(vec![], None, None);

        for i in 0..(SUBSCRIBER_QUEUE as u64 + 50) {
            hub.publish(EventStream::Scan, scan(i));
            // Keep the fast one drained.
            let _ = fast.try_recv();
        }
        // The publisher never blocked, and the slow subscriber is still
        // registered — it lost frames, it was not disconnected.
        assert_eq!(hub.subscriber_count(), 2);
        drop(slow);
    }

    #[test]
    fn a_disconnected_subscriber_is_reaped() {
        let hub = EventHub::new(64, "e1");
        {
            let (_, _, _rx) = hub.subscribe(vec![], None, None);
            assert_eq!(hub.subscriber_count(), 1);
        }
        // The receiver dropped with the scope; the next publish notices.
        hub.publish(EventStream::Scan, scan(1));
        assert_eq!(hub.subscriber_count(), 0);
    }

    #[test]
    fn subscription_ids_are_distinct() {
        let hub = EventHub::new(64, "e1");
        let (a, _, _ra) = hub.subscribe(vec![], None, None);
        let (b, _, _rb) = hub.subscribe(vec![], None, None);
        assert_ne!(a.subscription_id, b.subscription_id);
    }
}
