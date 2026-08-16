//! The event-subscription contract: sequence numbers, bounded buffering,
//! resume cursors and snapshot recovery.
//!
//! # Why this is more than fire-and-forget
//!
//! §4.3 gives events one job — "lets CLI and UI observe identical state"
//! (AC-60) — and that is only true if a client that misses frames can *tell*.
//! A stream with no sequence numbers cannot distinguish "nothing happened" from
//! "I was disconnected for four seconds during a 10M-file scan", so the two
//! observers silently diverge and the divergence is invisible in exactly the
//! situation that produces it.
//!
//! Four mechanisms, each answering a specific failure:
//!
//! | failure | mechanism |
//! |---|---|
//! | a frame is lost or reordered | [`Seq`], strictly increasing, no gaps within a stream |
//! | the client reconnects | `resume_from` on [`crate::request::SubscribeRequest`] |
//! | the client was away longer than the daemon can buffer | [`ResumeOutcome::SnapshotRequired`] |
//! | a slow client would grow the daemon's memory without bound | [`EventBuffer`] evicts oldest-first |
//!
//! The third row is the one worth stating plainly: **a bounded buffer means
//! resume can fail, and a resume contract that cannot fail is a lie about
//! memory.** So the failure is a first-class outcome carrying the oldest
//! sequence still held, and the client's recovery is defined — take a snapshot
//! by calling the ordinary read methods, then subscribe from `next_seq`.
//!
//! # What is here and what is the daemon's
//!
//! This module is pure data and one pure data structure. [`EventBuffer`] does no
//! I/O, spawns nothing and knows nothing about connections; it is here rather
//! than in `shepherd-daemon` so the eviction and resume arithmetic — the part
//! that is easy to get subtly wrong and hard to observe in production — is unit
//! testable in the crate that defines the contract. Fan-out to connections,
//! backpressure on a slow socket and the snapshot itself are the daemon's
//! (task T6).

use std::collections::VecDeque;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A monotonic per-daemon-run event sequence number.
///
/// Numbering is **global across streams**, not per stream. One counter means a
/// client holds one cursor no matter how many streams it subscribes to, and the
/// relative order of a `ScanProgress` and the `JobTransition` it caused is
/// preserved. The cost is that a client subscribed to one stream sees gaps in
/// the numbers it receives; that is expected and is why the contract is "no
/// gaps in what the daemon *emitted*", not "no gaps in what you received".
///
/// Sequence numbers restart at 1 on daemon restart. A resume cursor is
/// therefore only meaningful within one run, which is why
/// [`SubscribeResult::epoch`] exists.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
pub struct Seq(pub u64);

impl Seq {
    /// The cursor meaning "before the first event". Never the sequence of a
    /// real frame — emission starts at 1 — so `resume_from: 0` unambiguously
    /// means "everything you still hold".
    pub const ZERO: Seq = Seq(0);

    pub const fn next(self) -> Seq {
        Seq(self.0 + 1)
    }
}

impl std::fmt::Display for Seq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The named event streams.
///
/// A closed enum on purpose: a client subscribes by name, and an unknown stream
/// name should be a clear error at subscribe time rather than a silent
/// never-delivers. Adding a stream is a minor bump.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventStream {
    /// Job queue transitions (§6 Phase 1's queue core).
    Job,
    /// Scan and walk progress.
    Scan,
    /// Index build progress.
    Index,
    /// Tiering, verification and restore progress.
    Tier,
    /// Power and network state changes (Phase 4 populates it; the stream is
    /// declared now so the Dashboard's contract does not change then).
    Power,
    /// Target reachability and scrub results.
    Target,
}

impl EventStream {
    pub const ALL: &'static [EventStream] = &[
        EventStream::Job,
        EventStream::Scan,
        EventStream::Index,
        EventStream::Tier,
        EventStream::Power,
        EventStream::Target,
    ];

    /// The `snake_case` wire name, matching the serde representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            EventStream::Job => "job",
            EventStream::Scan => "scan",
            EventStream::Index => "index",
            EventStream::Tier => "tier",
            EventStream::Power => "power",
            EventStream::Target => "target",
        }
    }
}

/// One event, as delivered.
///
/// Sent as a JSON-RPC notification (`method: "event"`, no `id`), which is what
/// lets events share the connection with request/response traffic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EventFrame {
    pub seq: Seq,
    pub stream: EventStream,
    /// Nanoseconds since the Unix epoch, from the daemon's clock.
    pub emitted_at: i64,
    pub payload: EventPayload,
}

/// The event payloads.
///
/// Internally tagged on `kind`, so an unknown payload is distinguishable from a
/// malformed one and a client can log "kind=x, ignored" instead of failing.
/// Adding a variant is a minor bump; a client built earlier must tolerate one it
/// does not know, which is why [`EventPayload::Unknown`] exists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventPayload {
    JobTransition {
        job_id: i64,
        class: String,
        from: String,
        to: String,
        #[serde(default)]
        attempts: u32,
        #[serde(default)]
        last_error: Option<String>,
    },
    ScanProgress {
        root_id: i64,
        files_seen: u64,
        bytes_seen: u64,
        #[serde(default)]
        current_path: Option<String>,
        done: bool,
    },
    IndexProgress {
        rows_indexed: u64,
        #[serde(default)]
        rows_total: Option<u64>,
        done: bool,
    },
    TierProgress {
        plan_id: String,
        target_id: i64,
        files_done: u64,
        files_total: u64,
        bytes_done: u64,
        bytes_total: u64,
        #[serde(default)]
        phase: Option<String>,
    },
    PowerState {
        on_battery: bool,
        #[serde(default)]
        metered_network: bool,
        #[serde(default)]
        detail: Option<String>,
    },
    TargetHealth {
        target_id: i64,
        reachable: bool,
        #[serde(default)]
        detail: Option<String>,
    },
    /// A payload kind this build does not know.
    ///
    /// Serde's untagged-fallback position: it must be **last**, and it captures
    /// the tag so a client can log what it skipped. Without it, a Phase 1 UI
    /// would hard-fail on the first Phase 5 event.
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

/// The answer to `events.subscribe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SubscribeResult {
    pub subscription_id: u64,
    /// Identifies this daemon *run*. A cursor from a different epoch cannot be
    /// resumed — sequence numbers restart at 1 — and the daemon answers
    /// [`ResumeOutcome::SnapshotRequired`] rather than replaying the wrong
    /// events with the right numbers.
    pub epoch: String,
    pub resume: ResumeOutcome,
    /// The sequence the next delivered frame will carry. A client that wants to
    /// reconnect later stores the highest `seq` it actually processed, not this.
    pub next_seq: Seq,
    /// The streams actually subscribed, expanded if the request named none.
    pub streams: Vec<EventStream>,
}

/// What happened to the client's resume request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ResumeOutcome {
    /// No cursor was supplied. Delivery starts with the next event produced.
    Fresh,
    /// The cursor was in the buffer. Buffered frames after it are replayed
    /// before live delivery resumes.
    Resumed {
        from: Seq,
        /// How many buffered frames are being replayed.
        replayed: u64,
    },
    /// The cursor is unusable and the client **must** re-read state through the
    /// ordinary methods before trusting the stream.
    ///
    /// This is not an error frame; the subscription is live and starts at
    /// `next_seq`. Only the client's belief about the past is invalid.
    SnapshotRequired {
        reason: SnapshotReason,
        /// The oldest sequence the daemon still holds, so a client can report
        /// how far behind it fell.
        oldest_available: Seq,
    },
}

/// Why a resume could not be honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotReason {
    /// The cursor is older than the oldest buffered frame: the client was away
    /// longer than the bound allows.
    CursorEvicted,
    /// The cursor belongs to a previous daemon run.
    EpochChanged,
    /// The cursor is ahead of anything the daemon has emitted — a client
    /// carrying state from a daemon that was reinstalled or rolled back.
    CursorAhead,
}

// ---------------------------------------------------------------------------
// The bounded buffer
// ---------------------------------------------------------------------------

/// Default retained-frame bound.
///
/// Chosen as a *frame count* rather than a byte budget because the payloads
/// above are small and bounded in shape, so count is a faithful proxy and is far
/// cheaper to reason about at the eviction site. If a later phase adds a payload
/// carrying user-controlled text of unbounded length, this must become a byte
/// budget — recorded here rather than discovered then.
pub const DEFAULT_EVENT_BUFFER_FRAMES: usize = 4096;

/// A bounded, in-order event buffer with resume support.
///
/// Pure data: no I/O, no clock, no allocation policy beyond the bound. The
/// daemon owns one of these per run and fans out from it.
#[derive(Debug, Clone)]
pub struct EventBuffer {
    frames: VecDeque<EventFrame>,
    capacity: usize,
    last_seq: Seq,
    /// Total frames evicted. Diagnostic: a nonzero value with no client
    /// reporting `SnapshotRequired` means the bound is doing its job.
    evicted: u64,
}

impl EventBuffer {
    /// # Panics
    /// If `capacity` is zero. A zero-capacity buffer would report
    /// `SnapshotRequired` for every resume including one issued microseconds
    /// earlier, which is a configuration mistake, not a runtime condition.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "event buffer capacity must be positive");
        Self {
            frames: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            last_seq: Seq::ZERO,
            evicted: 0,
        }
    }

    /// Assign the next sequence number and retain the frame, evicting the
    /// oldest if the bound is reached.
    pub fn push(&mut self, stream: EventStream, emitted_at: i64, payload: EventPayload) -> Seq {
        self.last_seq = self.last_seq.next();
        let frame = EventFrame {
            seq: self.last_seq,
            stream,
            emitted_at,
            payload,
        };
        if self.frames.len() == self.capacity {
            self.frames.pop_front();
            self.evicted += 1;
        }
        self.frames.push_back(frame);
        self.last_seq
    }

    /// The sequence the next pushed frame will carry.
    pub fn next_seq(&self) -> Seq {
        self.last_seq.next()
    }

    /// The highest sequence emitted so far. [`Seq::ZERO`] before the first push.
    pub fn last_seq(&self) -> Seq {
        self.last_seq
    }

    /// The oldest sequence still retained, or [`Seq::ZERO`] if empty.
    pub fn oldest_available(&self) -> Seq {
        self.frames.front().map_or(Seq::ZERO, |f| f.seq)
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Resolve a resume request.
    ///
    /// Returns the outcome and, when resumable, the frames to replay — filtered
    /// to `streams` if it is non-empty.
    pub fn resume(
        &self,
        resume_from: Option<Seq>,
        streams: &[EventStream],
    ) -> (ResumeOutcome, Vec<EventFrame>) {
        let Some(cursor) = resume_from else {
            return (ResumeOutcome::Fresh, Vec::new());
        };

        // A cursor ahead of what this daemon has ever emitted. Replaying from
        // the start would hand the client frames it believes it has already
        // seen, under numbers it has already used.
        if cursor > self.last_seq {
            return (
                ResumeOutcome::SnapshotRequired {
                    reason: SnapshotReason::CursorAhead,
                    oldest_available: self.oldest_available(),
                },
                Vec::new(),
            );
        }

        // `cursor` means "I have processed everything up to and including this",
        // so the client needs `cursor + 1` onward. It is resumable when that
        // frame is still held — or when the client is already fully caught up,
        // in which case there is nothing to replay and nothing was missed.
        let caught_up = cursor == self.last_seq;
        let have_next = self.frames.front().is_some_and(|f| f.seq <= cursor.next());
        if !caught_up && !have_next {
            return (
                ResumeOutcome::SnapshotRequired {
                    reason: SnapshotReason::CursorEvicted,
                    oldest_available: self.oldest_available(),
                },
                Vec::new(),
            );
        }

        let replay: Vec<EventFrame> = self
            .frames
            .iter()
            .filter(|f| f.seq > cursor)
            .filter(|f| streams.is_empty() || streams.contains(&f.stream))
            .cloned()
            .collect();

        (
            ResumeOutcome::Resumed {
                from: cursor,
                replayed: replay.len() as u64,
            },
            replay,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(root_id: i64, n: u64) -> EventPayload {
        EventPayload::ScanProgress {
            root_id,
            files_seen: n,
            bytes_seen: n * 1024,
            current_path: None,
            done: false,
        }
    }

    fn buf_with(capacity: usize, n: u64) -> EventBuffer {
        let mut b = EventBuffer::new(capacity);
        for i in 1..=n {
            b.push(EventStream::Scan, i as i64, scan(1, i));
        }
        b
    }

    #[test]
    fn sequences_start_at_one_and_never_repeat() {
        let mut b = EventBuffer::new(8);
        assert_eq!(b.last_seq(), Seq::ZERO);
        assert_eq!(b.next_seq(), Seq(1));
        let a = b.push(EventStream::Job, 0, scan(1, 1));
        let c = b.push(EventStream::Scan, 0, scan(1, 2));
        assert_eq!((a, c), (Seq(1), Seq(2)));
    }

    #[test]
    fn sequences_are_global_across_streams() {
        // One cursor covers every stream, and causal order survives.
        let mut b = EventBuffer::new(8);
        b.push(EventStream::Scan, 0, scan(1, 1));
        b.push(EventStream::Job, 0, scan(1, 2));
        b.push(EventStream::Scan, 0, scan(1, 3));
        let seqs: Vec<u64> = b.frames.iter().map(|f| f.seq.0).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn no_cursor_is_a_fresh_subscription() {
        let b = buf_with(8, 3);
        let (outcome, replay) = b.resume(None, &[]);
        assert_eq!(outcome, ResumeOutcome::Fresh);
        assert!(replay.is_empty());
    }

    #[test]
    fn a_live_cursor_replays_exactly_what_was_missed() {
        let b = buf_with(8, 5);
        let (outcome, replay) = b.resume(Some(Seq(2)), &[]);
        assert_eq!(
            outcome,
            ResumeOutcome::Resumed {
                from: Seq(2),
                replayed: 3
            }
        );
        assert_eq!(
            replay.iter().map(|f| f.seq.0).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "the cursor is inclusive: the client already has 2"
        );
    }

    #[test]
    fn a_caught_up_cursor_resumes_with_nothing_to_replay() {
        let b = buf_with(8, 5);
        let (outcome, replay) = b.resume(Some(Seq(5)), &[]);
        assert_eq!(
            outcome,
            ResumeOutcome::Resumed {
                from: Seq(5),
                replayed: 0
            }
        );
        assert!(replay.is_empty());
    }

    #[test]
    fn resume_from_zero_replays_everything_still_held() {
        let b = buf_with(8, 3);
        let (outcome, replay) = b.resume(Some(Seq::ZERO), &[]);
        assert!(matches!(
            outcome,
            ResumeOutcome::Resumed { replayed: 3, .. }
        ));
        assert_eq!(replay.len(), 3);
    }

    #[test]
    fn the_buffer_is_bounded_and_evicts_oldest_first() {
        let b = buf_with(4, 10);
        assert_eq!(b.len(), 4);
        assert_eq!(b.evicted(), 6);
        assert_eq!(b.oldest_available(), Seq(7));
        assert_eq!(b.last_seq(), Seq(10));
    }

    #[test]
    fn an_evicted_cursor_demands_a_snapshot_and_says_how_far_behind() {
        // The failure a bounded buffer makes possible, surfaced rather than
        // papered over by replaying from the start.
        let b = buf_with(4, 10);
        let (outcome, replay) = b.resume(Some(Seq(2)), &[]);
        assert_eq!(
            outcome,
            ResumeOutcome::SnapshotRequired {
                reason: SnapshotReason::CursorEvicted,
                oldest_available: Seq(7)
            }
        );
        assert!(
            replay.is_empty(),
            "a partial replay would look like a complete one to the client"
        );
    }

    #[test]
    fn the_boundary_cursor_is_resumable_and_the_one_before_it_is_not() {
        // Off-by-one at the eviction edge is the bug this file exists to
        // prevent, so the edge is pinned from both sides.
        let b = buf_with(4, 10); // holds 7..=10
        assert!(matches!(
            b.resume(Some(Seq(6)), &[]).0,
            ResumeOutcome::Resumed { .. }
        ));
        assert_eq!(b.resume(Some(Seq(6)), &[]).1.len(), 4);
        assert!(matches!(
            b.resume(Some(Seq(5)), &[]).0,
            ResumeOutcome::SnapshotRequired { .. }
        ));
    }

    #[test]
    fn a_cursor_from_the_future_demands_a_snapshot() {
        let b = buf_with(8, 3);
        assert_eq!(
            b.resume(Some(Seq(99)), &[]).0,
            ResumeOutcome::SnapshotRequired {
                reason: SnapshotReason::CursorAhead,
                oldest_available: Seq(1)
            }
        );
    }

    #[test]
    fn an_empty_buffer_can_still_be_resumed_from_zero() {
        let b = EventBuffer::new(4);
        assert_eq!(
            b.resume(Some(Seq::ZERO), &[]).0,
            ResumeOutcome::Resumed {
                from: Seq::ZERO,
                replayed: 0
            }
        );
    }

    #[test]
    fn stream_filtering_narrows_the_replay_but_not_the_numbering() {
        let mut b = EventBuffer::new(8);
        b.push(EventStream::Scan, 0, scan(1, 1));
        b.push(EventStream::Job, 0, scan(1, 2));
        b.push(EventStream::Scan, 0, scan(1, 3));
        let (_, replay) = b.resume(Some(Seq::ZERO), &[EventStream::Scan]);
        assert_eq!(
            replay.iter().map(|f| f.seq.0).collect::<Vec<_>>(),
            vec![1, 3],
            "gaps in a filtered stream are expected; the numbers stay global"
        );
    }

    #[test]
    fn an_unknown_payload_kind_parses_instead_of_failing() {
        // A Phase 1 client receiving a Phase 5 event.
        let f: EventFrame = serde_json::from_str(
            r#"{"seq":9,"stream":"index","emitted_at":0,
                "payload":{"kind":"embedding_progress","done":41}}"#,
        )
        .unwrap();
        match f.payload {
            EventPayload::Unknown(v) => {
                assert_eq!(v["kind"], serde_json::json!("embedding_progress"))
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn known_payloads_round_trip() {
        let f = EventFrame {
            seq: Seq(4),
            stream: EventStream::Job,
            emitted_at: 1_700_000_000_000_000_000,
            payload: EventPayload::JobTransition {
                job_id: 12,
                class: "hash".into(),
                from: "running".into(),
                to: "done".into(),
                attempts: 1,
                last_error: None,
            },
        };
        let j = serde_json::to_value(&f).unwrap();
        assert_eq!(j["payload"]["kind"], serde_json::json!("job_transition"));
        assert_eq!(serde_json::from_value::<EventFrame>(j).unwrap(), f);
    }

    #[test]
    fn every_stream_has_a_wire_name_matching_its_serde_form() {
        for s in EventStream::ALL {
            let j = serde_json::to_string(s).unwrap();
            assert_eq!(j, format!("\"{}\"", s.as_str()));
        }
        assert_eq!(EventStream::ALL.len(), 6);
    }

    #[test]
    #[should_panic(expected = "capacity must be positive")]
    fn a_zero_capacity_buffer_is_a_configuration_error() {
        let _ = EventBuffer::new(0);
    }
}
