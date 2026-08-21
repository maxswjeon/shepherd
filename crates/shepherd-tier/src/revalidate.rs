//! §4.10.2 — the remote side is identity-bound, and fails closed.
//!
//! # Two mechanisms, and why B exists
//!
//! Iteration 2 recognised only provider-version identity, which read literally
//! made **SMB, NFS and non-versioned S3 buckets permanently
//! destruction-ineligible** — voiding tiering on the entire NAS family the
//! product ships. §4.10.2 calls that "an unintended product hole, not a safety
//! decision", and adds content self-attestation:
//!
//! * **A — provider version.** `object_version` pinned at verify; a cheap HEAD
//!   after the local hash re-reads it and **genuinely re-attests**, because
//!   version ids are immutable. Deletion is version-scoped so a discard cannot
//!   destroy a *replacement*.
//! * **B — content self-attestation.** §4.9 commits the BLAKE3 into the key, so
//!   a full re-read hashing to the expected value proves *this key holds
//!   exactly these bytes*. AC-1 already mandates that re-read, so B is free.
//! * **Neither → destruction refused, permanently.**
//!
//! # What the closing HEAD does and does not prove
//!
//! Under A it is a real re-attestation. **Under B it is existence and size
//! only** — it catches deletion and truncation, and it does **not** catch a
//! same-size content replacement. §4.10.2 refuses to present it as
//! revalidation, and [`ClosingCheck::reattests`] carries that distinction so no
//! call site can quietly assume the stronger reading.
//!
//! # The ordering, and why it is this way round
//!
//! Exactly one of the local hash and the remote check can finish at ≈ *T*, the
//! unlink. §4.10.2 puts the **local hash second-to-last** and a cheap HEAD last,
//! because the two hazards are not equally likely: a process holding a writable
//! descriptor — an editor, a sync client, a backup agent — is *ordinary*,
//! whereas the remote hazard needs someone with direct target access
//! deliberately writing mismatched bytes to a hash-named key. Minimise the
//! window on the plausible hazard.
//!
//! The cost is stated rather than hidden: the local-fd window is one HEAD round
//! trip, **10–100 ms** (not the "microseconds" iteration 4 claimed), and under
//! mechanism B the remote window is the local-hash duration plus that HEAD —
//! seconds to minutes on a large file (D-11, OQ-I).

use shepherd_core::{Blake3Hash, ObjectVersion, TargetId, Timestamp};
use shepherd_storage::adapter::AttestationMode;

/// How a location's state stands, per §4.4's `object_location.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationState {
    Pending,
    Verified,
    /// Lost, but another location still holds the content. §4.10.2's predicate
    /// admits this for the ∀ clause; a plain `Lost` does not.
    LostButReplicated,
    Lost,
}

/// One remote copy, as the destroy predicate sees it.
#[derive(Debug, Clone)]
pub struct Location {
    pub target: TargetId,
    pub state: LocationState,
    pub attestation: AttestationMode,
    /// §4.4's invariant: a third-party (plugin-backed) target is never
    /// custody-eligible. Such locations **count as replicas but never satisfy
    /// the ∃ clause**.
    pub custody_eligible: bool,
    pub last_full_hash_verified_at: Option<Timestamp>,
    /// OQ-1: the replica publication receipt for this location.
    pub publication_receipt_ok: bool,
    /// Pinned at verify. Present only under [`AttestationMode::Version`].
    pub object_version: Option<ObjectVersion>,
    pub expected_hash: Blake3Hash,
}

impl Location {
    /// Whether this location can, on its own, authorise destroying the last
    /// local copy.
    fn satisfies_custody(&self, now: Timestamp, window: std::time::Duration) -> bool {
        self.state_holds_the_object()
            && self.custody_eligible
            && self.attestation.permits_destruction()
            && self.publication_receipt_ok
            && self.verified_within(now, window)
    }

    /// Whether this location is known to hold the object **now**.
    ///
    /// Every other conjunct of [`Self::satisfies_custody`] is a *historical*
    /// fact — an attestation timestamp, a receipt, a pinned version — and a
    /// location keeps all of them when it transitions out of `Verified`. The
    /// state is therefore the only field that distinguishes "this copy exists"
    /// from "this copy is known to be gone", which makes it the one that must
    /// not be omitted from a predicate authorising destruction of the sole
    /// local copy.
    ///
    /// **Exhaustive, with no `_` arm, deliberately.** A `LocationState` added
    /// later must not default into counting as custody; the compiler is what
    /// forces the author to decide. This is the same convention the rules-side
    /// safety predicate uses.
    fn state_holds_the_object(&self) -> bool {
        match self.state {
            LocationState::Verified => true,
            // `Pending` was never confirmed. `Lost` is known not to hold it.
            // `LostButReplicated` is the subtle one: it says *some other*
            // location still has the content, which is exactly why §4.10.2
            // admits it for the ∀ clause — and says nothing whatever about
            // this location, which is why it cannot satisfy the ∃ clause.
            LocationState::Pending | LocationState::Lost | LocationState::LostButReplicated => {
                false
            }
        }
    }

    fn verified_within(&self, now: Timestamp, window: std::time::Duration) -> bool {
        let Some(at) = self.last_full_hash_verified_at else {
            return false;
        };
        let age_nanos = now.as_nanos().saturating_sub(at.as_nanos());
        age_nanos >= 0 && (age_nanos as u128) <= window.as_nanos()
    }
}

/// Why destruction was refused. Every variant is a fail-closed exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestroyRefusal {
    /// No location is both custody-eligible and attested within the window.
    NoAttestedCustodian { examined: usize },
    /// A location the rule asked for was never reached. §4.10.2: "a rule
    /// requesting two targets does not get to destroy the original because one
    /// succeeded."
    RequiredLocationNotReached {
        target: TargetId,
        state: LocationState,
    },
    /// The root is gated (PM-3 resync / availability, or D-12
    /// `destruction_ineligible`).
    RootRefuses { reason: String },
    /// The closing check failed.
    ClosingCheckFailed { detail: String },
}

/// A location this predicate has ACCEPTED, and the only kind
/// `execute_local_destruction` takes.
///
/// # Why a token rather than a `&Location`
///
/// The destroy path was handed a bare reference with a doc comment saying it
/// had "already been checked against §4.10.2's N-location predicate by
/// `destroy_permitted`". That is a comment, and the path's own checks are about
/// BINDING — target, prefix, hash, key — not about custody: a location that is
/// stale, `Pending`, `Lost`, missing its publication receipt, or on a
/// plugin-backed target that is not custody-eligible passes every one of them.
/// Under content attestation the closing HEAD then proves only size and
/// existence, so the sole local copy is unlinked on the strength of a location
/// the predicate would have refused.
///
/// This type cannot be constructed anywhere else — the field is private and
/// there is no constructor — so "the predicate said yes" becomes something a
/// caller must OBTAIN rather than something it can assert. Same move as
/// `PreparedIntent`, for the same reason: a claim in a comment is not a claim
/// the compiler checks.
#[derive(Debug, Clone, Copy)]
pub struct PermittedCustodian<'a>(&'a Location);

impl<'a> PermittedCustodian<'a> {
    /// The location the predicate accepted.
    pub fn location(&self) -> &'a Location {
        self.0
    }
}

impl std::ops::Deref for PermittedCustodian<'_> {
    type Target = Location;

    fn deref(&self) -> &Location {
        self.0
    }
}

/// §4.10.2's N-location destroy predicate.
///
/// ```text
/// destroy_permitted(file) =
///       ∃ L : L.state = verified ∧ L.custody_eligible ∧ L.attestation ≠ none
///                                ∧ L.verified_within(window)
///                                ∧ L.publication_receipt_ok
///   AND ∀ L required by the rule : L.state ∈ {verified, lost-but-replicated}
/// ```
///
/// In words: **at least one location must currently hold the object, and be
/// fully attested and custody-eligible**, and **every location the rule asked
/// for must have been reached**. Note the two clauses read `state` to different
/// standards on purpose: the ∃ clause demands `verified`, because it is
/// asserting that *this* copy exists, while the ∀ clause also admits
/// `lost-but-replicated`, because it is only asserting that the replication the
/// user asked for was carried out somewhere. The two clauses do different jobs — the first says the content
/// survives somewhere trustworthy, the second says the user's replication
/// intent was honoured — and satisfying only one is not a partial pass, it is a
/// refusal.
pub fn destroy_permitted<'a>(
    locations: &'a [Location],
    required: &[TargetId],
    now: Timestamp,
    window: std::time::Duration,
) -> std::result::Result<PermittedCustodian<'a>, DestroyRefusal> {
    // ∀ clause first: it is cheaper and its failure is the more informative
    // message.
    for target in required {
        let reached = locations.iter().find(|l| l.target == *target);
        match reached {
            Some(l)
                if matches!(
                    l.state,
                    LocationState::Verified | LocationState::LostButReplicated
                ) => {}
            Some(l) => {
                return Err(DestroyRefusal::RequiredLocationNotReached {
                    target: *target,
                    state: l.state,
                });
            }
            None => {
                return Err(DestroyRefusal::RequiredLocationNotReached {
                    target: *target,
                    state: LocationState::Pending,
                });
            }
        }
    }

    // The state clause lives inside `satisfies_custody`, not here. It was once
    // conjoined at this call site, which closed the hole for *this* caller
    // while leaving the predicate that is named for the question answering it
    // wrongly — so a second caller would have inherited a fail-open default.
    locations
        .iter()
        .find(|l| l.satisfies_custody(now, window))
        .map(PermittedCustodian)
        .ok_or(DestroyRefusal::NoAttestedCustodian {
            examined: locations.len(),
        })
}

/// The closing cheap HEAD of §4.10.2's ordering — step 3 of four.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingCheck {
    pub mode: AttestationMode,
    /// Version read back by the HEAD, under mechanism A.
    pub observed_version: Option<ObjectVersion>,
    pub observed_size: Option<u64>,
}

impl ClosingCheck {
    /// Whether this check genuinely re-attests identity.
    ///
    /// `true` only under mechanism A. Under B the answer is `false` and the
    /// caller must not treat a pass as proof the bytes are unchanged — it
    /// proves existence and size, nothing more.
    pub fn reattests(&self) -> bool {
        self.mode.head_reattests()
    }

    /// Evaluate the check against what was pinned at verify.
    pub fn evaluate(
        &self,
        pinned_version: Option<&ObjectVersion>,
        expected_size: u64,
    ) -> std::result::Result<(), DestroyRefusal> {
        match self.observed_size {
            None => {
                return Err(DestroyRefusal::ClosingCheckFailed {
                    detail: "object absent at the closing HEAD — it was deleted between \
                             verification and destruction"
                        .into(),
                });
            }
            Some(size) if size != expected_size => {
                return Err(DestroyRefusal::ClosingCheckFailed {
                    detail: format!(
                        "object truncated or replaced: expected {expected_size} bytes, HEAD \
                         reports {size}"
                    ),
                });
            }
            Some(_) => {}
        }

        if self.mode == AttestationMode::Version {
            match (pinned_version, self.observed_version.as_ref()) {
                (Some(pinned), Some(observed)) if pinned == observed => Ok(()),
                (Some(pinned), Some(observed)) => Err(DestroyRefusal::ClosingCheckFailed {
                    detail: format!(
                        "version changed between verify and destroy: pinned {}, now {}",
                        pinned.as_opaque(),
                        observed.as_opaque()
                    ),
                }),
                _ => Err(DestroyRefusal::ClosingCheckFailed {
                    detail: "mechanism A requires a version on both sides, and one is missing \
                             — failing closed rather than degrading to a size check"
                        .into(),
                }),
            }
        } else {
            // Mechanism B. Deliberately NOT presented as re-attestation.
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

    /// ~3.2 years after the epoch, so that a `from_nanos(1)` verification is
    /// genuinely older than a 30-day window. The first version of this fixture
    /// used 1e12 ns — 1000 seconds — which is *inside* the window, so the
    /// "stale" test was asserting against a fresh timestamp and failed. Worth
    /// keeping the note: a time fixture that is wrong by six orders of
    /// magnitude still looks plausible.
    fn now() -> Timestamp {
        Timestamp::from_nanos(100_000_000_000_000_000)
    }

    fn loc(target: i64) -> Location {
        Location {
            target: TargetId::new(target),
            state: LocationState::Verified,
            attestation: AttestationMode::Version,
            custody_eligible: true,
            last_full_hash_verified_at: Some(Timestamp::from_nanos(
                100_000_000_000_000_000 - 1_000_000_000,
            )),
            publication_receipt_ok: true,
            object_version: Some(ObjectVersion::new("v1")),
            expected_hash: Blake3Hash::from_bytes([1; 32]),
        }
    }

    #[test]
    fn a_single_attested_custodian_permits_destruction() {
        let l = vec![loc(1)];
        assert!(destroy_permitted(&l, &[TargetId::new(1)], now(), WINDOW).is_ok());
    }

    /// The accepting direction, on the predicate itself. A custody check fixed
    /// into "never eligible" would pass every refusal test below and silently
    /// disable tiering, so the pair is load-bearing.
    #[test]
    fn a_verified_location_satisfies_custody() {
        assert!(
            loc(1).satisfies_custody(now(), WINDOW),
            "a fully attested Verified location must still authorise destruction"
        );
    }

    /// The ∃ clause reads `L.custody_eligible ∧ …`, and the location's *state*
    /// is what says whether L still holds the object at all. A location that
    /// has transitioned to `Pending`, `Lost` or `LostButReplicated` keeps its
    /// previous attestation timestamp and receipt, so every other conjunct
    /// still passes — the state is the only thing that distinguishes them.
    ///
    /// Asserted against `satisfies_custody` directly, because that is the
    /// function whose name claims to answer the question.
    #[test]
    fn a_location_that_does_not_hold_the_object_never_satisfies_custody() {
        for state in [
            LocationState::Pending,
            LocationState::Lost,
            LocationState::LostButReplicated,
        ] {
            let mut l = loc(1);
            l.state = state;
            assert!(
                !l.satisfies_custody(now(), WINDOW),
                "{state:?} still satisfied the ∃ clause: this location is not known to hold \
                 the object, and it would authorise destroying the sole local copy"
            );
        }
    }

    /// The whole-predicate view of the same fact. `destroy_permitted` must
    /// refuse outright — not merely fail to pick this location — when the only
    /// candidate is in a state that does not hold the object.
    #[test]
    fn destroy_permitted_refuses_a_custodian_that_does_not_hold_the_object() {
        for state in [
            LocationState::Pending,
            LocationState::Lost,
            LocationState::LostButReplicated,
        ] {
            let mut l = loc(1);
            l.state = state;
            assert_eq!(
                destroy_permitted(&[l], &[], now(), WINDOW).unwrap_err(),
                DestroyRefusal::NoAttestedCustodian { examined: 1 },
                "{state:?} was accepted as the sole custodian"
            );
        }
    }

    /// The ∃ clause: a third-party target counts as a replica but can never
    /// authorise destruction (§4.4's invariant).
    #[test]
    fn a_third_party_location_never_satisfies_the_existential_clause() {
        let mut l = loc(1);
        l.custody_eligible = false;
        let err = destroy_permitted(&[l], &[], now(), WINDOW).unwrap_err();
        assert_eq!(err, DestroyRefusal::NoAttestedCustodian { examined: 1 });
    }

    #[test]
    fn a_target_with_no_attestation_never_authorises_destruction() {
        let mut l = loc(1);
        l.attestation = AttestationMode::None;
        let err = destroy_permitted(&[l], &[], now(), WINDOW).unwrap_err();
        assert!(matches!(err, DestroyRefusal::NoAttestedCustodian { .. }));
    }

    #[test]
    fn a_stale_verification_does_not_authorise_destruction() {
        let mut l = loc(1);
        l.last_full_hash_verified_at = Some(Timestamp::from_nanos(1));
        let err = destroy_permitted(&[l], &[], now(), WINDOW).unwrap_err();
        assert!(matches!(err, DestroyRefusal::NoAttestedCustodian { .. }));
    }

    #[test]
    fn a_never_verified_location_does_not_authorise_destruction() {
        let mut l = loc(1);
        l.last_full_hash_verified_at = None;
        assert!(destroy_permitted(&[l], &[], now(), WINDOW).is_err());
    }

    #[test]
    fn a_missing_publication_receipt_refuses() {
        let mut l = loc(1);
        l.publication_receipt_ok = false;
        assert!(destroy_permitted(&[l], &[], now(), WINDOW).is_err());
    }

    /// The ∀ clause, and the sentence §4.10.2 spells out: "a rule requesting two
    /// targets does not get to destroy the original because one succeeded."
    #[test]
    fn one_of_two_required_targets_is_not_enough() {
        let good = loc(1);
        let mut pending = loc(2);
        pending.state = LocationState::Pending;

        let err = destroy_permitted(
            &[good, pending],
            &[TargetId::new(1), TargetId::new(2)],
            now(),
            WINDOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DestroyRefusal::RequiredLocationNotReached {
                target: TargetId::new(2),
                state: LocationState::Pending,
            }
        );
    }

    #[test]
    fn a_required_target_that_was_never_attempted_refuses() {
        let err = destroy_permitted(&[loc(1)], &[TargetId::new(9)], now(), WINDOW).unwrap_err();
        assert!(matches!(
            err,
            DestroyRefusal::RequiredLocationNotReached { .. }
        ));
    }

    /// `lost-but-replicated` satisfies the ∀ clause; a plain `lost` does not.
    #[test]
    fn lost_but_replicated_satisfies_the_universal_clause() {
        let good = loc(1);
        let mut lost = loc(2);
        lost.state = LocationState::LostButReplicated;
        assert!(
            destroy_permitted(
                &[good.clone(), lost],
                &[TargetId::new(1), TargetId::new(2)],
                now(),
                WINDOW
            )
            .is_ok()
        );

        let mut really_lost = loc(2);
        really_lost.state = LocationState::Lost;
        assert!(
            destroy_permitted(
                &[good, really_lost],
                &[TargetId::new(1), TargetId::new(2)],
                now(),
                WINDOW
            )
            .is_err()
        );
    }

    // --- the closing check ---

    #[test]
    fn mechanism_a_head_is_a_real_reattestation() {
        let c = ClosingCheck {
            mode: AttestationMode::Version,
            observed_version: Some(ObjectVersion::new("v1")),
            observed_size: Some(100),
        };
        assert!(c.reattests());
        assert!(c.evaluate(Some(&ObjectVersion::new("v1")), 100).is_ok());
    }

    #[test]
    fn mechanism_a_refuses_when_the_version_moved() {
        let c = ClosingCheck {
            mode: AttestationMode::Version,
            observed_version: Some(ObjectVersion::new("v2")),
            observed_size: Some(100),
        };
        let err = c
            .evaluate(Some(&ObjectVersion::new("v1")), 100)
            .unwrap_err();
        assert!(matches!(err, DestroyRefusal::ClosingCheckFailed { .. }));
    }

    /// Mechanism A with a version missing on either side fails closed rather
    /// than silently degrading to mechanism B's weaker check.
    #[test]
    fn mechanism_a_without_a_version_fails_closed_rather_than_degrading() {
        let c = ClosingCheck {
            mode: AttestationMode::Version,
            observed_version: None,
            observed_size: Some(100),
        };
        assert!(c.evaluate(Some(&ObjectVersion::new("v1")), 100).is_err());
    }

    /// **The honest limit.** Under B the closing HEAD catches deletion and
    /// truncation and nothing else — a same-size content replacement passes.
    /// §4.10.2 refuses to call it revalidation, and so does this test.
    #[test]
    fn mechanism_b_head_catches_deletion_and_truncation_only() {
        let c = ClosingCheck {
            mode: AttestationMode::Content,
            observed_version: None,
            observed_size: Some(100),
        };
        assert!(!c.reattests(), "B's HEAD is not a re-attestation");

        // Deletion.
        let gone = ClosingCheck {
            observed_size: None,
            ..c.clone()
        };
        assert!(gone.evaluate(None, 100).is_err());
        // Truncation.
        let short = ClosingCheck {
            observed_size: Some(50),
            ..c.clone()
        };
        assert!(short.evaluate(None, 100).is_err());
        // Same-size replacement: PASSES, and that is the documented residual.
        assert!(
            c.evaluate(None, 100).is_ok(),
            "a same-size replacement is not detectable by a HEAD — what actually bounds \
             this is content addressing, since different bytes belong under a different key"
        );
    }
}
