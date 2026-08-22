//! The shared error type.
//!
//! `shepherd-core` performs no I/O, so this enum carries **no** `std::io::Error`
//! variant — an I/O error is described here as data (`path`, `detail`) by the
//! crate that hit it. That keeps rule 1 ("`shepherd-core` depends on nothing
//! internal") from being quietly undermined by a core type that only makes
//! sense to an I/O caller.
//!
//! The variant that matters most is [`CoreError::Unprovable`]. §4.10 requires
//! the destroy path to **fail closed** on unprovable identity: if the system
//! cannot prove the remote copy matches, it must not destroy the local one.
//! Giving that outcome its own variant means it cannot be flattened into a
//! generic failure and then handled by a `_ =>` arm that proceeds anyway.

use std::fmt;

use serde::{Deserialize, Serialize};

pub type Result<T, E = CoreError> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A value did not satisfy an invariant of its type.
    #[error("invalid {what}: {detail}")]
    Invalid { what: String, detail: String },

    /// A required entity was not present.
    #[error("{what} not found: {key}")]
    NotFound { what: String, key: String },

    /// The operation is legal but refused by policy — a safety floor, a
    /// deny-list entry, a user ignore rule, or a disabled capability.
    #[error("refused by {policy}: {reason}")]
    Refused { policy: String, reason: String },

    /// Identity could not be proven, so the caller must **not** proceed.
    ///
    /// The destroy path treats this as terminal by construction (§4.10:
    /// "fail-closed on unprovable identity"). It is never a retry signal.
    #[error("identity unprovable for {subject}: {reason} — failing closed")]
    Unprovable { subject: String, reason: String },

    /// An I/O failure, described as data because this crate does no I/O.
    #[error("io error at {path}: {detail}")]
    Io { path: String, detail: String },

    /// A precondition of a multi-step operation no longer holds.
    #[error("precondition failed: {detail}")]
    Precondition { detail: String },
}

impl CoreError {
    pub fn invalid(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Invalid {
            what: what.into(),
            detail: detail.into(),
        }
    }

    pub fn not_found(what: impl Into<String>, key: impl fmt::Display) -> Self {
        Self::NotFound {
            what: what.into(),
            key: key.to_string(),
        }
    }

    pub fn refused(policy: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Refused {
            policy: policy.into(),
            reason: reason.into(),
        }
    }

    pub fn unprovable(subject: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Unprovable {
            subject: subject.into(),
            reason: reason.into(),
        }
    }

    /// Whether retrying could plausibly succeed.
    ///
    /// [`CoreError::Unprovable`] and [`CoreError::Refused`] are **never**
    /// retryable: retrying a fail-closed decision is how a fail-closed system
    /// becomes a fail-open one.
    pub fn is_retryable(&self) -> bool {
        matches!(self, CoreError::Io { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_errors_are_never_retryable() {
        assert!(!CoreError::unprovable("remote object", "version missing").is_retryable());
        assert!(!CoreError::refused("safety floor", "file is open").is_retryable());
        assert!(
            CoreError::Io {
                path: "/x".into(),
                detail: "EAGAIN".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn messages_name_the_subject() {
        let e = CoreError::unprovable("s3://bucket/key", "no version id");
        assert!(e.to_string().contains("s3://bucket/key"));
        assert!(e.to_string().contains("failing closed"));
    }
}
