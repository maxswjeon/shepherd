//! One place that configures the `tracing` subscriber.
//!
//! The daemon, `shepctl` and the test harnesses all call [`init_tracing`], so
//! every process emits the same shape and honours the same `SHEPHERD_LOG`
//! filter. Calling it more than once is not an error — a global subscriber can
//! only be installed once, and a second call reports that rather than panicking,
//! because a library that aborts the process over its logging setup is a worse
//! outcome than one that logs a little less.

use tracing_subscriber::EnvFilter;

/// Environment variable controlling the log filter, e.g. `shepherd_tier=debug`.
pub const LOG_ENV: &str = "SHEPHERD_LOG";

/// Install the global tracing subscriber.
///
/// Returns `false` if a subscriber was already installed.
pub fn init_tracing(default_directive: &str) -> bool {
    let filter =
        EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(default_directive));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false)
        .try_init()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent_and_reports_the_second_call() {
        let first = init_tracing("info");
        let second = init_tracing("info");
        // Whichever call installs the subscriber, exactly one of them may
        // succeed and neither may panic. Other tests in this binary may have
        // installed it first, so assert the invariant, not the order.
        assert!(!(first && second), "two installs must not both succeed");
    }
}
