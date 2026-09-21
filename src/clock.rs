// Time helpers shared by the modules that compare timestamps.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use worker::Date;

/// The Worker runtime's current time. `std::time::SystemTime::now()` isn't
/// usable here -- `wasm32-unknown-unknown` has no OS clock -- so this goes
/// through `worker::Date` (backed by the JS host) instead, then converts
/// into a `SystemTime` so callers can use ordinary `Duration`-based
/// arithmetic rather than raw millisecond math.
pub(crate) fn now() -> SystemTime { UNIX_EPOCH + Duration::from_millis(Date::now().as_millis()) }

/// True if `then` is at most `max_age` before `now`. Also false if `then` is
/// later than `now` (clock skew, a corrupted value):
/// `SystemTime::duration_since` returns `Err` in that case, treated the same as
/// "too old" rather than trusting a nonsensical value.
pub(crate) fn is_within(now: SystemTime, then: SystemTime, max_age: Duration) -> bool {
    now.duration_since(then).is_ok_and(|age| age < max_age)
}

/// A point in time by which something has to be finished.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline(SystemTime);

impl Deadline {
    /// A deadline `budget` from now.
    pub(crate) fn after(budget: Duration) -> Self { Self::starting_at(now(), budget) }

    /// A deadline `budget` after `start`.
    fn starting_at(start: SystemTime, budget: Duration) -> Self { Self(start + budget) }

    /// How long is left, or zero once the deadline has passed.
    pub(crate) fn remaining(self) -> Duration { self.remaining_at(now()) }

    /// How long is left as of `now`, or zero once the deadline has passed.
    fn remaining_at(self, now: SystemTime) -> Duration { self.0.duration_since(now).unwrap_or(Duration::ZERO) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deadline_remaining_counts_down_and_stops_at_zero() {
        let start = UNIX_EPOCH + Duration::from_secs(100);
        let deadline = Deadline::starting_at(start, Duration::from_secs(5));
        assert_eq!(deadline.remaining_at(start), Duration::from_secs(5));
        assert_eq!(deadline.remaining_at(start + Duration::from_secs(2)), Duration::from_secs(3));
        assert_eq!(deadline.remaining_at(start + Duration::from_secs(5)), Duration::ZERO);
        assert_eq!(deadline.remaining_at(start + Duration::from_secs(9)), Duration::ZERO);
    }

    const MAX_AGE: Duration = Duration::from_secs(10);

    #[test]
    fn test_is_within_recent() {
        let then = UNIX_EPOCH + Duration::from_secs(100);
        assert!(is_within(then + MAX_AGE - Duration::from_millis(1), then, MAX_AGE));
    }

    #[test]
    fn test_is_within_too_old() {
        let then = UNIX_EPOCH + Duration::from_secs(100);
        assert!(!is_within(then + MAX_AGE, then, MAX_AGE));
    }

    #[test]
    fn test_is_within_in_the_future_is_not_within() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        assert!(!is_within(now, now + Duration::from_millis(1), MAX_AGE));
    }
}
