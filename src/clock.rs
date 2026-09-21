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

#[cfg(test)]
mod tests {
    use super::*;

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
