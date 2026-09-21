// What is known about Telegram's CIDR list, and the decisions made from it.
// Pure logic only: no KV, network or clock access, so it can be tested
// natively. Loading, fetching and storing live in telegram_cidrs.rs.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use ipnetwork::IpNetwork;
use worker::js_sys;

use crate::clock;

/// How long a confirmation keeps the cached list trusted: while it lasts, an
/// unrecognized IP is rejected outright rather than triggering a fetch.
pub(crate) const CIDR_LIST_MAX_AGE: Duration = Duration::from_hours(24);
/// After a fetch attempt, of any outcome, no further fetch until about this
/// long has passed (give or take `CIDR_LIST_RETRY_JITTER`), so a failing
/// Telegram endpoint isn't hit by every request.
const CIDR_LIST_RETRY_INTERVAL: Duration = Duration::from_hours(6);
/// How far either side of `CIDR_LIST_RETRY_INTERVAL` the random jitter reaches
/// (see `jittered`), spreading out retries that would otherwise all become due
/// at the same moment.
const CIDR_LIST_RETRY_JITTER: Duration = Duration::from_hours(1);
/// Once about this long has passed since Telegram last confirmed the list
/// (give or take `CIDR_LIST_FORCE_REFETCH_JITTER`), force a background re-fetch
/// even for a *recognized* IP, so the list can't drift arbitrarily far out of
/// date while every request happens to come from a known range.
const CIDR_LIST_FORCE_REFETCH_MAX_AGE: Duration = Duration::from_hours(30 * 24);
/// How far either side of `CIDR_LIST_FORCE_REFETCH_MAX_AGE` the random jitter
/// reaches (see `jittered`), so requests don't all cross the threshold at the
/// same instant.
const CIDR_LIST_FORCE_REFETCH_JITTER: Duration = Duration::from_hours(12);

/// Validate a CIDR block or plain IP string. Returns true if parseable.
/// Plain IPs (no "/") are valid and treated as /32 (IPv4) or /128 (IPv6).
fn validate_cidr_line(line: &str) -> bool {
    if line.is_empty() {
        return false;
    }
    line.parse::<IpNetwork>().is_ok()
}

/// Parse and validate CIDR list, returning only the validated entries.
/// Skips empty lines; returns None if any non-empty line is malformed or if
/// list is empty.
pub(crate) fn parse_cidr_list(content: &str) -> Option<String> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !validate_cidr_line(trimmed) {
            return None; // Any malformed line rejects entire list
        }
        entries.push(trimmed);
    }

    if entries.is_empty() {
        return None;
    }

    Some(entries.join("\n"))
}

/// The networks in `list`, skipping any line that doesn't parse.
pub(crate) fn parse_networks(list: &str) -> Vec<IpNetwork> {
    list.lines().filter_map(|line| line.trim().parse().ok()).collect()
}

/// What this isolate knows about the CIDR list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CidrSnapshot {
    /// Empty if no list has been cached.
    pub networks: Vec<IpNetwork>,
    /// When Telegram last confirmed the list: a successful fetch or a 304.
    pub fetched_at: Option<SystemTime>,
    /// When a fetch from Telegram was last attempted, whatever came of it.
    /// Throttles re-fetches without claiming the list was confirmed, which
    /// `fetched_at` must never do: it is sent as `If-Modified-Since`, and a 304
    /// against a time we never actually got the list at would keep a stale list
    /// forever.
    pub attempted_at: Option<SystemTime>,
}

impl CidrSnapshot {
    /// True if `ip` is in the list.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool { self.networks.iter().any(|network| network.contains(ip)) }

    /// The time to send as `If-Modified-Since`: when Telegram last confirmed
    /// the list, and only if a list is actually on hand. A 304 answered
    /// against anything else would leave us with a list we never received.
    pub(crate) fn if_modified_since(&self) -> Option<SystemTime> {
        if self.networks.is_empty() {
            None
        } else {
            self.fetched_at
        }
    }

    /// True if Telegram confirmed the list recently enough to reject an
    /// unrecognized IP on its strength.
    fn confirmed_recently(&self, now: SystemTime) -> bool {
        self.fetched_at.is_some_and(|at| clock::is_within(now, at, CIDR_LIST_MAX_AGE))
    }

    /// True if a fetch was attempted within `retry_interval`.
    fn attempted_recently(&self, now: SystemTime, retry_interval: Duration) -> bool {
        self.attempted_at.is_some_and(|at| clock::is_within(now, at, retry_interval))
    }

    /// The snapshot after `outcome`, as of `now`.
    pub(crate) fn after(&self, outcome: &CidrFetchOutcome, now: SystemTime) -> Self {
        let mut updated = self.clone();
        updated.attempted_at = Some(now);
        match outcome {
            CidrFetchOutcome::Updated(list) => {
                updated.networks = parse_networks(list);
                updated.fetched_at = Some(now);
            }
            CidrFetchOutcome::NotModified => updated.fetched_at = Some(now),
            CidrFetchOutcome::Rejected | CidrFetchOutcome::Unreachable => {}
        }
        updated
    }
}

/// The result of combining what this isolate remembers with what KV holds.
/// The latest timestamps win, and so does the list that was confirmed most
/// recently, preferring KV on a tie. A list is never replaced by an empty one.
pub(crate) fn merge(memory: Option<&CidrSnapshot>, kv: CidrSnapshot) -> CidrSnapshot {
    let Some(memory) = memory else { return kv };
    let memory_list_is_newer = memory.fetched_at > kv.fetched_at;
    let take_memory_list = !memory.networks.is_empty() && (memory_list_is_newer || kv.networks.is_empty());
    CidrSnapshot {
        networks: if take_memory_list { memory.networks.clone() } else { kv.networks },
        fetched_at: memory.fetched_at.max(kv.fetched_at),
        attempted_at: memory.attempted_at.max(kv.attempted_at),
    }
}

/// The randomly drawn thresholds one request applies, so concurrent requests
/// cross them at different moments.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Thresholds {
    retry_interval: Duration,
    force_refetch_max_age: Duration,
}

impl Thresholds {
    /// Fresh random thresholds.
    pub(crate) fn draw() -> Self {
        Self {
            retry_interval: jittered(CIDR_LIST_RETRY_INTERVAL, CIDR_LIST_RETRY_JITTER),
            force_refetch_max_age: jittered(CIDR_LIST_FORCE_REFETCH_MAX_AGE, CIDR_LIST_FORCE_REFETCH_JITTER),
        }
    }

    /// The thresholds with no jitter, for tests.
    #[cfg(test)]
    fn undrawn() -> Self {
        Self { retry_interval: CIDR_LIST_RETRY_INTERVAL, force_refetch_max_age: CIDR_LIST_FORCE_REFETCH_MAX_AGE }
    }
}

/// True if a request from a *recognized* IP should also start a background
/// refresh: Telegram hasn't confirmed the list for about a month and no fetch
/// was attempted recently.
pub(crate) fn background_refresh_due(snapshot: &CidrSnapshot, now: SystemTime, thresholds: Thresholds) -> bool {
    let confirmed_within_force_age =
        snapshot.fetched_at.is_some_and(|at| clock::is_within(now, at, thresholds.force_refetch_max_age));
    !snapshot.attempted_recently(now, thresholds.retry_interval) && !confirmed_within_force_age
}

/// What a request from an IP that isn't in the list should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnknownIpPlan {
    /// The list is confirmed current, so the IP really isn't Telegram's.
    Reject,
    /// The list isn't confirmed current, and a refresh was attempted too
    /// recently to try again, so the IP can't be judged.
    Unverifiable,
    /// The list isn't confirmed current and a refresh is due.
    Refresh,
}

/// What a request from an IP that isn't in the list should do.
pub(crate) fn unknown_ip_plan(snapshot: &CidrSnapshot, now: SystemTime, thresholds: Thresholds) -> UnknownIpPlan {
    if snapshot.confirmed_recently(now) {
        UnknownIpPlan::Reject
    } else if snapshot.attempted_recently(now, thresholds.retry_interval) {
        UnknownIpPlan::Unverifiable
    } else {
        UnknownIpPlan::Refresh
    }
}

/// True if a refresh has nothing to do because the list was confirmed, or a
/// fetch attempted, recently enough that the snapshot says one isn't due.
pub(crate) fn refresh_unnecessary(snapshot: &CidrSnapshot, now: SystemTime, thresholds: Thresholds) -> bool {
    snapshot.confirmed_recently(now) || snapshot.attempted_recently(now, thresholds.retry_interval)
}

/// What asking Telegram for the CIDR list came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CidrFetchOutcome {
    /// Telegram sent a valid list.
    Updated(String),
    /// Telegram confirmed the cached list is current.
    NotModified,
    /// Telegram answered, but not with a usable list.
    Rejected,
    /// Telegram couldn't be reached.
    Unreachable,
}

/// `centre` moved by a random amount up to `jitter` either way, freshly drawn
/// on every call. Concurrent requests then cross a threshold at different
/// moments, rather than all deciding at the same instant.
fn jittered(centre: Duration, jitter: Duration) -> Duration { apply_jitter(centre, jitter, js_sys::Math::random()) }

/// `centre` moved by up to `jitter` either way: `unit`, in `0.0..=1.0`, picks
/// the position across that range, with 0.5 leaving `centre` unchanged.
fn apply_jitter(centre: Duration, jitter: Duration, unit: f64) -> Duration {
    if unit < 0.5 {
        centre.saturating_sub(jitter.mul_f64(1.0 - 2.0 * unit))
    } else {
        centre.saturating_add(jitter.mul_f64(2.0 * unit - 1.0))
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    fn network(cidr: &str) -> IpNetwork { cidr.parse().expect("test network literal must parse") }

    /// A fixed "now" far enough from the epoch that every age below is a valid
    /// time.
    fn now() -> SystemTime { UNIX_EPOCH + CIDR_LIST_FORCE_REFETCH_MAX_AGE * 2 }

    fn snapshot(fetched_ago: Option<Duration>, attempted_ago: Option<Duration>) -> CidrSnapshot {
        CidrSnapshot {
            networks: vec![network("91.108.56.0/22")],
            fetched_at: fetched_ago.map(|ago| now() - ago),
            attempted_at: attempted_ago.map(|ago| now() - ago),
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn test_validate_cidr_line() {
        let cases = [
            ("91.108.56.0/22", true),
            ("0.0.0.0/0", true),
            ("192.168.1.0/24", true),
            ("2001:b28:f23d::/48", true),
            ("::/0", true),
            ("fe80::/10", true),
            ("1.2.3.4", true),     // plain IPv4
            ("2001:db8::1", true), // plain IPv6
            ("", false),
            ("not-an-ip", false),
            ("1.2.3.4/33", false),     // IPv4 prefix too large
            ("2001:db8::/129", false), // IPv6 prefix too large
            ("1.2.3.4/abc", false),    // invalid prefix
        ];
        for (input, expected) in cases {
            assert_eq!(validate_cidr_line(input), expected, "input: {input}");
        }
    }

    #[test]
    fn test_parse_cidr_list_valid() {
        let list = "91.108.56.0/22\n\n91.108.4.0/22\n1.2.3.4";
        let result = parse_cidr_list(list).expect("the test list is valid");
        assert!(result.contains("91.108.56.0/22"));
        assert!(result.contains("1.2.3.4"));
        assert_eq!(result.lines().count(), 3, "empty line should be skipped");
    }

    #[test]
    fn test_parse_cidr_list_rejects_malformed() {
        let list = "91.108.56.0/22\ninvalid-cidr\n91.108.4.0/22";
        assert!(parse_cidr_list(list).is_none());
    }

    #[test]
    fn test_parse_cidr_list_empty() {
        assert!(parse_cidr_list("").is_none());
        assert!(parse_cidr_list("\n\n").is_none());
    }

    #[test]
    fn test_contains() {
        let snapshot = CidrSnapshot {
            networks: parse_networks("91.108.56.0/22\n1.2.3.4\n2001:b28:f23d::/48"),
            ..CidrSnapshot::default()
        };
        let cases = [
            ("91.108.56.100", true),    // in IPv4 CIDR block
            ("1.2.3.4", true),          // exact plain-IP match
            ("1.2.3.5", false),         // near miss on plain IP
            ("2001:b28:f23d::1", true), // in IPv6 CIDR block
            ("2001:db8::1", false),     // not in any range
            ("9.9.9.9", false),         // not in any range
        ];
        for (ip_str, expected) in cases {
            let ip: IpAddr = ip_str.parse().expect("test address literal must parse");
            assert_eq!(snapshot.contains(ip), expected, "ip: {ip_str}");
        }
    }

    #[test]
    fn test_if_modified_since_needs_a_list_and_a_confirmation() {
        let confirmed = snapshot(Some(SECOND), None);
        assert_eq!(confirmed.if_modified_since(), confirmed.fetched_at);
        assert_eq!(CidrSnapshot { networks: vec![], ..confirmed.clone() }.if_modified_since(), None);
        assert_eq!(CidrSnapshot { fetched_at: None, ..confirmed }.if_modified_since(), None);
    }

    #[test]
    fn test_unknown_ip_plan() {
        let t = Thresholds::undrawn();
        let long_ago = CIDR_LIST_FORCE_REFETCH_MAX_AGE + SECOND;
        let past_max_age = CIDR_LIST_MAX_AGE + SECOND;
        let past_retry = CIDR_LIST_RETRY_INTERVAL + SECOND;
        let cases = [
            // Confirmed within the trust window: rejected, whatever the attempts.
            (snapshot(Some(SECOND), None), UnknownIpPlan::Reject),
            (snapshot(Some(SECOND), Some(SECOND)), UnknownIpPlan::Reject),
            // Not confirmed recently, but attempted recently: can't judge.
            (snapshot(Some(past_max_age), Some(SECOND)), UnknownIpPlan::Unverifiable),
            (snapshot(Some(long_ago), Some(SECOND)), UnknownIpPlan::Unverifiable),
            (snapshot(None, Some(SECOND)), UnknownIpPlan::Unverifiable),
            // Not confirmed recently and no recent attempt: refresh.
            (snapshot(Some(past_max_age), Some(past_retry)), UnknownIpPlan::Refresh),
            (snapshot(Some(past_max_age), None), UnknownIpPlan::Refresh),
            (snapshot(None, None), UnknownIpPlan::Refresh),
        ];
        for (state, expected) in cases {
            assert_eq!(unknown_ip_plan(&state, now(), t), expected, "state: {state:?}");
        }
    }

    #[test]
    fn test_unknown_ip_plan_treats_a_future_confirmation_as_unconfirmed() {
        let mut state = snapshot(None, None);
        state.fetched_at = Some(now() + SECOND);
        assert_eq!(unknown_ip_plan(&state, now(), Thresholds::undrawn()), UnknownIpPlan::Refresh);
    }

    #[test]
    fn test_background_refresh_due() {
        let t = Thresholds::undrawn();
        let long_ago = CIDR_LIST_FORCE_REFETCH_MAX_AGE + SECOND;
        let past_retry = CIDR_LIST_RETRY_INTERVAL + SECOND;
        let cases = [
            (snapshot(Some(SECOND), None), false),
            (snapshot(Some(CIDR_LIST_MAX_AGE + SECOND), None), false), // stale, but not a month
            (snapshot(Some(long_ago), None), true),
            (snapshot(Some(long_ago), Some(past_retry)), true),
            (snapshot(Some(long_ago), Some(SECOND)), false), // attempted recently
            (snapshot(None, None), true),                    // never confirmed
        ];
        for (state, expected) in cases {
            assert_eq!(background_refresh_due(&state, now(), t), expected, "state: {state:?}");
        }
    }

    #[test]
    fn test_refresh_unnecessary() {
        let t = Thresholds::undrawn();
        let past_max_age = CIDR_LIST_MAX_AGE + SECOND;
        let past_retry = CIDR_LIST_RETRY_INTERVAL + SECOND;
        assert!(refresh_unnecessary(&snapshot(Some(SECOND), None), now(), t));
        assert!(refresh_unnecessary(&snapshot(Some(past_max_age), Some(SECOND)), now(), t));
        assert!(!refresh_unnecessary(&snapshot(Some(past_max_age), Some(past_retry)), now(), t));
    }

    #[test]
    fn test_after_updated_replaces_the_list_and_records_both_times() {
        let before = snapshot(Some(CIDR_LIST_MAX_AGE * 2), None);
        let after = before.after(&CidrFetchOutcome::Updated("1.2.3.4".to_string()), now());
        assert_eq!(after.networks, parse_networks("1.2.3.4"));
        assert_eq!(after.fetched_at, Some(now()));
        assert_eq!(after.attempted_at, Some(now()));
    }

    #[test]
    fn test_after_not_modified_keeps_the_list_and_records_both_times() {
        let before = snapshot(Some(CIDR_LIST_MAX_AGE * 2), None);
        let after = before.after(&CidrFetchOutcome::NotModified, now());
        assert_eq!(after.networks, before.networks);
        assert_eq!(after.fetched_at, Some(now()));
        assert_eq!(after.attempted_at, Some(now()));
    }

    #[test]
    fn test_after_a_failure_records_only_the_attempt() {
        let before = snapshot(Some(CIDR_LIST_MAX_AGE * 2), None);
        for outcome in [CidrFetchOutcome::Rejected, CidrFetchOutcome::Unreachable] {
            let after = before.after(&outcome, now());
            assert_eq!(after.networks, before.networks);
            assert_eq!(after.fetched_at, before.fetched_at, "a failure confirms nothing");
            assert_eq!(after.attempted_at, Some(now()));
        }
    }

    #[test]
    fn test_merge_without_memory_is_kv() {
        let kv = snapshot(Some(SECOND), Some(SECOND));
        assert_eq!(merge(None, kv.clone()), kv);
    }

    #[test]
    fn test_merge_takes_the_latest_timestamps_and_the_newer_list() {
        let mut memory = snapshot(Some(2 * SECOND), Some(SECOND));
        memory.networks = vec![network("1.1.1.0/24")];
        let mut kv = snapshot(Some(SECOND), Some(2 * SECOND));
        kv.networks = vec![network("2.2.2.0/24")];

        let merged = merge(Some(&memory), kv.clone());
        // KV confirmed the list more recently (1s ago vs 2s ago).
        assert_eq!(merged.networks, kv.networks);
        assert_eq!(merged.fetched_at, kv.fetched_at);
        // Memory attempted more recently (1s ago vs 2s ago).
        assert_eq!(merged.attempted_at, memory.attempted_at);
    }

    #[test]
    fn test_merge_keeps_a_newer_memory_list() {
        let mut memory = snapshot(Some(SECOND), None);
        memory.networks = vec![network("1.1.1.0/24")];
        let mut kv = snapshot(Some(2 * SECOND), None);
        kv.networks = vec![network("2.2.2.0/24")];
        assert_eq!(merge(Some(&memory), kv).networks, memory.networks);
    }

    #[test]
    fn test_merge_never_replaces_a_list_with_an_empty_one() {
        let memory = snapshot(Some(2 * SECOND), None);
        let kv = CidrSnapshot { networks: vec![], fetched_at: Some(now() - SECOND), attempted_at: None };
        assert_eq!(merge(Some(&memory), kv).networks, memory.networks);
    }

    #[test]
    fn test_apply_jitter_spans_either_side_of_the_centre() {
        let centre = Duration::from_hours(6);
        let jitter = Duration::from_hours(1);
        assert_eq!(apply_jitter(centre, jitter, 0.0), Duration::from_hours(5));
        assert_eq!(apply_jitter(centre, jitter, 0.5), centre);
        assert_eq!(apply_jitter(centre, jitter, 1.0), Duration::from_hours(7));
        assert!(apply_jitter(centre, jitter, 0.25) < centre);
        assert!(apply_jitter(centre, jitter, 0.75) > centre);
    }

    #[test]
    fn test_apply_jitter_saturates_at_zero() {
        assert_eq!(apply_jitter(Duration::from_secs(1), Duration::from_hours(1), 0.0), Duration::ZERO);
    }
}
