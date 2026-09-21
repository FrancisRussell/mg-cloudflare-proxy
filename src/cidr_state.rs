// What is known about Telegram's CIDR list, and the decisions made from it.
// Pure logic only: no KV, network or clock access, so it can be tested
// natively. Loading, fetching and storing live in telegram_cidrs.rs.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnetwork::IpNetwork;

use crate::clock;

/// How long a confirmation keeps the cached list trusted: while it lasts, an
/// unrecognized IP is rejected outright rather than triggering a fetch.
pub(crate) const CIDR_LIST_MAX_AGE: Duration = Duration::from_hours(24);
/// After a failed fetch, no further fetch until about this long has passed
/// (give or take `CIDR_LIST_RETRY_JITTER`), so a failing Telegram endpoint
/// isn't hit by every request.
const CIDR_LIST_RETRY_INTERVAL: Duration = Duration::from_hours(6);
/// How far either side of `CIDR_LIST_RETRY_INTERVAL` the jitter reaches (see
/// `jittered`), spreading out retries that would otherwise all become due at
/// the same moment.
const CIDR_LIST_RETRY_JITTER: Duration = Duration::from_hours(1);
/// Once about this long has passed since Telegram last confirmed the list
/// (give or take `CIDR_LIST_FORCE_REFETCH_JITTER`), force a background re-fetch
/// even for a *recognized* IP, so the list can't drift arbitrarily far out of
/// date while every request happens to come from a known range.
const CIDR_LIST_FORCE_REFETCH_MAX_AGE: Duration = Duration::from_hours(30 * 24);
/// How far either side of `CIDR_LIST_FORCE_REFETCH_MAX_AGE` the jitter reaches
/// (see `jittered`), so deployments don't all cross the threshold at the same
/// instant.
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
    /// It is sent as `If-Modified-Since`, so it must never claim a
    /// confirmation that didn't happen: a 304 against a time we never actually
    /// got the list at would keep a stale list forever.
    pub fetched_at: Option<SystemTime>,
    /// When the last fetch failed, if no fetch has succeeded since. Present
    /// only while retrying after a failure, and what makes a failing Telegram
    /// endpoint wait out the retry interval instead of being hit by every
    /// request.
    pub failed_at: Option<SystemTime>,
}

impl CidrSnapshot {
    /// A snapshot of the given state. A failure that isn't later than the last
    /// confirmation is dropped: it can only be left over from before that
    /// confirmation, when clearing it didn't get through.
    pub(crate) fn new(networks: Vec<IpNetwork>, fetched_at: Option<SystemTime>, failed_at: Option<SystemTime>) -> Self {
        let failed_at = failed_at.filter(|failed| fetched_at.is_none_or(|fetched| *failed > fetched));
        Self { networks, fetched_at, failed_at }
    }

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

    /// True if the last fetch failed and it is too soon to try again: the
    /// retry interval, jittered by a value fixed by the failure's own time so
    /// that every isolate agrees when it ends.
    fn retry_pending(&self, now: SystemTime) -> bool {
        self.failed_at.is_some_and(|failed| {
            let interval = jittered(CIDR_LIST_RETRY_INTERVAL, CIDR_LIST_RETRY_JITTER, failed);
            clock::is_within(now, failed, interval)
        })
    }

    /// The snapshot after `outcome`, as of `now`: a confirmation clears any
    /// failure, and anything else records one.
    pub(crate) fn after(&self, outcome: &CidrFetchOutcome, now: SystemTime) -> Self {
        let mut updated = self.clone();
        match outcome {
            CidrFetchOutcome::Updated(list) => {
                updated.networks = parse_networks(list);
                updated.fetched_at = Some(now);
                updated.failed_at = None;
            }
            CidrFetchOutcome::NotModified => {
                updated.fetched_at = Some(now);
                updated.failed_at = None;
            }
            CidrFetchOutcome::Rejected | CidrFetchOutcome::Unreachable => updated.failed_at = Some(now),
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
    CidrSnapshot::new(
        if take_memory_list { memory.networks.clone() } else { kv.networks },
        memory.fetched_at.max(kv.fetched_at),
        memory.failed_at.max(kv.failed_at),
    )
}

/// True if a request from a *recognized* IP should also start a background
/// refresh. After a failed fetch that's once the retry interval has passed,
/// whatever the list's age, until a fetch succeeds. Otherwise it's when
/// Telegram hasn't confirmed the list for about a month, jittered by a value
/// fixed by the time of the last confirmation so that every isolate agrees when
/// that is.
pub(crate) fn background_refresh_due(snapshot: &CidrSnapshot, now: SystemTime) -> bool {
    if snapshot.failed_at.is_some() {
        return !snapshot.retry_pending(now);
    }
    snapshot.fetched_at.is_none_or(|fetched| {
        let max_age = jittered(CIDR_LIST_FORCE_REFETCH_MAX_AGE, CIDR_LIST_FORCE_REFETCH_JITTER, fetched);
        !clock::is_within(now, fetched, max_age)
    })
}

/// What a request from an IP that isn't in the list should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnknownIpPlan {
    /// The list is confirmed current, so the IP really isn't Telegram's.
    Reject,
    /// The list isn't confirmed current, and the last fetch failed too
    /// recently to try again, so the IP can't be judged.
    Unverifiable,
    /// The list isn't confirmed current and a refresh is due.
    Refresh,
}

/// What a request from an IP that isn't in the list should do.
pub(crate) fn unknown_ip_plan(snapshot: &CidrSnapshot, now: SystemTime) -> UnknownIpPlan {
    if snapshot.confirmed_recently(now) {
        UnknownIpPlan::Reject
    } else if snapshot.retry_pending(now) {
        UnknownIpPlan::Unverifiable
    } else {
        UnknownIpPlan::Refresh
    }
}

/// True if a refresh has nothing to do: the list was confirmed recently, or a
/// failed fetch is still waiting out its retry interval.
pub(crate) fn refresh_unnecessary(snapshot: &CidrSnapshot, now: SystemTime) -> bool {
    snapshot.confirmed_recently(now) || snapshot.retry_pending(now)
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

/// `centre` moved by up to `jitter` either way, by an amount fixed by `since`.
/// The same timestamp gives the same result in every isolate, so they all agree
/// on when a threshold measured from it is crossed, while different timestamps
/// give different results and so spread deployments out.
fn jittered(centre: Duration, jitter: Duration, since: SystemTime) -> Duration {
    apply_jitter(centre, jitter, unit_from(since))
}

/// The number of distinct values a 53-bit integer takes, as a float.
const FLOAT_MANTISSA_RANGE: f64 = 9_007_199_254_740_992.0; // 2^53

/// A number in `0.0..1.0` derived from `time` by mixing its milliseconds, so
/// that times close together still give unrelated results.
fn unit_from(time: SystemTime) -> f64 {
    let millis = time.duration_since(UNIX_EPOCH).map_or(0, |since_epoch| since_epoch.as_millis());
    let mut mixed = u64::try_from(millis).unwrap_or(u64::MAX);
    // The SplitMix64 finaliser.
    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^= mixed >> 31;
    // Keep the top 53 bits, which a float represents exactly.
    let top_bits = mixed >> 11;
    #[allow(clippy::cast_precision_loss)] // 53 bits fit an f64 mantissa exactly
    let unit = top_bits as f64 / FLOAT_MANTISSA_RANGE;
    unit
}

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

    /// A snapshot with a list, confirmed `fetched_ago` and last failed
    /// `failed_ago`. A failure is only kept if it's later than the
    /// confirmation.
    fn snapshot(fetched_ago: Option<Duration>, failed_ago: Option<Duration>) -> CidrSnapshot {
        CidrSnapshot::new(
            vec![network("91.108.56.0/22")],
            fetched_ago.map(|ago| now() - ago),
            failed_ago.map(|ago| now() - ago),
        )
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

    /// Well inside the retry interval whatever its jitter.
    const SOON_AFTER_ATTEMPT: Duration = Duration::from_hours(4);
    /// Well past the retry interval whatever its jitter.
    const LONG_AFTER_ATTEMPT: Duration = Duration::from_hours(8);
    /// Well inside the month-long threshold whatever its jitter.
    const WITHIN_A_MONTH: Duration = Duration::from_hours(29 * 24);
    /// Well past the month-long threshold whatever its jitter.
    const PAST_A_MONTH: Duration = Duration::from_hours(31 * 24);

    #[test]
    fn test_new_keeps_a_failure_only_if_it_is_later_than_the_confirmation() {
        let hour = Duration::from_hours(1);
        // Later than the confirmation: a real failure.
        assert!(snapshot(Some(2 * hour), Some(hour)).failed_at.is_some());
        assert!(snapshot(None, Some(hour)).failed_at.is_some());
        // Not later: left over from before the confirmation, so dropped.
        assert!(snapshot(Some(hour), Some(hour)).failed_at.is_none());
        assert!(snapshot(Some(hour), Some(2 * hour)).failed_at.is_none());
        // Nothing recorded.
        assert!(snapshot(Some(hour), None).failed_at.is_none());
        assert!(snapshot(None, None).failed_at.is_none());
    }

    #[test]
    fn test_unknown_ip_plan() {
        let past_max_age = CIDR_LIST_MAX_AGE + SECOND;
        let cases = [
            // Confirmed within the trust window: rejected.
            (snapshot(Some(SECOND), Some(SECOND)), UnknownIpPlan::Reject),
            (snapshot(Some(SECOND), None), UnknownIpPlan::Reject),
            // Not confirmed recently, the last fetch failed a little while ago: can't judge.
            (snapshot(Some(past_max_age), Some(SOON_AFTER_ATTEMPT)), UnknownIpPlan::Unverifiable),
            (snapshot(Some(PAST_A_MONTH), Some(SOON_AFTER_ATTEMPT)), UnknownIpPlan::Unverifiable),
            (snapshot(None, Some(SOON_AFTER_ATTEMPT)), UnknownIpPlan::Unverifiable),
            // The retry interval has passed: refresh.
            (snapshot(Some(past_max_age), Some(LONG_AFTER_ATTEMPT)), UnknownIpPlan::Refresh),
            // Not confirmed recently and the last fetch didn't fail: refresh.
            (snapshot(Some(past_max_age), Some(past_max_age)), UnknownIpPlan::Refresh),
            (snapshot(Some(past_max_age), None), UnknownIpPlan::Refresh),
            (snapshot(None, None), UnknownIpPlan::Refresh),
        ];
        for (state, expected) in cases {
            assert_eq!(unknown_ip_plan(&state, now()), expected, "state: {state:?}");
        }
    }

    #[test]
    fn test_unknown_ip_plan_treats_a_future_confirmation_as_unconfirmed() {
        let mut state = snapshot(None, None);
        state.fetched_at = Some(now() + SECOND);
        assert_eq!(unknown_ip_plan(&state, now()), UnknownIpPlan::Refresh);
    }

    #[test]
    fn test_background_refresh_due_when_the_last_fetch_succeeded() {
        let cases = [
            (snapshot(Some(SECOND), Some(SECOND)), false),
            (snapshot(Some(CIDR_LIST_MAX_AGE + SECOND), Some(CIDR_LIST_MAX_AGE + SECOND)), false), /* stale, not a
                                                                                                    * month */
            (snapshot(Some(WITHIN_A_MONTH), Some(WITHIN_A_MONTH)), false),
            (snapshot(Some(PAST_A_MONTH), Some(PAST_A_MONTH)), true),
            (snapshot(Some(PAST_A_MONTH), None), true), // seeded, no failure since
            (snapshot(None, None), true),               // never confirmed
        ];
        for (state, expected) in cases {
            assert_eq!(background_refresh_due(&state, now()), expected, "state: {state:?}");
        }
    }

    #[test]
    fn test_background_refresh_after_a_failure_follows_the_retry_interval_alone() {
        // However old the list is, or isn't, only the time since the failed
        // attempt counts.
        for confirmed in [Some(WITHIN_A_MONTH), Some(PAST_A_MONTH), None] {
            assert!(
                !background_refresh_due(&snapshot(confirmed, Some(SOON_AFTER_ATTEMPT)), now()),
                "confirmed {confirmed:?} ago, failed soon ago"
            );
            assert!(
                background_refresh_due(&snapshot(confirmed, Some(LONG_AFTER_ATTEMPT)), now()),
                "confirmed {confirmed:?} ago, failed long ago"
            );
        }
    }

    #[test]
    fn test_decisions_depend_only_on_the_stored_timestamps() {
        // Inside the jitter band the answer varies between failures but is the
        // same every time for one failure: nothing random is drawn per request.
        let in_band = CIDR_LIST_RETRY_INTERVAL;
        let mut answers = std::collections::HashSet::new();
        for offset_millis in 0..200 {
            let failed = now() - in_band - Duration::from_millis(offset_millis * 37);
            let state = CidrSnapshot::new(vec![network("91.108.56.0/22")], Some(now() - PAST_A_MONTH), Some(failed));
            let first = state.retry_pending(now());
            for _ in 0..3 {
                assert_eq!(state.retry_pending(now()), first);
            }
            answers.insert(first);
        }
        assert_eq!(answers.len(), 2, "failures at the centre of the band should differ in when their wait ends");
    }

    #[test]
    fn test_refresh_unnecessary() {
        let past_max_age = CIDR_LIST_MAX_AGE + SECOND;
        assert!(refresh_unnecessary(&snapshot(Some(SECOND), Some(SECOND)), now()));
        assert!(refresh_unnecessary(&snapshot(Some(past_max_age), Some(SOON_AFTER_ATTEMPT)), now()));
        assert!(!refresh_unnecessary(&snapshot(Some(past_max_age), Some(LONG_AFTER_ATTEMPT)), now()));
        assert!(!refresh_unnecessary(&snapshot(Some(past_max_age), Some(past_max_age)), now()));
    }

    #[test]
    fn test_unit_from_is_deterministic_spread_and_in_range() {
        let times: Vec<f64> =
            (0..1000).map(|i| unit_from(UNIX_EPOCH + Duration::from_millis(1_700_000_000_000 + i))).collect();
        assert!(times.iter().all(|unit| (0.0..1.0).contains(unit)));
        assert_eq!(
            unit_from(UNIX_EPOCH + Duration::from_millis(42)).to_bits(),
            unit_from(UNIX_EPOCH + Duration::from_millis(42)).to_bits()
        );
        // Adjacent milliseconds shouldn't give adjacent results, and the values
        // should cover the range rather than cluster.
        let mean = times.iter().sum::<f64>() / 1000.0;
        assert!((0.4..0.6).contains(&mean), "mean {mean}");
        let below_a_quarter = times.iter().filter(|unit| **unit < 0.25).count();
        assert!((150..350).contains(&below_a_quarter), "{below_a_quarter} below a quarter");
    }

    #[test]
    fn test_after_updated_replaces_the_list_and_clears_a_failure() {
        let before = snapshot(Some(CIDR_LIST_MAX_AGE * 2), Some(SOON_AFTER_ATTEMPT));
        assert!(before.failed_at.is_some());
        let after = before.after(&CidrFetchOutcome::Updated("1.2.3.4".to_string()), now());
        assert_eq!(after.networks, parse_networks("1.2.3.4"));
        assert_eq!(after.fetched_at, Some(now()));
        assert_eq!(after.failed_at, None);
    }

    #[test]
    fn test_after_not_modified_keeps_the_list_and_clears_a_failure() {
        let before = snapshot(Some(CIDR_LIST_MAX_AGE * 2), Some(SOON_AFTER_ATTEMPT));
        let after = before.after(&CidrFetchOutcome::NotModified, now());
        assert_eq!(after.networks, before.networks);
        assert_eq!(after.fetched_at, Some(now()));
        assert_eq!(after.failed_at, None);
    }

    #[test]
    fn test_after_a_failure_records_only_the_failure() {
        let before = snapshot(Some(CIDR_LIST_MAX_AGE * 2), None);
        for outcome in [CidrFetchOutcome::Rejected, CidrFetchOutcome::Unreachable] {
            let after = before.after(&outcome, now());
            assert_eq!(after.networks, before.networks);
            assert_eq!(after.fetched_at, before.fetched_at, "a failure confirms nothing");
            assert_eq!(after.failed_at, Some(now()));
        }
    }

    #[test]
    fn test_merge_without_memory_is_kv() {
        let kv = snapshot(Some(SECOND), Some(SECOND));
        assert_eq!(merge(None, kv.clone()), kv);
    }

    #[test]
    fn test_merge_takes_the_latest_timestamps_and_the_newer_list() {
        let hour = Duration::from_hours(1);
        let mut memory = snapshot(Some(5 * hour), Some(hour));
        memory.networks = vec![network("1.1.1.0/24")];
        let mut kv = snapshot(Some(4 * hour), Some(2 * hour));
        kv.networks = vec![network("2.2.2.0/24")];

        let merged = merge(Some(&memory), kv.clone());
        // KV confirmed the list more recently (4h ago vs 5h ago).
        assert_eq!(merged.networks, kv.networks);
        assert_eq!(merged.fetched_at, kv.fetched_at);
        // Memory failed more recently (1h ago vs 2h ago).
        assert_eq!(merged.failed_at, memory.failed_at);
    }

    #[test]
    fn test_merge_drops_a_failure_that_a_later_confirmation_supersedes() {
        let hour = Duration::from_hours(1);
        let memory = snapshot(Some(5 * hour), Some(3 * hour)); // failed 3h ago
        let kv = snapshot(Some(hour), None); // but confirmed 1h ago
        assert_eq!(merge(Some(&memory), kv).failed_at, None);
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
        let kv = CidrSnapshot::new(vec![], Some(now() - SECOND), None);
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
