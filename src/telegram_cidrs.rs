// Telegram IP allowlist: validates an incoming client IP against Telegram's
// published CIDR ranges, cached in KV. The cache is expected to be seeded
// before the first deploy and is refreshed on demand -- see `is_telegram_ip`'s
// doc comment for the fetch-triggering rules.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::StatusCode;
use ipnetwork::IpNetwork;
use worker::*;

use crate::clock;
use crate::outbound::send_with_timeout;

/// Header names used on the outbound CIDR-list fetch.
mod header_names {
    use http::HeaderName;

    /// Sent on the outbound CIDR-list fetch, echoing back when Telegram last
    /// confirmed the cached list, so an unchanged list costs Telegram's
    /// server a 304 rather than a full body.
    pub const IF_MODIFIED_SINCE: HeaderName = HeaderName::from_static("if-modified-since");
}

/// Validate a CIDR block or plain IP string. Returns true if parseable.
/// Plain IPs (no "/") are valid and treated as /32 (IPv4) or /128 (IPv6).
fn validate_cidr_line(line: &str) -> bool {
    if line.is_empty() {
        return false;
    }
    line.parse::<IpNetwork>().is_ok()
}

/// True if `ip` is in the given CIDR list.
fn is_telegram_ip_with_list(ip: std::net::IpAddr, cidr_list: &str) -> bool {
    cidr_list.lines().any(|net_str| if let Ok(net) = net_str.parse::<IpNetwork>() { net.contains(ip) } else { false })
}

/// Parse and validate CIDR list, returning only the validated entries.
/// Skips empty lines; returns None if any non-empty line is malformed or if
/// list is empty.
fn parse_cidr_list(content: &str) -> Option<String> {
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

const CIDR_LIST_KV_KEY: &str = "telegram_cidrs";
/// When Telegram last confirmed the cached list: a successful fetch or a 304.
const CIDR_LIST_FETCHED_AT_KV_KEY: &str = "telegram_cidrs_fetched_at";
/// When a fetch from Telegram was last attempted, whatever came of it.
/// Throttles re-fetches without claiming the list was confirmed, which
/// `CIDR_LIST_FETCHED_AT_KV_KEY` must never do: it is sent as
/// `If-Modified-Since`, and a 304 against a time we never actually got the
/// list at would keep a stale list forever.
const CIDR_LIST_ATTEMPTED_AT_KV_KEY: &str = "telegram_cidrs_attempted_at";
/// How long a confirmation keeps the cached list fresh: while it lasts, an
/// unrecognized IP doesn't trigger a re-fetch.
const CIDR_LIST_MAX_AGE: Duration = Duration::from_hours(24);
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
/// even for a *recognized* IP -- otherwise a dropped-and-reassigned Telegram
/// range would stay trusted forever, since a recognized IP normally never
/// triggers a fetch at all (see `is_telegram_ip`). Real IPv4 reclaim
/// quarantine periods run 3 months (ARIN) to 6 months (RIPE), so 30 days is a
/// conservative margin.
const CIDR_LIST_FORCE_REFETCH_MAX_AGE: Duration = Duration::from_hours(30 * 24);
/// How far either side of `CIDR_LIST_FORCE_REFETCH_MAX_AGE` the random jitter
/// reaches (see `jittered`), so requests don't all cross the threshold at the
/// same instant.
const CIDR_LIST_FORCE_REFETCH_JITTER: Duration = Duration::from_hours(12);
/// How long Telegram gets to answer a CIDR list fetch. Bounds a server that
/// accepts the connection and then never replies.
const CIDR_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait before retrying a failed KV read.
const KV_READ_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Where to fetch the Telegram CIDR list from. Overridable via the
/// `CIDR_LIST_URL` wrangler var (see wrangler.toml) so the integration test
/// can point this at a local mock server instead of Telegram's real endpoint.
const TELEGRAM_CIDR_URL: &str = "https://core.telegram.org/resources/cidr.txt";
const CIDR_LIST_URL_VAR: &str = "CIDR_LIST_URL";

/// How far the cached CIDR list can be trusted, from most to least. See
/// `CIDR_LIST_MAX_AGE` and `CIDR_LIST_FORCE_REFETCH_MAX_AGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CidrListFreshness {
    /// Recent enough that even an unrecognized IP shouldn't trigger a fetch.
    Fresh,
    /// Old enough that an unrecognized IP may trigger a fetch, but a
    /// recognized one still won't.
    Stale,
    /// Old enough, or with no usable fetched-at timestamp, that even a
    /// recognized IP should prompt a background re-fetch.
    VeryStale,
}

/// Milliseconds since the Unix epoch, for storing a `SystemTime` in KV
/// (which only holds strings) and for handing to `worker::Date`, which
/// speaks in millis rather than `SystemTime`.
fn millis_since_epoch(t: SystemTime) -> u64 {
    #[allow(clippy::cast_possible_truncation)] // millis-since-epoch fits comfortably in a u64 for millions of years
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Whether a client IP is a Telegram IP.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TelegramIpCheck {
    Telegram,
    NotTelegram,
    /// The cache couldn't be read, so the question can't be answered. Not the
    /// same as an empty cache, which is answered by fetching the list.
    CacheUnavailable,
}

/// Checks `ip` against the cached list first -- a recognized IP never
/// triggers a *blocking* fetch. Only an unrecognized IP against a list older
/// than `CIDR_LIST_MAX_AGE` (or a missing one) triggers one before answering:
/// real Telegram traffic shouldn't pay for a round-trip to Telegram on every
/// request, and a flood of unrecognized IPs shouldn't force more than one
/// fetch per `CIDR_LIST_RETRY_INTERVAL`.
///
/// A recognized IP against a *very* stale list still kicks off a re-fetch,
/// but in the background via `ctx.wait_until`, so it never delays the
/// response.
///
/// If the cache can't be read, nothing is fetched: a KV outage must not
/// turn into a fetch per request.
pub(crate) async fn is_telegram_ip(
    kv: &KvStore, ip: std::net::IpAddr, fetch_url: &str, ctx: &Context,
) -> TelegramIpCheck {
    let cached = match current_cidr_list(kv).await {
        Ok(cached) => cached,
        Err(e) => {
            console_error!("cidr_cache: outcome=failed reason=kv_read_error error={e}");
            return TelegramIpCheck::CacheUnavailable;
        }
    };
    if is_telegram_ip_with_list(ip, &cached.list) {
        if matches!(cached.freshness, CidrListFreshness::VeryStale) {
            let kv = kv.clone();
            let fetch_url = fetch_url.to_string();
            ctx.wait_until(async move {
                fetch_fresh_cidr_list(&kv, &fetch_url, cached.if_modified_since.as_deref()).await;
            });
        }
        return TelegramIpCheck::Telegram;
    }
    if matches!(cached.freshness, CidrListFreshness::Fresh) {
        return TelegramIpCheck::NotTelegram;
    }

    match fetch_fresh_cidr_list(kv, fetch_url, cached.if_modified_since.as_deref()).await {
        Some(fresh) if is_telegram_ip_with_list(ip, &fresh) => TelegramIpCheck::Telegram,
        _ => TelegramIpCheck::NotTelegram,
    }
}

/// What's currently in the KV cache, and how far to trust it.
#[derive(Debug, Clone)]
struct CachedCidrList {
    /// Empty if nothing has been cached.
    list: String,
    freshness: CidrListFreshness,
    /// The `If-Modified-Since` value safe to send if a fetch is needed: the
    /// real time Telegram last confirmed the list, and only when a list is
    /// actually on hand. A 304 answered against anything else would leave us
    /// with a list we never received.
    if_modified_since: Option<String>,
}

/// The cache's contents, or an error if KV can't be read. Keys that are
/// absent, or hold an unparseable timestamp, are treated as not cached.
async fn current_cidr_list(kv: &KvStore) -> std::result::Result<CachedCidrList, KvError> {
    let list = kv_get_text(kv, CIDR_LIST_KV_KEY).await?;
    let fetched_at = read_timestamp(kv, CIDR_LIST_FETCHED_AT_KV_KEY).await?;
    let attempted_at = read_timestamp(kv, CIDR_LIST_ATTEMPTED_AT_KV_KEY).await?;

    let freshness = freshness_of(
        clock::now(),
        attempted_at,
        fetched_at,
        jittered(CIDR_LIST_RETRY_INTERVAL, CIDR_LIST_RETRY_JITTER),
        jittered(CIDR_LIST_FORCE_REFETCH_MAX_AGE, CIDR_LIST_FORCE_REFETCH_JITTER),
    );
    let if_modified_since = list.as_ref().and(fetched_at).map(http_date);
    Ok(CachedCidrList { list: list.unwrap_or_default(), freshness, if_modified_since })
}

/// The millis-since-epoch timestamp stored under `key`; `None` if absent or
/// unparseable.
async fn read_timestamp(kv: &KvStore, key: &str) -> std::result::Result<Option<SystemTime>, KvError> {
    let value = kv_get_text(kv, key).await?;
    Ok(value.and_then(|v| v.parse::<u64>().ok()).map(|ms| UNIX_EPOCH + Duration::from_millis(ms)))
}

/// Classifies the cache. `Fresh` means no fetch is due: Telegram confirmed
/// the list within `CIDR_LIST_MAX_AGE`, or a fetch was attempted within
/// `retry_interval`. Otherwise the list is `Stale` while it was confirmed
/// within `force_refetch_max_age`, and `VeryStale` beyond that or with no
/// confirmed time at all, so an unseeded or damaged cache fails toward
/// refreshing.
fn freshness_of(
    now: SystemTime, attempted_at: Option<SystemTime>, fetched_at: Option<SystemTime>, retry_interval: Duration,
    force_refetch_max_age: Duration,
) -> CidrListFreshness {
    let within = |then: Option<SystemTime>, max_age| then.is_some_and(|then| clock::is_within(now, then, max_age));
    if within(attempted_at, retry_interval) || within(fetched_at, CIDR_LIST_MAX_AGE) {
        CidrListFreshness::Fresh
    } else if within(fetched_at, force_refetch_max_age) {
        CidrListFreshness::Stale
    } else {
        CidrListFreshness::VeryStale
    }
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

/// What asking Telegram for the CIDR list came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CidrFetchOutcome {
    /// Telegram sent a valid list.
    Updated(String),
    /// Telegram confirmed the cached list is current.
    NotModified,
    /// Telegram answered, but not with a usable list.
    Rejected,
    /// Telegram couldn't be reached.
    Unreachable,
}

/// Fetches a fresh CIDR list from Telegram and caches it. Sends
/// `if_modified_since` as `If-Modified-Since`: an unchanged list (the common
/// case) then costs Telegram's server a bodyless 304 instead of the full list.
/// Returns the new list, or `None` if the cached one stands.
///
/// Every attempt is recorded, so a failing endpoint isn't hit by every
/// request, whether it answered badly or couldn't be reached. Only a 304 or a
/// valid list that was written to KV also records that Telegram confirmed the
/// list.
async fn fetch_fresh_cidr_list(kv: &KvStore, fetch_url: &str, if_modified_since: Option<&str>) -> Option<String> {
    match request_cidr_list(fetch_url, if_modified_since).await {
        CidrFetchOutcome::Updated(list) => {
            // Only vouch for the list in KV if it actually got written.
            if kv_put_best_effort(kv, CIDR_LIST_KV_KEY, &list).await {
                mark_cidr_list_confirmed(kv).await;
            } else {
                mark_cidr_list_attempted(kv).await;
            }
            Some(list)
        }
        CidrFetchOutcome::NotModified => {
            mark_cidr_list_confirmed(kv).await;
            None
        }
        CidrFetchOutcome::Rejected | CidrFetchOutcome::Unreachable => {
            mark_cidr_list_attempted(kv).await;
            None
        }
    }
}

/// Asks Telegram for the CIDR list and logs how that went, without touching
/// KV.
async fn request_cidr_list(fetch_url: &str, if_modified_since: Option<&str>) -> CidrFetchOutcome {
    let mut init = RequestInit::new();
    if let Some(if_modified_since) = if_modified_since {
        let headers = Headers::new();
        let _ = headers.set(header_names::IF_MODIFIED_SINCE.as_str(), if_modified_since);
        init.with_headers(headers);
    }
    let Ok(req) = Request::new_with_init(fetch_url, &init) else { return CidrFetchOutcome::Unreachable };

    let mut resp = match send_with_timeout(req, CIDR_FETCH_TIMEOUT).await {
        Ok(resp) => resp,
        Err(failure) => {
            console_error!("cidr_fetch: outcome=failed reason={failure}");
            return CidrFetchOutcome::Unreachable;
        }
    };

    let status = resp.status_code();
    if status == StatusCode::NOT_MODIFIED.as_u16() {
        console_log!("cidr_fetch: outcome=not_modified status={status}");
        return CidrFetchOutcome::NotModified;
    }
    if !StatusCode::from_u16(status).is_ok_and(|s| s.is_success()) {
        console_error!("cidr_fetch: outcome=failed reason=bad_status status={status}");
        return CidrFetchOutcome::Rejected;
    }
    let body = match resp.text().await {
        Ok(body) => body,
        Err(e) => {
            console_error!("cidr_fetch: outcome=failed reason=body_read_error status={status} error={e}");
            return CidrFetchOutcome::Rejected;
        }
    };
    let Some(list) = parse_cidr_list(&body) else {
        console_error!("cidr_fetch: outcome=failed reason=unparseable status={status}");
        return CidrFetchOutcome::Rejected;
    };
    console_log!("cidr_fetch: outcome=success entries={} status={status}", list.lines().count());
    CidrFetchOutcome::Updated(list)
}

/// The `CIDR_LIST_URL` var if set (always true when deployed via
/// wrangler.toml's own `[vars]` default), falling back to the hardcoded
/// Telegram URL otherwise.
pub(crate) fn cidr_list_url(env: &Env) -> String {
    env.var(CIDR_LIST_URL_VAR).map_or_else(|_| TELEGRAM_CIDR_URL.to_string(), |v| v.to_string())
}

/// Records that a fetch was attempted, whether or not it produced a list.
async fn mark_cidr_list_attempted(kv: &KvStore) {
    kv_put_best_effort(kv, CIDR_LIST_ATTEMPTED_AT_KV_KEY, &millis_since_epoch(clock::now()).to_string()).await;
}

/// Records that Telegram confirmed the cached list is current.
async fn mark_cidr_list_confirmed(kv: &KvStore) {
    let now = millis_since_epoch(clock::now()).to_string();
    kv_put_best_effort(kv, CIDR_LIST_FETCHED_AT_KV_KEY, &now).await;
    kv_put_best_effort(kv, CIDR_LIST_ATTEMPTED_AT_KV_KEY, &now).await;
}

/// An HTTP-date string (e.g. for `If-Modified-Since`) for the given point
/// in time.
fn http_date(t: SystemTime) -> String {
    let js_date: js_sys::Date = Date::new(DateInit::Millis(millis_since_epoch(t))).into();
    js_date.to_utc_string().into()
}

/// The text stored under `key`, retrying once after `KV_READ_RETRY_DELAY` so
/// that a momentary failure doesn't count as an outage.
async fn kv_get_text(kv: &KvStore, key: &str) -> std::result::Result<Option<String>, KvError> {
    match kv.get(key).text().await {
        Ok(value) => Ok(value),
        Err(e) => {
            console_log!("cidr_cache: kv read failed, retrying key={key} error={e}");
            Delay::from(KV_READ_RETRY_DELAY).await;
            kv.get(key).text().await
        }
    }
}

/// `KvStore::put` only constructs a builder -- the write itself doesn't
/// happen until `.execute().await`, easy to miss since the outer call isn't
/// itself async. Failures don't propagate, since a missed write only means
/// the next request re-fetches and it's never worth failing an otherwise-valid
/// request over; the result says whether the write happened for callers that
/// must not act as if it had.
async fn kv_put_best_effort(kv: &KvStore, key: &str, value: &str) -> bool {
    let written = match kv.put(key, value) {
        Ok(builder) => builder.execute().await.is_ok(),
        Err(_) => false,
    };
    if !written {
        console_error!("cidr_cache: outcome=failed reason=kv_write_error key={key}");
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A fixed "now" far enough from the epoch that every age below is a valid
    /// time.
    fn now_for_freshness_tests() -> SystemTime { UNIX_EPOCH + CIDR_LIST_FORCE_REFETCH_MAX_AGE * 2 }

    /// `freshness_of` with the unjittered retry interval and force-refetch age.
    fn freshness(
        now: SystemTime, attempted_at: Option<SystemTime>, fetched_at: Option<SystemTime>,
    ) -> CidrListFreshness {
        freshness_of(now, attempted_at, fetched_at, CIDR_LIST_RETRY_INTERVAL, CIDR_LIST_FORCE_REFETCH_MAX_AGE)
    }

    #[test]
    fn test_freshness_of_by_confirmed_age() {
        let now = now_for_freshness_tests();
        let cases = [
            (now - Duration::from_secs(1), CidrListFreshness::Fresh),
            (now - CIDR_LIST_MAX_AGE - Duration::from_secs(1), CidrListFreshness::Stale),
            (now - CIDR_LIST_FORCE_REFETCH_MAX_AGE - Duration::from_secs(1), CidrListFreshness::VeryStale),
            (now + Duration::from_secs(1), CidrListFreshness::VeryStale), // confirmed "in the future"
        ];
        for (fetched_at, expected) in cases {
            assert_eq!(freshness(now, None, Some(fetched_at)), expected);
        }
    }

    #[test]
    fn test_freshness_of_missing_timestamps_is_very_stale() {
        let now = now_for_freshness_tests();
        assert_eq!(freshness(now, None, None), CidrListFreshness::VeryStale);
    }

    #[test]
    fn test_freshness_of_recent_attempt_throttles_regardless_of_confirmed_age() {
        let now = now_for_freshness_tests();
        let long_ago = now - CIDR_LIST_FORCE_REFETCH_MAX_AGE - Duration::from_secs(1);
        let just_inside_retry_interval = now - CIDR_LIST_RETRY_INTERVAL + Duration::from_secs(1);
        for fetched_at in [Some(long_ago), None] {
            assert_eq!(freshness(now, Some(just_inside_retry_interval), fetched_at), CidrListFreshness::Fresh);
        }
    }

    #[test]
    fn test_freshness_of_old_attempt_falls_back_to_confirmed_age() {
        let now = now_for_freshness_tests();
        let old_attempt = now - CIDR_LIST_RETRY_INTERVAL - Duration::from_secs(1);
        let confirmed_recently = now - CIDR_LIST_MAX_AGE - Duration::from_secs(1);
        let confirmed_long_ago = now - CIDR_LIST_FORCE_REFETCH_MAX_AGE - Duration::from_secs(1);
        assert_eq!(freshness(now, Some(old_attempt), Some(confirmed_recently)), CidrListFreshness::Stale);
        assert_eq!(freshness(now, Some(old_attempt), Some(confirmed_long_ago)), CidrListFreshness::VeryStale);
    }

    #[test]
    fn test_freshness_of_confirmation_within_max_age_is_fresh_despite_an_old_attempt() {
        let now = now_for_freshness_tests();
        let old_attempt = now - CIDR_LIST_RETRY_INTERVAL - Duration::from_secs(1);
        let confirmed_within_max_age = now - CIDR_LIST_MAX_AGE + Duration::from_secs(1);
        assert_eq!(freshness(now, Some(old_attempt), Some(confirmed_within_max_age)), CidrListFreshness::Fresh);
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

    #[test]
    fn test_is_telegram_ip_with_list() {
        let cidr_list = "91.108.56.0/22\n1.2.3.4\n2001:b28:f23d::/48";
        let cases = [
            ("91.108.56.100", true),    // in IPv4 CIDR block
            ("1.2.3.4", true),          // exact plain-IP match
            ("1.2.3.5", false),         // near miss on plain IP
            ("2001:b28:f23d::1", true), // in IPv6 CIDR block
            ("2001:db8::1", false),     // not in any range
            ("9.9.9.9", false),         // not in any range
        ];
        for (ip_str, expected) in cases {
            let ip: std::net::IpAddr = ip_str.parse().expect("test address literal must parse");
            assert_eq!(is_telegram_ip_with_list(ip, cidr_list), expected, "ip: {ip_str}");
        }
    }
}
