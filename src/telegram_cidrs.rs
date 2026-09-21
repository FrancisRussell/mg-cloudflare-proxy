// Telegram IP allowlist: validates an incoming client IP against Telegram's
// published CIDR ranges, cached in KV. The cache is seeded before the first
// deploy (scripts/seed-cidr-cache.sh) and refreshed on demand -- see
// `is_telegram_ip`'s doc comment for the fetch-triggering rules.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::StatusCode;
use ipnetwork::IpNetwork;
use worker::*;

use crate::clock;

mod header_names {
    use http::HeaderName;

    /// Sent on the outbound CIDR-list fetch, echoing back the last fetch
    /// attempt's own timestamp, so an unchanged list costs Telegram's
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
const CIDR_LIST_FETCHED_AT_KV_KEY: &str = "telegram_cidrs_fetched_at";
/// How long a cached CIDR list is trusted before an unrecognized IP is
/// allowed to trigger a re-fetch.
const CIDR_LIST_MAX_AGE: Duration = Duration::from_hours(24);
/// Beyond this age, force a background re-fetch even for a *recognized* IP
/// -- otherwise a dropped-and-reassigned Telegram range would stay trusted
/// forever, since a recognized IP normally never triggers a fetch at all
/// (see `is_telegram_ip`). Real IPv4 reclaim quarantine periods run 3
/// months (ARIN) to 6 months (RIPE), so 30 days is a conservative margin.
const CIDR_LIST_FORCE_REFETCH_MAX_AGE: Duration = Duration::from_hours(30 * 24);
/// Width of the random jitter subtracted from `CIDR_LIST_FORCE_REFETCH_MAX_AGE`
/// (see `jittered_force_refetch_max_age`) -- only ever shortens the
/// effective threshold, never lengthens it, so the 30-day promise is never
/// exceeded, just sometimes acted on a little early.
const CIDR_LIST_FORCE_REFETCH_JITTER: Duration = Duration::from_hours(24);
/// Where to fetch the Telegram CIDR list from. Overridable via the
/// `CIDR_LIST_URL` wrangler var (see wrangler.toml) so the integration test
/// can point this at a local mock server instead of Telegram's real endpoint.
const TELEGRAM_CIDR_URL: &str = "https://core.telegram.org/resources/cidr.txt";
const CIDR_LIST_URL_VAR: &str = "CIDR_LIST_URL";

/// How trustworthy the cached CIDR list currently is, oldest-tolerated-use
/// first. See `CIDR_LIST_MAX_AGE` and `CIDR_LIST_FORCE_REFETCH_MAX_AGE`.
#[derive(Debug, PartialEq, Eq)]
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

/// True if `ip` is a Telegram IP. Checks the cached list first -- a
/// recognized IP never triggers a *blocking* fetch. Only an unrecognized IP
/// against a list older than `CIDR_LIST_MAX_AGE` (or a missing one) triggers
/// one before answering: real Telegram traffic shouldn't pay for a round-trip
/// to Telegram on every request, and a flood of unrecognized IPs shouldn't
/// force more than one fetch per `CIDR_LIST_MAX_AGE` window.
///
/// A recognized IP against a *very* stale list still kicks off a re-fetch,
/// but in the background via `ctx.wait_until`, so it never delays the
/// response.
pub(crate) async fn is_telegram_ip(kv: &KvStore, ip: std::net::IpAddr, fetch_url: &str, ctx: &Context) -> bool {
    let cached = current_cidr_list(kv).await;
    if is_telegram_ip_with_list(ip, &cached.list) {
        if matches!(cached.freshness, CidrListFreshness::VeryStale) {
            let kv = kv.clone();
            let fetch_url = fetch_url.to_string();
            ctx.wait_until(async move {
                fetch_fresh_cidr_list(&kv, &fetch_url, &cached.list, cached.if_modified_since.as_deref()).await;
            });
        }
        return true;
    }
    if matches!(cached.freshness, CidrListFreshness::Fresh) {
        return false;
    }

    match fetch_fresh_cidr_list(kv, fetch_url, &cached.list, cached.if_modified_since.as_deref()).await {
        Some(fresh) => is_telegram_ip_with_list(ip, &fresh),
        None => false,
    }
}

/// What's currently in the KV cache, and how far to trust it.
struct CachedCidrList {
    /// Empty if nothing has been cached.
    list: String,
    freshness: CidrListFreshness,
    /// The `If-Modified-Since` value safe to send if a fetch is needed: the
    /// real time of the last fetch, and only when a list from that fetch is
    /// actually on hand. A 304 answered against anything else would leave us
    /// with a list we never received.
    if_modified_since: Option<String>,
}

async fn current_cidr_list(kv: &KvStore) -> CachedCidrList {
    let list = kv.get(CIDR_LIST_KV_KEY).text().await.ok().flatten();
    let fetched_at = match kv.get(CIDR_LIST_FETCHED_AT_KV_KEY).text().await {
        Ok(Some(fetched_at)) => fetched_at.parse::<u64>().ok().map(|ms| UNIX_EPOCH + Duration::from_millis(ms)),
        _ => None,
    };

    let freshness = freshness_of(clock::now(), fetched_at, jittered_force_refetch_max_age());
    let if_modified_since = list.as_ref().and(fetched_at).map(http_date);
    CachedCidrList { list: list.unwrap_or_default(), freshness, if_modified_since }
}

/// Classifies a list fetched at `fetched_at`. A missing timestamp is
/// `VeryStale`, so an unseeded or damaged cache fails toward refreshing.
fn freshness_of(now: SystemTime, fetched_at: Option<SystemTime>, force_refetch_max_age: Duration) -> CidrListFreshness {
    let Some(fetched_at) = fetched_at else { return CidrListFreshness::VeryStale };
    if clock::is_within(now, fetched_at, CIDR_LIST_MAX_AGE) {
        CidrListFreshness::Fresh
    } else if clock::is_within(now, fetched_at, force_refetch_max_age) {
        CidrListFreshness::Stale
    } else {
        CidrListFreshness::VeryStale
    }
}

/// `CIDR_LIST_FORCE_REFETCH_MAX_AGE` shortened by a random amount up to
/// `CIDR_LIST_FORCE_REFETCH_JITTER`, freshly redrawn on every call --
/// spreads out when different concurrent requests conclude the cache is
/// `VeryStale`, rather than all of them crossing the same fixed cutoff at
/// once (a synchronized fleet of edge locations would otherwise all decide
/// to background-refetch in the same narrow window).
fn jittered_force_refetch_max_age() -> Duration {
    let jitter = CIDR_LIST_FORCE_REFETCH_JITTER.mul_f64(js_sys::Math::random());
    CIDR_LIST_FORCE_REFETCH_MAX_AGE.saturating_sub(jitter)
}

/// Attempts to fetch, validate, and cache a fresh CIDR list from Telegram.
/// Sends `if_modified_since` as `If-Modified-Since`: an unchanged list (the
/// common case) then costs Telegram's server a bodyless 304 instead of the
/// full list.
///
/// The fetched-at timestamp is updated on any definitive answer (a 304, a
/// success, or a bad-but-reachable response like an unparseable body), so a
/// broken-but-reachable endpoint isn't hit on every subsequent
/// unrecognized-IP request either -- only a network-level failure leaves it
/// untouched, since that's the one case worth retrying sooner than
/// `CIDR_LIST_MAX_AGE`.
///
/// `current_list` is returned unchanged on a 304, since that response
/// carries no body to re-derive it from.
async fn fetch_fresh_cidr_list(
    kv: &KvStore, fetch_url: &str, current_list: &str, if_modified_since: Option<&str>,
) -> Option<String> {
    let mut init = RequestInit::new();
    if let Some(if_modified_since) = if_modified_since {
        let headers = Headers::new();
        let _ = headers.set(header_names::IF_MODIFIED_SINCE.as_str(), if_modified_since);
        init.with_headers(headers);
    }
    let Ok(req) = Request::new_with_init(fetch_url, &init) else { return None };

    match Fetch::Request(req).send().await {
        Ok(mut resp) => {
            let status = resp.status_code();
            if status == StatusCode::NOT_MODIFIED.as_u16() {
                console_log!("cidr_fetch: outcome=not_modified status={status}");
                mark_cidr_list_fetched(kv).await;
                return Some(current_list.to_string());
            }
            if StatusCode::from_u16(status).is_ok_and(|s| s.is_success()) {
                match resp.text().await {
                    Ok(body) => {
                        if let Some(parsed) = parse_cidr_list(&body) {
                            console_log!(
                                "cidr_fetch: outcome=success entries={} status={status}",
                                parsed.lines().count()
                            );
                            kv_put_best_effort(kv, CIDR_LIST_KV_KEY, &parsed).await;
                            mark_cidr_list_fetched(kv).await;
                            return Some(parsed);
                        }
                        console_error!("cidr_fetch: outcome=failed reason=unparseable status={status}");
                        mark_cidr_list_fetched(kv).await;
                    }
                    Err(e) => {
                        console_error!("cidr_fetch: outcome=failed reason=body_read_error status={status} error={e}");
                        mark_cidr_list_fetched(kv).await;
                    }
                }
            } else {
                console_error!("cidr_fetch: outcome=failed reason=bad_status status={status}");
                mark_cidr_list_fetched(kv).await;
            }
        }
        Err(e) => console_error!("cidr_fetch: outcome=failed reason=network_error error={e}"),
    }
    None
}

/// The `CIDR_LIST_URL` var if set (always true when deployed via
/// wrangler.toml's own `[vars]` default), falling back to the hardcoded
/// Telegram URL otherwise.
pub(crate) fn cidr_list_url(env: &Env) -> String {
    env.var(CIDR_LIST_URL_VAR).map_or_else(|_| TELEGRAM_CIDR_URL.to_string(), |v| v.to_string())
}

async fn mark_cidr_list_fetched(kv: &KvStore) {
    kv_put_best_effort(kv, CIDR_LIST_FETCHED_AT_KV_KEY, &millis_since_epoch(clock::now()).to_string()).await;
}

/// An HTTP-date string (e.g. for `If-Modified-Since`) for the given point
/// in time.
fn http_date(t: SystemTime) -> String {
    let js_date: js_sys::Date = Date::new(DateInit::Millis(millis_since_epoch(t))).into();
    js_date.to_utc_string().into()
}

/// `KvStore::put` only constructs a builder -- the write itself doesn't
/// happen until `.execute().await`, easy to miss since the outer call isn't
/// itself async. Failures are swallowed here: a missed write only means the
/// next request re-fetches, so it's never worth failing an otherwise-valid
/// request over.
async fn kv_put_best_effort(kv: &KvStore, key: &str, value: &str) {
    if let Ok(builder) = kv.put(key, value) {
        let _ = builder.execute().await;
    }
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
        let result = parse_cidr_list(list).unwrap();
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
    fn test_freshness_of() {
        let now = UNIX_EPOCH + CIDR_LIST_FORCE_REFETCH_MAX_AGE * 2;
        let cases = [
            (now - Duration::from_secs(1), CidrListFreshness::Fresh),
            (now - CIDR_LIST_MAX_AGE - Duration::from_secs(1), CidrListFreshness::Stale),
            (now - CIDR_LIST_FORCE_REFETCH_MAX_AGE - Duration::from_secs(1), CidrListFreshness::VeryStale),
            (now + Duration::from_secs(1), CidrListFreshness::VeryStale), // fetched "in the future"
        ];
        for (fetched_at, expected) in cases {
            assert_eq!(freshness_of(now, Some(fetched_at), CIDR_LIST_FORCE_REFETCH_MAX_AGE), expected);
        }
    }

    #[test]
    fn test_freshness_of_missing_timestamp_is_very_stale() {
        assert_eq!(freshness_of(UNIX_EPOCH, None, CIDR_LIST_FORCE_REFETCH_MAX_AGE), CidrListFreshness::VeryStale);
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
            let ip: std::net::IpAddr = ip_str.parse().unwrap();
            assert_eq!(is_telegram_ip_with_list(ip, cidr_list), expected, "ip: {ip_str}");
        }
    }
}
