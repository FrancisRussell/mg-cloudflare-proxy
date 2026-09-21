// Telegram IP allowlist: validates an incoming client IP against Telegram's
// published CIDR ranges. A pull-through cache: each isolate keeps the list in
// memory, KV holds the copy shared between isolates (seeded before the first
// deploy), and Telegram is the origin, fetched only when a refresh is due. See
// `is_telegram_ip`'s doc comment for the rules.

use std::cell::{Cell, RefCell};
use std::pin::pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_channel::oneshot;
use futures_util::future::{select, try_join3, Either};
use http::StatusCode;
use worker::*;

use crate::cidr_state::{
    background_refresh_due, merge, parse_cidr_list, parse_networks, refresh_unnecessary, unknown_ip_plan,
    CidrFetchOutcome, CidrSnapshot, Thresholds, UnknownIpPlan,
};
use crate::clock::{self, Deadline};
use crate::outbound::send_with_timeout;

/// Header names used on the outbound CIDR-list fetch.
mod header_names {
    use http::HeaderName;

    /// Sent on the outbound CIDR-list fetch, echoing back when Telegram last
    /// confirmed the cached list, so an unchanged list costs Telegram's
    /// server a 304 rather than a full body.
    pub const IF_MODIFIED_SINCE: HeaderName = HeaderName::from_static("if-modified-since");
}

const CIDR_LIST_KV_KEY: &str = "telegram_cidrs";
/// When Telegram last confirmed the cached list: a successful fetch or a 304.
const CIDR_LIST_FETCHED_AT_KV_KEY: &str = "telegram_cidrs_fetched_at";
/// When a fetch from Telegram was last attempted, whatever came of it.
const CIDR_LIST_ATTEMPTED_AT_KV_KEY: &str = "telegram_cidrs_attempted_at";
/// How long Telegram gets to answer a CIDR list fetch. Bounds a server that
/// accepts the connection and then never replies.
const CIDR_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait before retrying a failed KV read.
const KV_READ_RETRY_DELAY: Duration = Duration::from_millis(100);
/// How long a refresh may hold this isolate's refresh lease before the lease
/// is treated as abandoned, so a refresh that never finishes can't block
/// every other one. Comfortably longer than a fetch plus its KV traffic.
const REFRESH_LEASE_DURATION: Duration = Duration::from_secs(30);
/// How often a request waiting for another refresh checks whether it's done.
const REFRESH_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Where to fetch the Telegram CIDR list from. Overridable via the
/// `CIDR_LIST_URL` wrangler var (see wrangler.toml) so the integration test
/// can point this at a local mock server instead of Telegram's real endpoint.
const TELEGRAM_CIDR_URL: &str = "https://core.telegram.org/resources/cidr.txt";
const CIDR_LIST_URL_VAR: &str = "CIDR_LIST_URL";

thread_local! {
    /// What this isolate last knew about the CIDR list; `None` until the
    /// first request loads it from KV. Lasts as long as the isolate does.
    static SNAPSHOT: RefCell<Option<CidrSnapshot>> = const { RefCell::new(None) };
    /// When the refresh now running in this isolate, if any, is treated as
    /// abandoned.
    static REFRESH_LEASE_EXPIRES: Cell<Option<SystemTime>> = const { Cell::new(None) };
}

/// What this isolate currently remembers about the CIDR list.
fn remembered() -> Option<CidrSnapshot> { SNAPSHOT.with(|snapshot| snapshot.borrow().clone()) }

/// Makes `snapshot` what this isolate remembers.
fn remember(snapshot: CidrSnapshot) { SNAPSHOT.with(|current| *current.borrow_mut() = Some(snapshot)); }

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
    /// The question can't be answered right now: the cache couldn't be read,
    /// or the list isn't confirmed current and refreshing it just failed.
    Unverifiable,
}

/// Checks `ip` against this isolate's copy of the list, loading it from KV
/// only the first time. A request waits for a refresh only until `deadline`; a
/// refresh still running by then carries on in the background.
///
/// A recognized IP is accepted straight away. If Telegram hasn't confirmed the
/// list for about a month, it also starts a refresh in the background via
/// `ctx.wait_until`, so it never delays the response.
///
/// An unrecognized IP is rejected if Telegram confirmed the list within the
/// last day. Otherwise the list may be out of date, so a refresh runs before
/// answering, unless one was attempted recently. If the answer still can't be
/// given, the request is `Unverifiable` rather than rejected. Real Telegram
/// traffic never waits on a refresh, and a flood of unrecognized IPs causes at
/// most one refresh per retry interval.
///
/// If the cache can't be read, nothing is fetched: a KV outage must not turn
/// into a fetch per request.
pub(crate) async fn is_telegram_ip(
    kv: &KvStore, ip: std::net::IpAddr, fetch_url: &str, ctx: &Context, deadline: Deadline,
) -> TelegramIpCheck {
    let snapshot = match remembered() {
        Some(snapshot) => snapshot,
        None => match load_from_kv(kv).await {
            Ok(loaded) => {
                console_log!("cidr_cache: outcome=loaded source=kv entries={}", loaded.networks.len());
                remember(merge(remembered().as_ref(), loaded));
                remembered().expect("the snapshot was just remembered")
            }
            Err(e) => {
                console_error!("cidr_cache: outcome=failed reason=kv_read_error error={e}");
                return TelegramIpCheck::Unverifiable;
            }
        },
    };
    let thresholds = Thresholds::draw();

    if snapshot.contains(ip) {
        if background_refresh_due(&snapshot, clock::now(), thresholds) {
            let kv = kv.clone();
            let fetch_url = fetch_url.to_string();
            ctx.wait_until(async move {
                refresh(kv, fetch_url, thresholds).await;
            });
        }
        return TelegramIpCheck::Telegram;
    }

    let snapshot = match unknown_ip_plan(&snapshot, clock::now(), thresholds) {
        UnknownIpPlan::Reject => return TelegramIpCheck::NotTelegram,
        UnknownIpPlan::Unverifiable => return TelegramIpCheck::Unverifiable,
        UnknownIpPlan::Refresh => match refresh_until(kv, fetch_url, thresholds, deadline, ctx).await {
            Some(refreshed) => refreshed,
            None => return TelegramIpCheck::Unverifiable,
        },
    };

    // Judge again on what the refresh left us with.
    if snapshot.contains(ip) {
        TelegramIpCheck::Telegram
    } else if matches!(unknown_ip_plan(&snapshot, clock::now(), thresholds), UnknownIpPlan::Reject) {
        TelegramIpCheck::NotTelegram
    } else {
        TelegramIpCheck::Unverifiable
    }
}

/// Runs a refresh, waiting for it only until `deadline`. The refresh runs
/// under `ctx.wait_until` from the start, so a slow Telegram doesn't hold up
/// the response but the refresh still finishes, and its result reaches later
/// requests. (Timers set up by a request don't survive the response, so a
/// refresh can't simply be handed over part-way.) Returns `None` if the
/// refresh didn't finish in time, or if KV couldn't be read.
async fn refresh_until(
    kv: &KvStore, fetch_url: &str, thresholds: Thresholds, deadline: Deadline, ctx: &Context,
) -> Option<CidrSnapshot> {
    let (sender, receiver) = oneshot::channel();
    let (kv, fetch_url) = (kv.clone(), fetch_url.to_string());
    ctx.wait_until(async move {
        // The request may have stopped waiting; the refresh's effects on the
        // snapshot and KV are what matter then.
        let _ = sender.send(refresh(kv, fetch_url, thresholds).await);
    });

    let out_of_time = pin!(Delay::from(deadline.remaining()));
    match select(receiver, out_of_time).await {
        Either::Left((Ok(refreshed), _)) => refreshed,
        Either::Left((Err(_), _)) => None,
        Either::Right(..) => {
            console_log!("cidr_cache: refresh outlasted the response time, finishing it in the background");
            None
        }
    }
}

/// Brings this isolate's copy up to date, and returns it, or `None` if KV
/// couldn't be read. KV is consulted first, since another isolate may already
/// have refreshed the list, or attempted to, and its timestamps decide whether
/// Telegram needs asking at all. Only one refresh runs in an isolate at a time:
/// the others wait for it and use what it leaves behind.
async fn refresh(kv: KvStore, fetch_url: String, thresholds: Thresholds) -> Option<CidrSnapshot> {
    let Some(_lease) = RefreshLease::claim(clock::now()) else {
        wait_for_running_refresh().await;
        return remembered();
    };

    let from_kv = match load_from_kv(&kv).await {
        Ok(loaded) => loaded,
        Err(e) => {
            console_error!("cidr_cache: outcome=failed reason=kv_read_error error={e}");
            return None;
        }
    };
    let merged = merge(remembered().as_ref(), from_kv);
    remember(merged.clone());
    if refresh_unnecessary(&merged, clock::now(), thresholds) {
        return Some(merged);
    }

    let if_modified_since = merged.if_modified_since().map(http_date);
    let outcome = request_cidr_list(&fetch_url, if_modified_since.as_deref()).await;
    let now = clock::now();
    let updated = merged.after(&outcome, now);
    remember(updated.clone());
    persist(&kv, &outcome, now).await;
    Some(updated)
}

/// This isolate's claim to be the one refreshing. Held for as long as the
/// value lives, so a refresh that is cancelled, or that fails, releases it;
/// one that never finishes is ignored once its lease has run out.
#[derive(Debug)]
struct RefreshLease {
    expires: SystemTime,
}

impl RefreshLease {
    /// The claim, or `None` if another refresh in this isolate holds a lease
    /// that hasn't run out.
    fn claim(now: SystemTime) -> Option<Self> {
        if REFRESH_LEASE_EXPIRES.get().is_some_and(|expires| expires > now) {
            return None;
        }
        let expires = now + REFRESH_LEASE_DURATION;
        REFRESH_LEASE_EXPIRES.set(Some(expires));
        Some(Self { expires })
    }
}

impl Drop for RefreshLease {
    fn drop(&mut self) {
        // Only release the lease this claim took: after it ran out, another
        // refresh may have taken its own.
        if REFRESH_LEASE_EXPIRES.get() == Some(self.expires) {
            REFRESH_LEASE_EXPIRES.set(None);
        }
    }
}

/// Waits until no refresh holds an unexpired lease in this isolate.
async fn wait_for_running_refresh() {
    while REFRESH_LEASE_EXPIRES.get().is_some_and(|expires| expires > clock::now()) {
        Delay::from(REFRESH_WAIT_POLL_INTERVAL).await;
    }
}

/// Reads the cache from KV. Keys that are absent, or hold an unparseable
/// timestamp, are treated as not cached.
async fn load_from_kv(kv: &KvStore) -> std::result::Result<CidrSnapshot, KvError> {
    let (list, fetched_at, attempted_at) = try_join3(
        kv_get_text(kv, CIDR_LIST_KV_KEY),
        read_timestamp(kv, CIDR_LIST_FETCHED_AT_KV_KEY),
        read_timestamp(kv, CIDR_LIST_ATTEMPTED_AT_KV_KEY),
    )
    .await?;
    Ok(CidrSnapshot { networks: list.map(|list| parse_networks(&list)).unwrap_or_default(), fetched_at, attempted_at })
}

/// The millis-since-epoch timestamp stored under `key`; `None` if absent or
/// unparseable.
async fn read_timestamp(kv: &KvStore, key: &str) -> std::result::Result<Option<SystemTime>, KvError> {
    let value = kv_get_text(kv, key).await?;
    Ok(value.and_then(|v| v.parse::<u64>().ok()).map(|ms| UNIX_EPOCH + Duration::from_millis(ms)))
}

/// Records `outcome` in KV. Every attempt is recorded, so a failing endpoint
/// isn't hit by every request, whether it answered badly or couldn't be
/// reached. Only a 304, or a valid list that was written to KV, also records
/// that Telegram confirmed the list.
async fn persist(kv: &KvStore, outcome: &CidrFetchOutcome, now: SystemTime) {
    match outcome {
        CidrFetchOutcome::Updated(list) => {
            // Only vouch for the list in KV if it actually got written.
            if kv_put_best_effort(kv, CIDR_LIST_KV_KEY, list).await {
                mark_confirmed(kv, now).await;
            } else {
                mark_attempted(kv, now).await;
            }
        }
        CidrFetchOutcome::NotModified => mark_confirmed(kv, now).await,
        CidrFetchOutcome::Rejected | CidrFetchOutcome::Unreachable => mark_attempted(kv, now).await,
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
async fn mark_attempted(kv: &KvStore, now: SystemTime) {
    kv_put_best_effort(kv, CIDR_LIST_ATTEMPTED_AT_KV_KEY, &millis_since_epoch(now).to_string()).await;
}

/// Records that Telegram confirmed the cached list is current.
async fn mark_confirmed(kv: &KvStore, now: SystemTime) {
    let millis = millis_since_epoch(now).to_string();
    kv_put_best_effort(kv, CIDR_LIST_FETCHED_AT_KV_KEY, &millis).await;
    kv_put_best_effort(kv, CIDR_LIST_ATTEMPTED_AT_KV_KEY, &millis).await;
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
    fn test_refresh_lease_is_exclusive_until_dropped() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let first = RefreshLease::claim(now).expect("nothing holds the lease yet");
        assert!(RefreshLease::claim(now).is_none(), "a second claim must wait for the first");
        drop(first);
        assert!(RefreshLease::claim(now).is_some(), "dropping the claim releases the lease");
    }

    #[test]
    fn test_refresh_lease_that_never_finishes_is_ignored_once_it_expires() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let stuck = RefreshLease::claim(now).expect("nothing holds the lease yet");
        let later = now + REFRESH_LEASE_DURATION + Duration::from_secs(1);
        let replacement = RefreshLease::claim(later).expect("the stuck lease has expired");
        drop(stuck); // Must not release the replacement's lease.
        assert!(RefreshLease::claim(later).is_none(), "the replacement still holds its lease");
        drop(replacement);
    }
}
