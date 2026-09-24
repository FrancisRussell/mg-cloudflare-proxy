// Mercurygram's notifications arrive as two kinds of request: a content-bearing
// POST and a bare PUT wake-up (all there is when there's no content to send,
// e.g. secret chats). Per aesgcm-proxy, which this is ported from, that's
// because a Simple Push token (`token_type=4`) is registered alongside the
// WebPush one, so a PUT is sent for every event and a POST also for regular
// messages. Like aesgcm-proxy, this drops the PUT when the POST for the same
// endpoint has just arrived. One instance of this Durable Object exists per
// endpoint URL, so the PUT and POST for the same endpoint always land on the
// same instance and can be correlated — a plain Worker gives no such
// guarantee across separate requests.
//
// State lives in `Cell`, not `state.storage()`: the correlation window
// (`RECENT_POST_WINDOW`) is far shorter than a Durable Object's idle eviction
// time, so nothing here is worth persisting across a restart.

use std::cell::Cell;
use std::time::{Duration, SystemTime};

use http::StatusCode;
use worker::*;

use crate::clock::{self, Deadline};
use crate::outbound::{send_with_timeout, FetchFailure};

/// Push headers from RFC 8030 that the `http` crate has no constant for.
/// `HeaderName::from_static` is `const fn`, so these are checked and built at
/// compile time; `worker::Headers` itself only takes `&str`, so callers pass
/// `NAME.as_str()`.
mod header_names {
    use http::HeaderName;

    /// RFC 8030 §5.2 message lifetime, in seconds.
    pub const TTL: HeaderName = HeaderName::from_static("ttl");
    /// RFC 8030 §5.3 delivery priority hint.
    pub const URGENCY: HeaderName = HeaderName::from_static("urgency");
}

/// RFC 8030 §5.2 message lifetime sent on the forwarded push, in seconds --
/// the maximum, so the push server retries delivery for as long as it's
/// willing to rather than giving up early.
const TTL_SECONDS: u32 = 30 * 24 * 60 * 60;
/// RFC 8030 §5.3 delivery priority sent on the forwarded push -- Telegram
/// notifications are time-sensitive, so always the highest priority.
const URGENCY_HIGH: &str = "high";
/// The `Content-Encoding` sent on every forwarded push. The folded body is not
/// itself aes128gcm-encoded.
const CONTENT_ENCODING_AES128GCM: &str = "aes128gcm";

/// How long a successful POST's timestamp counts as "recent" when a PUT for
/// the same endpoint checks in.
const RECENT_POST_WINDOW: Duration = Duration::from_secs(2);

/// How long the PUT handler waits for a same-endpoint POST to land before
/// giving up and forwarding a synthetic wake-up. Nothing documents how far
/// apart the two requests arrive, so this is an empirical guess, not a spec
/// value.
const CORRELATION_WAIT: Duration = Duration::from_millis(200);

/// How much of the request's time a PUT keeps back for forwarding its wake-up
/// while it waits for POSTs still being forwarded. Once only this much is left
/// it stops waiting and forwards, accepting a possible duplicate over holding
/// the wake-up up behind a slow push server. A POST's own retry can extend
/// how long it holds `posts_in_flight`, making that duplicate somewhat more
/// likely than before -- the same trade-off, just reached a little more often.
const FORWARD_RESERVE: Duration = Duration::from_secs(1);
/// How often that wait checks whether the POSTs have finished.
const POST_IN_FLIGHT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How much of `deadline` a retried attempt needs left (on top of any wait
/// before it, e.g. a 429's `Retry-After`) to be worth making at all, rather
/// than answering with the first attempt's failure. The only cap on how long
/// a `Retry-After` is honoured: spending the rest of the budget waiting one
/// out is no different from spending it on any other retry.
const MIN_RETRY_BUDGET: Duration = Duration::from_secs(1);

/// One endpoint's record of recent POSTs, used to decide whether its PUTs are
/// redundant wake-ups.
#[durable_object]
#[derive(Debug)]
pub struct Correlator {
    last_post: Cell<Option<SystemTime>>,
    /// POSTs currently being forwarded. Each one is unrecorded in `last_post`
    /// until its forward succeeds, so a PUT that only looked at `last_post`
    /// could forward a wake-up while its own POST was still on the way.
    posts_in_flight: Cell<u32>,
    // A Durable Object's `fetch` takes `&self`, so the runtime can dispatch
    // concurrent requests to the same instance, interleaved at `.await`
    // points. Without this flag, two PUTs arriving close together could
    // both pass the "no recent POST" check, both wait out
    // `CORRELATION_WAIT`, and both forward — a duplicate wake-up. Whichever
    // PUT claims this flag first is the sole decision-maker; a second
    // concurrent PUT defers to it instead of racing to its own forward.
    put_in_flight: Cell<bool>,
}

impl DurableObject for Correlator {
    // Neither `State` nor `Env` is needed: correlation state lives purely in
    // `last_post`/`put_in_flight` (see module doc — deliberately not
    // `state.storage()`), and forwarding needs no bindings.
    fn new(_state: State, _env: Env) -> Self {
        Self { last_post: Cell::new(None), posts_in_flight: Cell::new(0), put_in_flight: Cell::new(false) }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let Some(target) = req.headers().get(crate::header_names::X_RELAY_TARGET.as_str())? else {
            return Response::error("missing X-Relay-Target", StatusCode::BAD_REQUEST.as_u16());
        };
        let target_url = url::Url::parse(&target).map_err(|e| Error::RustError(format!("bad target: {e}")))?;
        let budget = req
            .headers()
            .get(crate::header_names::X_RELAY_BUDGET_MS.as_str())?
            .and_then(|millis| millis.parse::<u64>().ok())
            .map_or(crate::DEFAULT_REQUEST_BUDGET, Duration::from_millis);
        let deadline = Deadline::after(budget);
        let body = req.bytes().await?;

        match req.method() {
            Method::Post => self.handle_post(&target_url, body, deadline).await,
            Method::Put => self.handle_put(&target_url, body, deadline).await,
            _ => crate::error_response(StatusCode::METHOD_NOT_ALLOWED),
        }
    }
}

impl Correlator {
    /// POST leg: forward the (already header-folded) body, and on success
    /// record that this endpoint just received real content, so a PUT
    /// arriving shortly after knows to suppress its wake-up.
    async fn handle_post(&self, target: &url::Url, body: Vec<u8>, deadline: Deadline) -> Result<Response> {
        let _in_flight = PostInFlight::begin(&self.posts_in_flight);
        let resp = forward(target, body, deadline).await?;
        if StatusCode::from_u16(resp.status_code()).is_ok_and(|s| s.is_success()) {
            self.last_post.set(Some(clock::now()));
        }
        Ok(resp)
    }

    /// PUT leg: if a POST for this same endpoint already landed (or lands
    /// within the wait window), this event was already delivered as real
    /// content — drop the redundant wake-up. Otherwise forward the original
    /// Simple Push body as a synthetic wake-up. A concurrent PUT for the
    /// same endpoint defers to whichever one got here first (see
    /// `put_in_flight`'s doc comment).
    async fn handle_put(&self, target: &url::Url, body: Vec<u8>, deadline: Deadline) -> Result<Response> {
        if self.recent_post() {
            return Response::ok("");
        }
        let Some(claim) = PutInFlight::claim(&self.put_in_flight) else { return Response::ok("") };

        Delay::from(CORRELATION_WAIT).await;
        self.wait_for_posts_in_flight(deadline).await;

        let should_forward = !self.recent_post();
        drop(claim);

        if should_forward {
            forward(target, body, deadline).await
        } else {
            Response::ok("")
        }
    }

    /// Waits for POSTs still being forwarded, until only `FORWARD_RESERVE` of
    /// the request's time is left: one may yet succeed and make this PUT
    /// redundant. A POST that fails records nothing, so the PUT still forwards
    /// after it.
    async fn wait_for_posts_in_flight(&self, deadline: Deadline) {
        while self.posts_in_flight.get() > 0 && deadline.remaining() > FORWARD_RESERVE {
            Delay::from(POST_IN_FLIGHT_POLL_INTERVAL).await;
        }
    }

    /// True if a POST for this endpoint succeeded within `RECENT_POST_WINDOW`.
    fn recent_post(&self) -> bool { is_post_recent(clock::now(), self.last_post.get(), RECENT_POST_WINDOW) }
}

/// Counts a POST as in flight for as long as it lives, including if it is
/// cancelled or fails.
#[derive(Debug)]
struct PostInFlight<'a>(&'a Cell<u32>);

impl<'a> PostInFlight<'a> {
    /// Counts one more POST in flight, until the returned value is dropped.
    fn begin(counter: &'a Cell<u32>) -> Self {
        counter.set(counter.get() + 1);
        Self(counter)
    }
}

impl Drop for PostInFlight<'_> {
    fn drop(&mut self) { self.0.set(self.0.get() - 1); }
}

/// Holds `Correlator::put_in_flight` for as long as it lives. Releasing on
/// drop means a PUT that is cancelled while waiting can't leave the flag set
/// and every later PUT for the endpoint suppressed.
#[derive(Debug)]
struct PutInFlight<'a>(&'a Cell<bool>);

impl<'a> PutInFlight<'a> {
    /// The claim, or `None` if another PUT already holds `flag`.
    fn claim(flag: &'a Cell<bool>) -> Option<Self> {
        if flag.replace(true) {
            None
        } else {
            Some(Self(flag))
        }
    }
}

impl Drop for PutInFlight<'_> {
    fn drop(&mut self) { self.0.set(false); }
}

/// True if `last_post` is within `window` of `now`.
fn is_post_recent(now: SystemTime, last_post: Option<SystemTime>, window: Duration) -> bool {
    last_post.is_some_and(|t| clock::is_within(now, t, window))
}

/// Forwards `body` to `target` as a WebPush-shaped POST, retrying once for a
/// failure that looks transient (see `retry_delay`). RFC 8030 §5 expects a
/// `201 Created` with a `Location` header on success, and some senders back
/// off on other 2xx codes, so any 2xx is normalized to that shape.
///
/// Uses `redirect: manual`, which stops a redirect being followed and
/// surfaces its real status and `Location` rather than an opaque response. A
/// push server that hasn't answered when `deadline` passes is given up on.
async fn forward(target: &url::Url, body: Vec<u8>, deadline: Deadline) -> Result<Response> {
    let body_size = body.len();
    let host = target.host_str().unwrap_or("?");

    let mut outcome = send_once(target, &body, deadline).await?;
    let mut retry_after = match &outcome {
        Ok(resp) => resp.headers().get(http::header::RETRY_AFTER.as_str())?,
        Err(_) => None,
    };
    let classified = match &outcome {
        Err(failure) => Err(*failure),
        Ok(resp) => Ok((resp.status_code(), retry_after.as_deref())),
    };
    if let Some(delay) = retry_delay(classified, clock::now()) {
        if deadline.remaining() > delay + MIN_RETRY_BUDGET {
            match &outcome {
                Err(failure) => console_log!("forward: retrying host={host} reason=fetch_failed error={failure}"),
                Ok(resp) => {
                    console_log!("forward: retrying host={host} reason=bad_status status={}", resp.status_code());
                }
            }
            if !delay.is_zero() {
                Delay::from(delay).await;
            }
            outcome = send_once(target, &body, deadline).await?;
            retry_after = match &outcome {
                Ok(resp) => resp.headers().get(http::header::RETRY_AFTER.as_str())?,
                Err(_) => None,
            };
        }
    }

    let resp = match outcome {
        Ok(resp) => resp,
        Err(failure) => {
            console_error!("forward failed: host={host} reason={failure}");
            return crate::error_response(failure.into());
        }
    };
    let push_server_status = resp.status_code();

    // A push server that redirects is rejected outright rather than relayed:
    // the SSRF check on `target` never saw wherever the Location points.
    if StatusCode::from_u16(push_server_status).is_ok_and(|s| s.is_redirection()) {
        console_error!(
            "forward rejected: host={host} reason=push_server_redirected push_server_status={push_server_status}"
        );
        return crate::error_response(StatusCode::BAD_GATEWAY);
    }

    let location = resp.headers().get(http::header::LOCATION.as_str())?;
    // retry_after already reflects this response: fetched once above, and
    // refreshed after a retry, never twice for the same response.
    let response =
        match ForwardReply::new(push_server_status, location.as_deref(), retry_after.as_deref(), target.as_str()) {
            ForwardReply::Created { location } => {
                let headers = Headers::new();
                headers.set(http::header::LOCATION.as_str(), &location)?;
                Response::empty()?.with_status(StatusCode::CREATED.as_u16()).with_headers(headers)
            }
            ForwardReply::Failed { status, retry_after } => {
                let headers = Headers::new();
                if let Some(retry_after) = retry_after {
                    headers.set(http::header::RETRY_AFTER.as_str(), &retry_after)?;
                }
                Response::empty()?.with_status(status).with_headers(headers)
            }
        };

    console_log!(
        "forwarded: host={host} body_size={body_size} push_server_status={push_server_status} our_status={}",
        response.status_code()
    );
    Ok(response)
}

/// Builds and sends one push attempt.
async fn send_once(
    target: &url::Url, body: &[u8], deadline: Deadline,
) -> Result<std::result::Result<Response, FetchFailure>> {
    let headers = Headers::new();
    headers.set(header_names::TTL.as_str(), &TTL_SECONDS.to_string())?;
    headers.set(header_names::URGENCY.as_str(), URGENCY_HIGH)?;
    headers.set(http::header::CONTENT_ENCODING.as_str(), CONTENT_ENCODING_AES128GCM)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual)
        .with_body(Some(js_sys::Uint8Array::from(body).into()));

    let req = Request::new_with_init(target.as_str(), &init)?;
    // The push server gets whatever is left of the request's time.
    Ok(send_with_timeout(req, deadline.remaining()).await)
}

/// How long to wait before retrying `outcome`, or `None` if it isn't worth
/// retrying at all: a timeout or DNS failure is unlikely to resolve within
/// the same request, and a push server status is only retried if it looks
/// transient -- 502, 503, 504, or a 429 with a usable `Retry-After` (RFC 8030
/// section 8.4). `now` is only needed to turn an HTTP-date `Retry-After` into
/// a duration; a delay-seconds one doesn't need it.
fn retry_delay(outcome: std::result::Result<(u16, Option<&str>), FetchFailure>, now: SystemTime) -> Option<Duration> {
    match outcome {
        // A connection failure can't be told apart from one where the push
        // server already processed the request before the connection dropped
        // -- retrying it risks delivering the same push twice, accepted like
        // every other duplicate-over-missed trade-off here.
        Err(FetchFailure::Connection) => Some(Duration::ZERO),
        Err(FetchFailure::TimedOut | FetchFailure::Dns) => None,
        Ok((status, retry_after)) => match StatusCode::from_u16(status).ok() {
            Some(StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT) => {
                Some(Duration::ZERO)
            }
            Some(StatusCode::TOO_MANY_REQUESTS) => retry_after_delay(retry_after?, now),
            _ => None,
        },
    }
}

/// Parses a `Retry-After` value in either form RFC 7231 section 7.1.3
/// allows -- delay-seconds, or an HTTP-date -- as a duration from `now`. A
/// date already in the past counts as due immediately, not as unusable.
fn retry_after_delay(retry_after: &str, now: SystemTime) -> Option<Duration> {
    if let Ok(seconds) = retry_after.parse() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(retry_after).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

/// How `forward` answers the caller once the push server has answered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ForwardReply {
    /// The push was accepted: RFC 8030 section 5's `201 Created` with the
    /// push message's `Location`.
    Created { location: String },
    /// The push server refused it. Only its status is passed on (RFC 8030
    /// gives statuses such as 404 for an expired subscription and 429 for a
    /// rate limit a meaning) along with `Retry-After`, which it may send with
    /// a 429 (RFC 8030 section 8.4). Its body and other headers have no
    /// defined meaning and aren't relayed.
    Failed { status: u16, retry_after: Option<String> },
}

impl ForwardReply {
    /// The reply for a push server that answered `status`, with the given
    /// `Location` and `Retry-After`. Any 2xx counts as accepted, since some
    /// senders back off on other 2xx codes; a missing `Location` falls back to
    /// `target`.
    fn new(status: u16, location: Option<&str>, retry_after: Option<&str>, target: &str) -> Self {
        if StatusCode::from_u16(status).is_ok_and(|s| s.is_success()) {
            Self::Created { location: location.map_or_else(|| target.to_string(), String::from) }
        } else {
            Self::Failed { status, retry_after: retry_after.map(String::from) }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn test_post_in_flight_counts_overlapping_posts_until_dropped() {
        let counter = Cell::new(0);
        let first = PostInFlight::begin(&counter);
        let second = PostInFlight::begin(&counter);
        assert_eq!(counter.get(), 2);
        drop(first);
        assert_eq!(counter.get(), 1);
        drop(second);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_put_in_flight_is_exclusive_until_dropped() {
        let flag = Cell::new(false);
        let first = PutInFlight::claim(&flag).expect("nothing holds the flag yet");
        assert!(PutInFlight::claim(&flag).is_none(), "a second claim must wait for the first to be released");
        drop(first);
        assert!(PutInFlight::claim(&flag).is_some(), "dropping the claim releases the flag");
    }

    #[test]
    fn test_is_post_recent() {
        let last_post = UNIX_EPOCH + Duration::from_secs(1);
        let just_inside = last_post + RECENT_POST_WINDOW - Duration::from_millis(1);
        let just_outside = last_post + RECENT_POST_WINDOW;
        assert!(is_post_recent(just_inside, Some(last_post), RECENT_POST_WINDOW));
        assert!(!is_post_recent(just_outside, Some(last_post), RECENT_POST_WINDOW));
        assert!(!is_post_recent(just_inside, None, RECENT_POST_WINDOW), "no POST has been seen");
    }

    /// An arbitrary "now" for the `retry_delay`/`retry_after_delay` tests.
    fn now() -> SystemTime { UNIX_EPOCH + Duration::from_secs(1_700_000_000) }

    #[test]
    fn test_retry_delay_retries_connection_failures_immediately() {
        assert_eq!(retry_delay(Err(FetchFailure::Connection), now()), Some(Duration::ZERO));
    }

    #[test]
    fn test_retry_delay_does_not_retry_timeouts_or_dns_failures() {
        assert_eq!(retry_delay(Err(FetchFailure::TimedOut), now()), None);
        assert_eq!(retry_delay(Err(FetchFailure::Dns), now()), None);
    }

    #[test]
    fn test_retry_delay_retries_transient_push_server_statuses_immediately() {
        for status in [StatusCode::BAD_GATEWAY, StatusCode::SERVICE_UNAVAILABLE, StatusCode::GATEWAY_TIMEOUT] {
            assert_eq!(retry_delay(Ok((status.as_u16(), None)), now()), Some(Duration::ZERO), "status: {status}");
        }
    }

    #[test]
    fn test_retry_delay_does_not_retry_other_push_server_statuses() {
        for status in [StatusCode::OK, StatusCode::BAD_REQUEST, StatusCode::NOT_FOUND, StatusCode::GONE] {
            assert_eq!(retry_delay(Ok((status.as_u16(), None)), now()), None, "status: {status}");
        }
    }

    #[test]
    fn test_retry_delay_honours_a_short_429_retry_after() {
        assert_eq!(
            retry_delay(Ok((StatusCode::TOO_MANY_REQUESTS.as_u16(), Some("2"))), now()),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn test_retry_delay_honours_a_long_429_retry_after_too() {
        // retry_delay itself doesn't cap this -- forward()'s own budget check
        // is what decides whether waiting this long is actually attempted.
        assert_eq!(
            retry_delay(Ok((StatusCode::TOO_MANY_REQUESTS.as_u16(), Some("120"))), now()),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn test_retry_delay_does_not_retry_429_with_no_usable_retry_after() {
        for retry_after in [None, Some("soon"), Some("")] {
            assert_eq!(
                retry_delay(Ok((StatusCode::TOO_MANY_REQUESTS.as_u16(), retry_after)), now()),
                None,
                "retry_after: {retry_after:?}"
            );
        }
    }

    #[test]
    fn test_retry_after_delay_parses_delay_seconds() {
        assert_eq!(retry_after_delay("2", now()), Some(Duration::from_secs(2)));
    }

    #[test]
    fn test_retry_after_delay_parses_an_http_date() {
        let at = now() + Duration::from_secs(30);
        assert_eq!(retry_after_delay(&httpdate::fmt_http_date(at), now()), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_retry_after_delay_treats_a_past_http_date_as_due_now() {
        let at = now() - Duration::from_secs(30);
        assert_eq!(retry_after_delay(&httpdate::fmt_http_date(at), now()), Some(Duration::ZERO));
    }

    #[test]
    fn test_retry_after_delay_rejects_unparseable_values() {
        for retry_after in ["soon", "", "Not, 32 Foo 2024 99:99:99 GMT"] {
            assert_eq!(retry_after_delay(retry_after, now()), None, "retry_after: {retry_after:?}");
        }
    }

    #[test]
    fn test_forward_reply_failure_passes_on_only_status_and_retry_after() {
        let target = "https://target.example";
        assert_eq!(
            ForwardReply::new(
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                Some("https://example.com/x"),
                Some("30"),
                target
            ),
            ForwardReply::Failed {
                status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                retry_after: Some("30".to_string())
            }
        );
        assert_eq!(
            ForwardReply::new(StatusCode::NOT_FOUND.as_u16(), None, None, target),
            ForwardReply::Failed { status: 404, retry_after: None }
        );
    }

    #[test]
    fn test_forward_reply_2xx_preserves_location() {
        assert_eq!(
            ForwardReply::new(StatusCode::OK.as_u16(), Some("https://example.com/x"), None, "https://target.example"),
            ForwardReply::Created { location: "https://example.com/x".to_string() }
        );
    }

    #[test]
    fn test_forward_reply_2xx_falls_back_to_target() {
        assert_eq!(
            ForwardReply::new(StatusCode::NO_CONTENT.as_u16(), None, None, "https://target.example"),
            ForwardReply::Created { location: "https://target.example".to_string() }
        );
    }
}
