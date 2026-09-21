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
// State lives in `Cell`, not `state.storage()`: the correlation window is
// only ~2s, well under a Durable Object's idle eviction time, so nothing
// here is worth persisting across a restart.

use std::cell::Cell;
use std::pin::pin;
use std::time::{Duration, SystemTime};

use futures_util::future::{select, Either};
use http::StatusCode;
use worker::*;

use crate::clock;

/// Header names used when forwarding to the distributor.
/// `HeaderName::from_static` is `const fn`, so these are checked and built at
/// compile time; `worker::Headers` itself only takes `&str`, so callers pass
/// `NAME.as_str()`.
mod header_names {
    use http::HeaderName;

    /// RFC 8030 §5.2 message lifetime, in seconds.
    pub const TTL: HeaderName = HeaderName::from_static("ttl");
    /// RFC 8030 §5.3 delivery priority hint.
    pub const URGENCY: HeaderName = HeaderName::from_static("urgency");
    /// The `WebPush` payload encoding of the forwarded body.
    pub const CONTENT_ENCODING: HeaderName = HeaderName::from_static("content-encoding");
    /// RFC 8030 §5 resource URL for the created push message, on both the
    /// distributor's response and our own normalized one.
    pub const LOCATION: HeaderName = HeaderName::from_static("location");
}

/// RFC 8030 §5.2 message lifetime sent on the forwarded push, in seconds --
/// the maximum, so the distributor retries delivery for as long as it's
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

/// How long a push server gets to answer a forwarded push before it's given
/// up on. Bounds a server that accepts the connection and then never replies,
/// which would otherwise hold the request open indefinitely.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the PUT handler waits for a same-endpoint POST to land before
/// giving up and forwarding a synthetic wake-up. Nothing documents how far
/// apart the two requests arrive, so this is an empirical guess, not a spec
/// value.
const CORRELATION_WAIT: Duration = Duration::from_millis(200);

/// The longest a PUT keeps waiting for POSTs that are still being forwarded
/// once `CORRELATION_WAIT` is over. Past it the PUT stops waiting and
/// forwards, accepting a possible duplicate over holding the wake-up up
/// behind a slow push server.
const POST_IN_FLIGHT_MAX_WAIT: Duration = Duration::from_secs(5);
/// How often that wait checks whether the POSTs have finished.
const POST_IN_FLIGHT_POLL_INTERVAL: Duration = Duration::from_millis(50);

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
        let body = req.bytes().await?;

        match req.method() {
            Method::Post => self.handle_post(&target_url, body).await,
            Method::Put => self.handle_put(&target_url, body).await,
            _ => crate::error_response(StatusCode::METHOD_NOT_ALLOWED),
        }
    }
}

impl Correlator {
    /// POST leg: forward the (already header-folded) body, and on success
    /// record that this endpoint just received real content, so a PUT
    /// arriving shortly after knows to suppress its wake-up.
    async fn handle_post(&self, target: &url::Url, body: Vec<u8>) -> Result<Response> {
        let _in_flight = PostInFlight::begin(&self.posts_in_flight);
        let resp = forward(target, body).await?;
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
    async fn handle_put(&self, target: &url::Url, body: Vec<u8>) -> Result<Response> {
        if self.recent_post() {
            return Response::ok("");
        }
        let Some(claim) = PutInFlight::claim(&self.put_in_flight) else { return Response::ok("") };

        Delay::from(CORRELATION_WAIT).await;
        self.wait_for_posts_in_flight().await;

        let should_forward = !self.recent_post();
        drop(claim);

        if should_forward {
            forward(target, body).await
        } else {
            Response::ok("")
        }
    }

    /// Waits, up to `POST_IN_FLIGHT_MAX_WAIT`, for POSTs still being forwarded:
    /// one may yet succeed and make this PUT redundant. A POST that fails
    /// records nothing, so the PUT still forwards after it.
    async fn wait_for_posts_in_flight(&self) {
        let deadline = clock::now() + POST_IN_FLIGHT_MAX_WAIT;
        while self.posts_in_flight.get() > 0 && clock::now() < deadline {
            Delay::from(POST_IN_FLIGHT_POLL_INTERVAL).await;
        }
    }

    fn recent_post(&self) -> bool { is_post_recent(clock::now(), self.last_post.get(), RECENT_POST_WINDOW) }
}

/// Counts a POST as in flight for as long as it lives, including if it is
/// cancelled or fails.
#[derive(Debug)]
struct PostInFlight<'a>(&'a Cell<u32>);

impl<'a> PostInFlight<'a> {
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

/// Forwards `body` to `target` as a WebPush-shaped POST. RFC 8030 §5 expects
/// a `201 Created` with a `Location` header on success, and some senders
/// back off on other 2xx codes, so any 2xx is normalized to that shape.
///
/// Uses `redirect: manual`, which stops a redirect being followed and
/// surfaces its real status and `Location` rather than an opaque response.
async fn forward(target: &url::Url, body: Vec<u8>) -> Result<Response> {
    let headers = Headers::new();
    headers.set(header_names::TTL.as_str(), &TTL_SECONDS.to_string())?;
    headers.set(header_names::URGENCY.as_str(), URGENCY_HIGH)?;
    headers.set(header_names::CONTENT_ENCODING.as_str(), CONTENT_ENCODING_AES128GCM)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));

    let body_size = body.len();
    let host = target.host_str().unwrap_or("?");

    let req = Request::new_with_init(target.as_str(), &init)?;
    let resp = match send_with_timeout(req).await {
        Ok(resp) => resp,
        Err(failure) => {
            console_error!("forward failed: host={host} reason={failure}");
            return crate::error_response(failure.status());
        }
    };
    let distributor_status = resp.status_code();

    // A distributor that redirects is rejected outright rather than relayed:
    // the SSRF check on `target` never saw wherever the Location points.
    if StatusCode::from_u16(distributor_status).is_ok_and(|s| s.is_redirection()) {
        console_error!(
            "forward rejected: host={host} reason=distributor_redirected distributor_status={distributor_status}"
        );
        return crate::error_response(StatusCode::BAD_GATEWAY);
    }

    let location = resp.headers().get(header_names::LOCATION.as_str())?;
    let retry_after = resp.headers().get(http::header::RETRY_AFTER.as_str())?;
    let response = match forward_reply(distributor_status, location.as_deref(), retry_after.as_deref(), target.as_str())
    {
        ForwardReply::Created { location } => {
            let headers = Headers::new();
            headers.set(header_names::LOCATION.as_str(), &location)?;
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
        "forwarded: host={host} body_size={body_size} distributor_status={distributor_status} our_status={}",
        response.status_code()
    );
    Ok(response)
}

/// Why a push server gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardFailure {
    TimedOut,
    /// The host name didn't resolve.
    Dns,
    /// Refused, reset, closed early, or an unparseable reply.
    Connection,
}

impl ForwardFailure {
    /// The status to answer the caller with: a gateway timeout if the push
    /// server was too slow, otherwise a bad gateway.
    fn status(self) -> StatusCode {
        match self {
            Self::TimedOut => StatusCode::GATEWAY_TIMEOUT,
            Self::Dns | Self::Connection => StatusCode::BAD_GATEWAY,
        }
    }

    /// Classifies a failed fetch by the runtime's error text, falling back to a
    /// generic connection failure.
    fn from_fetch_error(error: &Error) -> Self {
        if error.to_string().contains("DNS lookup failed") {
            Self::Dns
        } else {
            Self::Connection
        }
    }
}

impl std::fmt::Display for ForwardFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TimedOut => "timeout",
            Self::Dns => "dns",
            Self::Connection => "connection",
        })
    }
}

/// Sends `req`, giving up after `FORWARD_TIMEOUT`.
async fn send_with_timeout(req: Request) -> std::result::Result<Response, ForwardFailure> {
    let controller = AbortController::default();
    let signal = controller.signal();
    let fetch = Fetch::Request(req);
    let send = pin!(fetch.send_with_signal(&signal));
    let timeout = pin!(Delay::from(FORWARD_TIMEOUT));
    match select(send, timeout).await {
        Either::Left((result, _)) => result.map_err(|e| ForwardFailure::from_fetch_error(&e)),
        Either::Right(..) => {
            controller.abort();
            Err(ForwardFailure::TimedOut)
        }
    }
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

/// The reply for a push server that answered `status`, with the given
/// `Location` and `Retry-After`. Any 2xx counts as accepted, since some
/// senders back off on other 2xx codes; a missing `Location` falls back to
/// `target`.
fn forward_reply(status: u16, location: Option<&str>, retry_after: Option<&str>, target: &str) -> ForwardReply {
    if StatusCode::from_u16(status).is_ok_and(|s| s.is_success()) {
        ForwardReply::Created { location: location.map_or_else(|| target.to_string(), String::from) }
    } else {
        ForwardReply::Failed { status, retry_after: retry_after.map(String::from) }
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
    fn test_is_post_recent_within_window() {
        let last_post = UNIX_EPOCH + Duration::from_secs(1);
        assert!(is_post_recent(last_post + Duration::from_millis(500), Some(last_post), RECENT_POST_WINDOW));
    }

    #[test]
    fn test_is_post_recent_outside_window() {
        let last_post = UNIX_EPOCH + Duration::from_secs(1);
        let now = last_post + RECENT_POST_WINDOW + Duration::from_millis(1);
        assert!(!is_post_recent(now, Some(last_post), RECENT_POST_WINDOW));
    }

    #[test]
    fn test_is_post_recent_no_prior_post() {
        assert!(!is_post_recent(UNIX_EPOCH + Duration::from_secs(1), None, RECENT_POST_WINDOW));
    }

    #[test]
    fn test_forward_failure_status() {
        assert_eq!(ForwardFailure::TimedOut.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(ForwardFailure::Dns.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(ForwardFailure::Connection.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_forward_failure_reasons() {
        assert_eq!(ForwardFailure::TimedOut.to_string(), "timeout");
        assert_eq!(ForwardFailure::Dns.to_string(), "dns");
        assert_eq!(ForwardFailure::Connection.to_string(), "connection");
    }

    #[test]
    fn test_forward_reply_failure_passes_on_only_status_and_retry_after() {
        let target = "https://target.example";
        assert_eq!(
            forward_reply(StatusCode::TOO_MANY_REQUESTS.as_u16(), Some("https://example.com/x"), Some("30"), target),
            ForwardReply::Failed { status: 429, retry_after: Some("30".to_string()) }
        );
        assert_eq!(
            forward_reply(StatusCode::NOT_FOUND.as_u16(), None, None, target),
            ForwardReply::Failed { status: 404, retry_after: None }
        );
    }

    #[test]
    fn test_forward_reply_2xx_preserves_location() {
        assert_eq!(
            forward_reply(StatusCode::OK.as_u16(), Some("https://example.com/x"), None, "https://target.example"),
            ForwardReply::Created { location: "https://example.com/x".to_string() }
        );
    }

    #[test]
    fn test_forward_reply_2xx_falls_back_to_target() {
        assert_eq!(
            forward_reply(StatusCode::NO_CONTENT.as_u16(), None, None, "https://target.example"),
            ForwardReply::Created { location: "https://target.example".to_string() }
        );
    }
}
