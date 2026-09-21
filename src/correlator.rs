// Telegram sends two requests per message: a content-bearing POST and a
// bare PUT wake-up (used when there's no content to send, e.g. secret
// chats). One instance of this Durable Object exists per endpoint URL (see
// `call_correlator` in lib.rs), so the PUT and POST for the same endpoint
// always land on the same instance and can be correlated — a plain Worker
// gives no such guarantee across separate requests.
//
// State lives in `Cell`, not `state.storage()`: the correlation window is
// only ~2s, well under a Durable Object's idle eviction time, so nothing
// here is worth persisting across a restart.

use std::cell::Cell;
use std::time::{Duration, SystemTime};

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
/// The `WebPush` payload encoding of the forwarded body -- aesgcm Draft-04's
/// only supported encoding.
const CONTENT_ENCODING_AES128GCM: &str = "aes128gcm";

/// How long a successful POST's timestamp counts as "recent" when a PUT for
/// the same endpoint checks in.
const RECENT_POST_WINDOW: Duration = Duration::from_secs(2);

/// How long the PUT handler waits for a same-endpoint POST to land before
/// giving up and forwarding a synthetic wake-up. Telegram's docs don't
/// describe this dual-delivery pattern at all, so there's no documented
/// timing to derive this from — it's an empirical guess, not a spec value.
const CORRELATION_WAIT: Duration = Duration::from_millis(200);

#[durable_object]
#[derive(Debug)]
pub struct Correlator {
    last_post: Cell<Option<SystemTime>>,
    // A Durable Object's `fetch` takes `&self`, so the runtime can dispatch
    // concurrent requests to the same instance, interleaved at `.await`
    // points. Without this flag, two PUTs arriving close together could
    // both pass the "no recent POST" check, both wait out
    // `CORRELATION_WAIT_MS`, and both forward — a duplicate wake-up. Whichever
    // PUT claims this flag first is the sole decision-maker; a second
    // concurrent PUT defers to it instead of racing to its own forward.
    put_in_flight: Cell<bool>,
}

impl DurableObject for Correlator {
    // Neither `State` nor `Env` is needed: correlation state lives purely in
    // `last_post`/`put_in_flight` (see module doc — deliberately not
    // `state.storage()`), and forwarding needs no bindings.
    fn new(_state: State, _env: Env) -> Self { Self { last_post: Cell::new(None), put_in_flight: Cell::new(false) } }

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
        if self.put_in_flight.replace(true) {
            return Response::ok("");
        }

        Delay::from(CORRELATION_WAIT).await;

        let should_forward = !self.recent_post();
        self.put_in_flight.set(false);

        if should_forward {
            forward(target, body).await
        } else {
            Response::ok("")
        }
    }

    fn recent_post(&self) -> bool { is_post_recent(clock::now(), self.last_post.get(), RECENT_POST_WINDOW) }
}

/// True if `last_post` is within `window` of `now`.
fn is_post_recent(now: SystemTime, last_post: Option<SystemTime>, window: Duration) -> bool {
    last_post.is_some_and(|t| clock::is_within(now, t, window))
}

/// Forwards `body` to `target` as a WebPush-shaped POST. RFC 8030 §5 expects
/// a `201 Created` with a `Location` header on success, and some senders
/// back off on other 2xx codes, so any 2xx is normalized to that shape.
///
/// Uses `redirect: manual` rather than `redirect: error`: both stop a
/// redirect from being followed, but `error` throws on construction under
/// the local Miniflare/workerd runtime for reasons that didn't reproduce
/// under `follow`/`manual` in isolation testing, while `manual` also has the
/// advantage (server-side, unlike a browser) of surfacing the redirect's
/// real status and `Location` rather than an opaque response.
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
    let resp = Fetch::Request(req).send().await?;
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

    let result = match wake_up_response_shape(distributor_status, location.as_deref(), target.as_str()) {
        None => Ok(resp),
        Some((status, location)) => Response::empty().map(|r| {
            r.with_status(status).with_headers({
                let h = Headers::new();
                let _ = h.set(header_names::LOCATION.as_str(), &location);
                h
            })
        }),
    };

    if let Ok(r) = &result {
        console_log!(
            "forwarded: host={host} body_size={body_size} distributor_status={distributor_status} our_status={}",
            r.status_code()
        );
    }
    result
}

/// The `(status, location)` `forward` should respond with for a POST that
/// got back `status`/`location` from `target`, per RFC 8030 §5's
/// `201 Created` + `Location` shape. `None` means pass the response through
/// unchanged (a non-2xx status).
fn wake_up_response_shape(status: u16, location: Option<&str>, target: &str) -> Option<(u16, String)> {
    if !StatusCode::from_u16(status).is_ok_and(|s| s.is_success()) {
        return None;
    }
    Some((StatusCode::CREATED.as_u16(), location.map_or_else(|| target.to_string(), String::from)))
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

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
    fn test_wake_up_response_shape_non_2xx_passes_through() {
        let internal_error = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
        let not_found = StatusCode::NOT_FOUND.as_u16();
        assert_eq!(
            wake_up_response_shape(internal_error, Some("https://example.com/x"), "https://target.example"),
            None
        );
        assert_eq!(wake_up_response_shape(not_found, None, "https://target.example"), None);
    }

    #[test]
    fn test_wake_up_response_shape_2xx_preserves_location() {
        let result =
            wake_up_response_shape(StatusCode::OK.as_u16(), Some("https://example.com/x"), "https://target.example");
        assert_eq!(result, Some((StatusCode::CREATED.as_u16(), "https://example.com/x".to_string())));
    }

    #[test]
    fn test_wake_up_response_shape_2xx_falls_back_to_target() {
        let result = wake_up_response_shape(StatusCode::NO_CONTENT.as_u16(), None, "https://target.example");
        assert_eq!(result, Some((StatusCode::CREATED.as_u16(), "https://target.example".to_string())));
    }
}
