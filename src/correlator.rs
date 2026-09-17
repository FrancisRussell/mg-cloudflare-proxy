// SPDX-FileCopyrightText: 2026 Francis
// SPDX-License-Identifier: MIT OR Apache-2.0
//
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
use std::time::Duration;

use worker::*;

/// How long a successful POST's timestamp counts as "recent" when a PUT for
/// the same endpoint checks in.
const RECENT_POST_WINDOW_MS: f64 = 2_000.0;

/// How long the PUT handler waits for a same-endpoint POST to land before
/// giving up and forwarding a synthetic wake-up. Telegram's docs don't
/// describe this dual-delivery pattern at all, so there's no documented
/// timing to derive this from — it's an empirical guess, not a spec value.
const CORRELATION_WAIT_MS: u64 = 200;

#[durable_object]
#[derive(Debug)]
pub struct Correlator {
    last_post: Cell<Option<f64>>,
}

impl DurableObject for Correlator {
    // Neither `State` nor `Env` is needed: correlation state lives purely in
    // `last_post` (see module doc — deliberately not `state.storage()`), and
    // forwarding needs no bindings.
    fn new(_state: State, _env: Env) -> Self { Self { last_post: Cell::new(None) } }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let Some(target) = req.headers().get("X-Relay-Target")? else {
            return Response::error("missing X-Relay-Target", 400);
        };
        let target_url = url::Url::parse(&target).map_err(|e| Error::RustError(format!("bad target: {e}")))?;
        let body = req.bytes().await?;

        match req.method() {
            Method::Post => self.handle_post(&target_url, body).await,
            Method::Put => self.handle_put(&target_url, body).await,
            _ => Response::error("method not allowed", 405),
        }
    }
}

impl Correlator {
    /// POST leg: forward the (already header-folded) body, and on success
    /// record that this endpoint just received real content, so a PUT
    /// arriving shortly after knows to suppress its wake-up.
    async fn handle_post(&self, target: &url::Url, body: Vec<u8>) -> Result<Response> {
        let resp = forward(target, body).await?;
        if (200..300).contains(&resp.status_code()) {
            // millis-since-epoch fits exactly in f64 until the year 287396.
            #[allow(clippy::cast_precision_loss)]
            self.last_post.set(Some(Date::now().as_millis() as f64));
        }
        Ok(resp)
    }

    /// PUT leg: if a POST for this same endpoint already landed (or lands
    /// within the wait window), this event was already delivered as real
    /// content — drop the redundant wake-up. Otherwise forward the original
    /// Simple Push body as a synthetic wake-up.
    async fn handle_put(&self, target: &url::Url, body: Vec<u8>) -> Result<Response> {
        if self.recent_post() {
            return Response::ok("");
        }

        Delay::from(Duration::from_millis(CORRELATION_WAIT_MS)).await;

        if self.recent_post() {
            return Response::ok("");
        }

        forward(target, body).await
    }

    // millis-since-epoch fits exactly in f64 until the year 287396.
    #[allow(clippy::cast_precision_loss)]
    fn recent_post(&self) -> bool {
        match self.last_post.get() {
            Some(t) => (Date::now().as_millis() as f64 - t) < RECENT_POST_WINDOW_MS,
            None => false,
        }
    }
}

/// Forwards `body` to `target` as a WebPush-shaped POST. RFC 8030 §5 expects
/// a `201 Created` with a `Location` header on success, and some senders
/// back off on other 2xx codes, so any 2xx is normalized to that shape.
async fn forward(target: &url::Url, body: Vec<u8>) -> Result<Response> {
    let headers = Headers::new();
    headers.set("ttl", "2592000")?;
    headers.set("urgency", "high")?;
    headers.set("content-encoding", "aes128gcm")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Error)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));

    let req = Request::new_with_init(target.as_str(), &init)?;
    let resp = Fetch::Request(req).send().await?;

    if !(200..300).contains(&resp.status_code()) {
        return Ok(resp);
    }

    let location = resp.headers().get("location")?.unwrap_or_else(|| target.to_string());

    Response::empty().map(|r| {
        r.with_status(201).with_headers({
            let h = Headers::new();
            let _ = h.set("location", &location);
            h
        })
    })
}
