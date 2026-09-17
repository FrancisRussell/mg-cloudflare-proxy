#![warn(clippy::pedantic)]
// `use worker::*` is the crate's own idiom; naming every re-export individually
// buys nothing. This isn't a published library, so a per-fn `# Errors` section
// would be noise.
#![allow(clippy::wildcard_imports, clippy::missing_errors_doc)]
//
// Web Push relay for a UnifiedPush distributor (e.g. Sunup, ntfy): folds the
// `Encryption`/`Crypto-Key` headers Telegram sends into the body, since
// UnifiedPush distributors strip headers. See src/correlator.rs for the
// wake-up correlation this depends on. No FCM/VAPID leg — only real
// UnifiedPush distributors are targeted.

mod correlator;

pub use correlator::Correlator;
use http::StatusCode;
use ipnetwork::IpNetwork;
use worker::*;

/// Header names this crate reads or writes. `HeaderName::from_static` is
/// `const fn`, so these are checked and built at compile time;
/// `worker::Headers` itself only takes `&str`, so callers pass `NAME.as_str()`.
mod header_names {
    use http::HeaderName;

    /// Client IP set by Cloudflare's edge; see `get_client_ip`'s docs for why
    /// this is trusted over `X-Forwarded-For`.
    pub const CF_CONNECTING_IP: HeaderName = HeaderName::from_static("cf-connecting-ip");
    /// Telegram's aesgcm Draft-04 encryption parameters.
    pub const ENCRYPTION: HeaderName = HeaderName::from_static("encryption");
    /// Telegram's aesgcm Draft-04 key.
    pub const CRYPTO_KEY: HeaderName = HeaderName::from_static("crypto-key");
    /// Internal header carrying the validated forwarding target from the
    /// Worker to the Correlator Durable Object (see src/correlator.rs).
    pub(crate) const X_RELAY_TARGET: HeaderName = HeaderName::from_static("x-relay-target");
    /// Sent on the outbound CIDR-list fetch, echoing back the last fetch
    /// attempt's own timestamp, so an unchanged list costs Telegram's
    /// server a 304 rather than a full body.
    pub const IF_MODIFIED_SINCE: HeaderName = HeaderName::from_static("if-modified-since");
}

/// Real `WebPush` ciphertext is small; anything past this is treated as
/// abuse rather than buffered and forwarded. 16KB covers real Telegram
/// notifications with headroom; anything larger is likely garbage.
const MAX_BODY_BYTES: usize = 16_384;

/// Bootstrap Telegram CIDR list, embedded at build time from
/// data/telegram-cidrs.txt. Used until the runtime cache (see
/// `is_telegram_ip`) has ever successfully fetched a fresher one.
const TELEGRAM_CIDR_BOOTSTRAP: &str = include_str!("../data/telegram-cidrs.txt");

/// Rejects anything that isn't a plain http(s) URL with a host and no
/// embedded credentials. Literal private/loopback IPs are rejected below;
/// a domain name that merely resolves to one is not caught, since Workers'
/// `fetch()` gives no hook into DNS resolution to check that at connect time.
fn validate_endpoint(raw: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(raw).map_err(|e| Error::RustError(format!("invalid url: {e}")))?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(Error::RustError("scheme must be http or https".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::RustError("url must not contain credentials".into()));
    }
    match parsed.host() {
        None => return Err(Error::RustError("url has no host".into())),
        Some(url::Host::Ipv4(ip)) if !is_ip_safe(std::net::IpAddr::V4(ip)) => {
            return Err(Error::RustError("literal IP is not public".into()));
        }
        Some(url::Host::Ipv6(ip)) if !is_ip_safe(std::net::IpAddr::V6(ip)) => {
            return Err(Error::RustError("literal IP is not public".into()));
        }
        _ => {}
    }
    Ok(parsed)
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
const CIDR_LIST_MAX_AGE_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;
/// Beyond this age, force a background re-fetch even for a *recognized* IP
/// -- otherwise a Telegram range that gets dropped and later reassigned
/// (e.g. after a registry reclaim) would stay trusted forever, since a
/// recognized IP normally never triggers a fetch at all (see
/// `is_telegram_ip`) and nothing else would prompt one if only
/// already-recognized IPs ever show up. IPv4 quarantine periods for
/// reclaimed address space run 3 months (ARIN) to 6 months (RIPE) before
/// reassignment, so a month of margin is comfortably conservative without
/// adding needless fetch traffic.
const CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS: f64 = 30.0 * 24.0 * 60.0 * 60.0 * 1000.0;
/// Where to fetch the Telegram CIDR list from. Overridable via the
/// `CIDR_LIST_URL` wrangler var (see wrangler.toml) so the integration test
/// can point this at a local mock server instead of Telegram's real endpoint.
const TELEGRAM_CIDR_URL: &str = "https://core.telegram.org/resources/cidr.txt";
const CIDR_LIST_URL_VAR: &str = "CIDR_LIST_URL";
/// wrangler.toml `[[kv_namespaces]]` binding name for the CIDR list cache.
const CIDR_CACHE_KV_BINDING: &str = "CIDR_CACHE";
/// wrangler.toml `[durable_objects]` binding name for the Correlator.
const CORRELATOR_BINDING: &str = "CORRELATOR";

/// How trustworthy the cached CIDR list currently is, oldest-tolerated-use
/// first. See `CIDR_LIST_MAX_AGE_MS` and `CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS`.
enum CidrListFreshness {
    /// Recent enough that even an unrecognized IP shouldn't trigger a fetch.
    Fresh,
    /// Old enough that an unrecognized IP may trigger a fetch, but a
    /// recognized one still won't.
    Stale,
    /// Old enough (or never successfully fetched) that even a recognized IP
    /// should prompt a background re-fetch.
    VeryStale,
}

/// True if `ip` is a Telegram IP. Checks the cached (or bootstrap, if never
/// successfully fetched) list first -- a recognized IP never triggers a
/// *blocking* fetch. Only an unrecognized IP, combined with the cached list
/// being missing or older than `CIDR_LIST_MAX_AGE_MS`, triggers a fetch
/// attempt before answering: real Telegram traffic is the overwhelmingly
/// common case and shouldn't pay for an outbound round-trip to Telegram on
/// every single request, and a flood of unrecognized IPs (a scan, an
/// attack) shouldn't be able to force more than one fetch per
/// `CIDR_LIST_MAX_AGE_MS` window either.
///
/// A recognized IP against a *very* stale list still kicks off a re-fetch,
/// but in the background via `ctx.wait_until` -- it doesn't delay the
/// response, since the IP was already validated against the list on hand.
async fn is_telegram_ip(kv: &KvStore, ip: std::net::IpAddr, fetch_url: &str, ctx: &Context) -> bool {
    let (list, freshness) = current_cidr_list(kv).await;
    if is_telegram_ip_with_list(ip, &list) {
        if matches!(freshness, CidrListFreshness::VeryStale) {
            let kv = kv.clone();
            let fetch_url = fetch_url.to_string();
            ctx.wait_until(async move {
                fetch_fresh_cidr_list(&kv, &fetch_url, &list).await;
            });
        }
        return true;
    }
    if matches!(freshness, CidrListFreshness::Fresh) {
        return false;
    }

    match fetch_fresh_cidr_list(kv, fetch_url, &list).await {
        Some(fresh) => is_telegram_ip_with_list(ip, &fresh),
        None => false,
    }
}

/// The CIDR list currently on hand (cached, or the compiled-in bootstrap if
/// nothing has ever been cached), and how fresh it is.
async fn current_cidr_list(kv: &KvStore) -> (String, CidrListFreshness) {
    let list = match kv.get(CIDR_LIST_KV_KEY).text().await {
        Ok(Some(cached)) => cached,
        _ => TELEGRAM_CIDR_BOOTSTRAP.to_string(),
    };

    #[allow(clippy::cast_precision_loss)] // millis-since-epoch fits exactly in f64 until the year 287396
    let now_ms = Date::now().as_millis() as f64;
    let freshness = match kv.get(CIDR_LIST_FETCHED_AT_KV_KEY).text().await {
        Ok(Some(fetched_at)) => match fetched_at.parse::<f64>() {
            Ok(fetched_at_ms) if is_cidr_list_fresh(now_ms, fetched_at_ms, CIDR_LIST_MAX_AGE_MS) => {
                CidrListFreshness::Fresh
            }
            Ok(fetched_at_ms) if is_cidr_list_fresh(now_ms, fetched_at_ms, CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS) => {
                CidrListFreshness::Stale
            }
            _ => CidrListFreshness::VeryStale,
        },
        _ => CidrListFreshness::VeryStale,
    };

    (list, freshness)
}

/// True if `fetched_at_ms` (millis since epoch) is within `max_age_ms` of
/// `now_ms` -- i.e. recent enough to skip re-fetching.
fn is_cidr_list_fresh(now_ms: f64, fetched_at_ms: f64, max_age_ms: f64) -> bool {
    (now_ms - fetched_at_ms) < max_age_ms
}

/// Attempts to fetch, validate, and cache a fresh CIDR list from Telegram.
/// Sends the last fetch attempt's own timestamp back as `If-Modified-Since`
/// -- HTTP servers compare that against their own resource's modification
/// time regardless of who set it, so this doesn't need Telegram's actual
/// `Last-Modified` echoed back verbatim, just some past point we're asking
/// "has it changed since here". An unchanged list (the common case) then
/// costs Telegram's server a bodyless 304 instead of the full list.
///
/// The fetched-at timestamp is updated on any definitive answer from the
/// endpoint (a 304, a success, or a bad-but-reachable response like an
/// unparseable body) so a broken-but-reachable endpoint doesn't get hit on
/// every subsequent unrecognized-IP request either -- only a network-level
/// failure (couldn't reach it at all) leaves the timestamp untouched, since
/// that's the one case worth retrying sooner than `CIDR_LIST_MAX_AGE_MS`.
///
/// `current_list` is returned unchanged on a 304, since that response
/// carries no body to re-derive it from.
async fn fetch_fresh_cidr_list(kv: &KvStore, fetch_url: &str, current_list: &str) -> Option<String> {
    let headers = Headers::new();
    if let Ok(Some(fetched_at)) = kv.get(CIDR_LIST_FETCHED_AT_KV_KEY).text().await {
        if let Some(http_date) = http_date_from_millis_str(&fetched_at) {
            let _ = headers.set(header_names::IF_MODIFIED_SINCE.as_str(), &http_date);
        }
    }
    let mut init = RequestInit::new();
    init.with_headers(headers);
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
fn cidr_list_url(env: &Env) -> String {
    env.var(CIDR_LIST_URL_VAR).map_or_else(|_| TELEGRAM_CIDR_URL.to_string(), |v| v.to_string())
}

async fn mark_cidr_list_fetched(kv: &KvStore) {
    #[allow(clippy::cast_precision_loss)] // millis-since-epoch fits exactly in f64 until the year 287396
    let now_ms = Date::now().as_millis() as f64;
    kv_put_best_effort(kv, CIDR_LIST_FETCHED_AT_KV_KEY, &now_ms.to_string()).await;
}

/// Converts a millis-since-epoch string (as stored under
/// `CIDR_LIST_FETCHED_AT_KV_KEY`) into an HTTP-date string suitable for the
/// `If-Modified-Since` request header.
fn http_date_from_millis_str(millis_str: &str) -> Option<String> {
    let millis: f64 = millis_str.parse().ok()?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // stored as a non-negative millis-since-epoch value
    let js_date: js_sys::Date = Date::new(DateInit::Millis(millis as u64)).into();
    Some(js_date.to_utc_string().into())
}

/// `KvStore::put` only constructs a builder -- the write itself doesn't
/// happen until `.execute().await`, easy to miss since the outer call isn't
/// itself async. Failures are swallowed here: every caller already has a
/// fallback for a cache miss (the bootstrap list, or just re-fetching),
/// so a write failing is never worth failing an otherwise-valid request over.
async fn kv_put_best_effort(kv: &KvStore, key: &str, value: &str) {
    if let Ok(builder) = kv.put(key, value) {
        let _ = builder.execute().await;
    }
}

/// Extract client IP from the `CF-Connecting-IP` header Cloudflare's edge
/// sets on every routed request. Unlike `X-Forwarded-For`, a client cannot
/// set this header itself, which is what the Telegram IP allowlist relies on.
fn get_client_ip(req: &Request) -> Option<String> {
    req.headers().get(header_names::CF_CONNECTING_IP.as_str()).ok().flatten()
}

/// `Response::error` using `status`'s own canonical reason phrase (e.g.
/// "Forbidden" for 403) as the message, for error paths that carry no
/// extra diagnostic detail beyond the status itself.
pub(crate) fn error_response(status: StatusCode) -> Result<Response> {
    Response::error(status.canonical_reason().expect("standard status code has a canonical reason"), status.as_u16())
}

/// Cached SSRF-prevention ranges not covered by Rust's built-in methods.
mod unsafe_ranges {
    use std::sync::LazyLock;

    use ipnetwork::IpNetwork;

    pub static UNSAFE_V4: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
        vec![
            "0.0.0.0/8".parse().expect("hardcoded CIDR literal must be valid"), // This host
            "100.64.0.0/10".parse().expect("hardcoded CIDR literal must be valid"), // CGNAT
            "198.18.0.0/15".parse().expect("hardcoded CIDR literal must be valid"), // Benchmarking
        ]
    });

    pub static UNSAFE_V6: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
        vec![
            "64:ff9b::/96".parse().expect("hardcoded CIDR literal must be valid"), // NAT64
            "64:ff9b:1::/48".parse().expect("hardcoded CIDR literal must be valid"), // NAT64 well-known prefix
            "2001:db8::/32".parse().expect("hardcoded CIDR literal must be valid"), // Documentation
            "3fff::/20".parse().expect("hardcoded CIDR literal must be valid"),    // Documentation
        ]
    });
}

/// True if `ip` is a public, routable address. Uses Rust's built-in methods
/// for standard ranges (loopback, private, link-local, multicast,
/// documentation, broadcast, unspecified, unique-local) plus cached ipnetwork
/// ranges Rust doesn't cover.
fn is_ip_safe(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            // Use Rust's built-in methods for standard ranges
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return false;
            }
            // Check cached ranges Rust doesn't cover
            !unsafe_ranges::UNSAFE_V4.iter().any(|net| net.contains(ip))
        }
        std::net::IpAddr::V6(v6) => {
            // Use Rust's built-in methods for standard ranges. to_ipv4()
            // matches both IPv4-compatible (::/96) and IPv4-mapped
            // (::ffff:0:0/96) addresses; it also matches ::1, but
            // is_loopback() above already rejects that case first.
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4().is_some()
            {
                return false;
            }
            // Check cached ranges Rust doesn't cover
            !unsafe_ranges::UNSAFE_V6.iter().any(|net| net.contains(ip))
        }
    }
}

/// Folds the `Encryption`/`Crypto-Key` headers into the body, since
/// `UnifiedPush` distributors strip headers.
///
/// Body format sent to the `UnifiedPush` endpoint:
///   aesgcm\n
///   Encryption: <value>\n
///   Crypto-Key: <value>\n
///   <original binary ciphertext>
fn fold_aesgcm_body(encryption: &str, crypto_key: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + encryption.len() + crypto_key.len() + body.len());
    out.extend_from_slice(b"aesgcm\nEncryption: ");
    out.extend_from_slice(encryption.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"Crypto-Key: ");
    out.extend_from_slice(crypto_key.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body);
    out
}

/// Look up the endpoint's Correlator instance and hand it a pre-shaped
/// internal request: `X-Relay-Target` carries the validated endpoint,
/// the method (POST/PUT) tells the Durable Object which branch to run,
/// and the body is whatever that branch should forward if it decides to.
async fn call_correlator(env: &Env, endpoint: &url::Url, method: Method, body: Vec<u8>) -> Result<Response> {
    let namespace = env.durable_object(CORRELATOR_BINDING)?;
    let stub = namespace.id_from_name(endpoint.as_str())?.get_stub()?;

    let headers = Headers::new();
    headers.set(header_names::X_RELAY_TARGET.as_str(), endpoint.as_str())?;

    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers).with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));

    let req = Request::new_with_init("https://do/relay", &init)?;
    stub.fetch_with_request(req).await
}

/// POST /aesgcm?e=<url-encoded-endpoint>
///
/// Structural validation (the `?e=` param, the target endpoint, body size)
/// runs before the Telegram-IP check: those are free, local, in-process
/// checks, and there's no reason a malformed request -- e.g. a random
/// scanner missing `?e=` entirely, which was never going to be forwarded
/// either way -- should get to spend a CIDR-list fetch attempt just because
/// it happens to come from an unrecognized IP. Only a request that's
/// otherwise well-formed enough to actually forward reaches the one check
/// that can trigger outbound traffic to Telegram.
async fn handle_aesgcm(mut req: Request, ctx: RouteContext<Context>) -> Result<Response> {
    let Some(client_ip_str) = get_client_ip(&req) else {
        console_log!("rejected: leg=aesgcm reason=missing_cf_connecting_ip");
        return error_response(StatusCode::FORBIDDEN);
    };
    let Ok(client_ip) = client_ip_str.parse::<std::net::IpAddr>() else {
        console_log!("rejected: leg=aesgcm reason=unparseable_cf_connecting_ip ip={client_ip_str}");
        return error_response(StatusCode::FORBIDDEN);
    };

    let url = req.url()?;
    let Some((_, endpoint_raw)) = url.query_pairs().find(|(k, _)| k == "e") else {
        console_log!("rejected: leg=aesgcm reason=missing_e_param ip={client_ip}");
        return Response::error("missing ?e= parameter", StatusCode::BAD_REQUEST.as_u16());
    };
    let endpoint_raw = endpoint_raw.into_owned();
    let Ok(endpoint) = validate_endpoint(&endpoint_raw) else {
        console_log!("rejected: leg=aesgcm reason=invalid_endpoint ip={client_ip}");
        return error_response(StatusCode::FORBIDDEN);
    };

    let encryption = req.headers().get(header_names::ENCRYPTION.as_str())?.unwrap_or_default();
    let crypto_key = req.headers().get(header_names::CRYPTO_KEY.as_str())?.unwrap_or_default();
    let body = req.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        console_log!(
            "rejected: leg=aesgcm reason=payload_too_large ip={client_ip} host={} size={}",
            endpoint.host_str().unwrap_or("?"),
            body.len()
        );
        return error_response(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let kv = ctx.env.kv(CIDR_CACHE_KV_BINDING)?;
    if !is_telegram_ip(&kv, client_ip, &cidr_list_url(&ctx.env), &ctx.data).await {
        console_log!("rejected: leg=aesgcm reason=ip_not_in_telegram_range ip={client_ip}");
        return error_response(StatusCode::FORBIDDEN);
    }

    let folded = fold_aesgcm_body(&encryption, &crypto_key, &body);

    call_correlator(&ctx.env, &endpoint, Method::Post, folded).await
}

/// PUT /<url-encoded-endpoint> — Simple Push (`token_type=4`) leg.
///
/// Same ordering rationale as `handle_aesgcm`: structural validation before
/// the one check that can trigger outbound traffic to Telegram.
async fn handle_put(mut req: Request, ctx: RouteContext<Context>) -> Result<Response> {
    let Some(client_ip_str) = get_client_ip(&req) else {
        console_log!("rejected: leg=put reason=missing_cf_connecting_ip");
        return error_response(StatusCode::FORBIDDEN);
    };
    let Ok(client_ip) = client_ip_str.parse::<std::net::IpAddr>() else {
        console_log!("rejected: leg=put reason=unparseable_cf_connecting_ip ip={client_ip_str}");
        return error_response(StatusCode::FORBIDDEN);
    };

    let path = req.path();
    let encoded = path.strip_prefix('/').unwrap_or(&path);
    let Ok(decoded) = percent_decode(encoded) else {
        console_log!("rejected: leg=put reason=invalid_percent_encoding ip={client_ip}");
        return error_response(StatusCode::FORBIDDEN);
    };

    let Ok(endpoint) = validate_endpoint(&decoded) else {
        console_log!("rejected: leg=put reason=invalid_endpoint ip={client_ip}");
        return error_response(StatusCode::FORBIDDEN);
    };

    let body = req.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        console_log!(
            "rejected: leg=put reason=payload_too_large ip={client_ip} host={} size={}",
            endpoint.host_str().unwrap_or("?"),
            body.len()
        );
        return error_response(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let kv = ctx.env.kv(CIDR_CACHE_KV_BINDING)?;
    if !is_telegram_ip(&kv, client_ip, &cidr_list_url(&ctx.env), &ctx.data).await {
        console_log!("rejected: leg=put reason=ip_not_in_telegram_range ip={client_ip}");
        return error_response(StatusCode::FORBIDDEN);
    }

    call_correlator(&ctx.env, &endpoint, Method::Put, body).await
}

/// The target endpoint URL travels url-encoded in the PUT path, so it needs
/// decoding before it's usable as a URL. Percent-decoded bytes that aren't
/// valid UTF-8 mean the path was malformed, not something to paper over —
/// reject it rather than substituting replacement characters and feeding
/// mangled input into URL parsing.
fn percent_decode(s: &str) -> Result<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|e| Error::RustError(format!("invalid percent-encoded UTF-8: {e}")))
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    // `ctx` rides as the router's per-request data (`RouteContext::data`) so
    // handlers can reach `ctx.wait_until` for the background CIDR re-fetch
    // backstop -- the router itself has no notion of the fetch event's
    // Context otherwise.
    Router::with_data(ctx).post_async("/aesgcm", handle_aesgcm).put_async("/*path", handle_put).run(req, env).await
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
    fn test_telegram_cidr_bootstrap_is_valid() {
        assert!(parse_cidr_list(TELEGRAM_CIDR_BOOTSTRAP).is_some(), "data/telegram-cidrs.txt must parse cleanly");
    }

    #[test]
    fn test_is_cidr_list_fresh_within_max_age() {
        assert!(is_cidr_list_fresh(1_000.0, 500.0, CIDR_LIST_MAX_AGE_MS));
    }

    #[test]
    fn test_is_cidr_list_fresh_outside_max_age() {
        let fetched_at = 1_000.0;
        let now = fetched_at + CIDR_LIST_MAX_AGE_MS + 1.0;
        assert!(!is_cidr_list_fresh(now, fetched_at, CIDR_LIST_MAX_AGE_MS));
    }

    #[test]
    fn test_is_cidr_list_fresh_within_force_refetch_max_age() {
        assert!(is_cidr_list_fresh(1_000.0, 500.0, CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS));
    }

    #[test]
    fn test_is_cidr_list_fresh_outside_force_refetch_max_age() {
        let fetched_at = 1_000.0;
        let now = fetched_at + CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS + 1.0;
        assert!(!is_cidr_list_fresh(now, fetched_at, CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS));
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

    #[test]
    fn test_is_ip_safe_public_ipv4() {
        let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert!(is_ip_safe(ip));

        let ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        assert!(is_ip_safe(ip));
    }

    #[test]
    fn test_is_ip_safe_private_ipv4() {
        assert!(!is_ip_safe("127.0.0.1".parse().unwrap())); // loopback
        assert!(!is_ip_safe("192.168.1.1".parse().unwrap())); // private
        assert!(!is_ip_safe("10.0.0.1".parse().unwrap())); // private
        assert!(!is_ip_safe("172.16.0.1".parse().unwrap())); // private
        assert!(!is_ip_safe("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(!is_ip_safe("192.0.2.1".parse().unwrap())); // TEST-NET
        assert!(!is_ip_safe("198.51.100.1".parse().unwrap())); // TEST-NET-2
        assert!(!is_ip_safe("203.0.113.1".parse().unwrap())); // TEST-NET-3
    }

    #[test]
    fn test_is_ip_safe_public_ipv6() {
        let ip: std::net::IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(is_ip_safe(ip));
    }

    #[test]
    fn test_is_ip_safe_private_ipv6() {
        assert!(!is_ip_safe("::1".parse().unwrap())); // loopback
        assert!(!is_ip_safe("fe80::1".parse().unwrap())); // link-local
        assert!(!is_ip_safe("fc00::1".parse().unwrap())); // ULA
        assert!(!is_ip_safe("::ffff:127.0.0.1".parse().unwrap())); // IPv4-mapped loopback
        assert!(!is_ip_safe("64:ff9b::1".parse().unwrap())); // NAT64
        assert!(!is_ip_safe("2001:db8::1".parse().unwrap())); // documentation
        assert!(!is_ip_safe("3fff::1".parse().unwrap())); // documentation
    }

    #[test]
    fn test_percent_decode() {
        let cases = [
            ("hello", "hello"),
            ("hello%20world", "hello world"),
            ("https%3A%2F%2Fexample.com", "https://example.com"),
            ("%2B%3D%26", "+=&"),
        ];
        for (input, expected) in cases {
            assert_eq!(percent_decode(input).unwrap(), expected, "input: {input}");
        }
    }

    #[test]
    fn test_percent_decode_invalid_hex_passes_through() {
        assert_eq!(percent_decode("%XY").unwrap(), "%XY");
        assert_eq!(percent_decode("%1G").unwrap(), "%1G");
    }

    #[test]
    fn test_percent_decode_rejects_invalid_utf8() {
        // %C3 alone is an incomplete 2-byte UTF-8 sequence.
        assert!(percent_decode("%C3").is_err());
    }

    #[test]
    fn test_fold_aesgcm_body_format() {
        let encryption = "salt=abc";
        let crypto_key = "dh=xyz";
        let body = b"ciphertext";

        let result = fold_aesgcm_body(encryption, crypto_key, body);
        let s = String::from_utf8_lossy(&result);

        assert!(s.starts_with("aesgcm\n"));
        assert!(s.contains("Encryption: salt=abc\n"));
        assert!(s.contains("Crypto-Key: dh=xyz\n"));
        assert!(s.ends_with("ciphertext"));
    }

    #[test]
    fn test_validate_endpoint_valid_http() {
        assert!(validate_endpoint("http://example.com").is_ok());
        assert!(validate_endpoint("https://example.com:8080").is_ok());
    }

    #[test]
    fn test_validate_endpoint_invalid_scheme() {
        assert!(validate_endpoint("ftp://example.com").is_err());
        assert!(validate_endpoint("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_endpoint_credentials() {
        assert!(validate_endpoint("http://user:pass@example.com").is_err());
    }

    #[test]
    fn test_validate_endpoint_literal_public_ip() {
        assert!(validate_endpoint("http://8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_endpoint_literal_private_ip() {
        assert!(validate_endpoint("http://127.0.0.1").is_err());
        assert!(validate_endpoint("http://192.168.1.1").is_err());
        assert!(validate_endpoint("http://10.0.0.1").is_err());
    }

    #[test]
    fn test_validate_endpoint_no_host() {
        assert!(validate_endpoint("http://").is_err());
    }
}
