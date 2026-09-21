#![warn(clippy::pedantic)]
// `use worker::*` is the crate's own idiom; naming every re-export individually
// buys nothing. This isn't a published library, so a per-fn `# Errors` section
// would be noise.
#![allow(clippy::wildcard_imports, clippy::missing_errors_doc)]
//
// Web Push rewrite proxy for a UnifiedPush distributor (e.g. Sunup, ntfy):
// folds the `Encryption`/`Crypto-Key` headers Telegram sends into the body,
// since UnifiedPush distributors strip headers. See src/correlator.rs for the
// wake-up correlation this depends on. No FCM/VAPID leg — only real
// UnifiedPush distributors are targeted.

mod clock;
mod correlator;
mod telegram_cidrs;

pub use correlator::Correlator;
use futures_util::StreamExt;
use http::StatusCode;
use telegram_cidrs::TelegramIpCheck;
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
}

/// Real `WebPush` ciphertext is small; anything past this is treated as
/// abuse rather than buffered and forwarded. 16KB covers real Telegram
/// notifications with headroom; anything larger is likely garbage.
const MAX_BODY_BYTES: usize = 16_384;

/// The request body, or `None` if it exceeds `MAX_BODY_BYTES`. A declared
/// `Content-Length` over the limit is refused without reading anything; the
/// read itself is also capped, so a chunked or under-declared body can't be
/// buffered past the limit either.
async fn read_capped_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    let declared_length =
        req.headers().get(http::header::CONTENT_LENGTH.as_str())?.and_then(|v| v.parse::<usize>().ok());
    if declared_length.is_some_and(|length| length > MAX_BODY_BYTES) {
        return Ok(None);
    }

    // No body stream means an empty body.
    let Ok(mut stream) = req.stream() else { return Ok(Some(Vec::new())) };
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

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

/// wrangler.toml `[[kv_namespaces]]` binding name for the CIDR list cache.
const CIDR_CACHE_KV_BINDING: &str = "CIDR_CACHE";
/// wrangler.toml `[durable_objects]` binding name for the Correlator.
const CORRELATOR_BINDING: &str = "CORRELATOR";

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

/// How long a client is told to wait before retrying when the CIDR cache
/// couldn't be read.
const CACHE_UNAVAILABLE_RETRY_AFTER_SECONDS: &str = "60";

/// `None` if `client_ip` is a Telegram IP, otherwise the response to send
/// instead of forwarding.
async fn reject_unless_telegram_ip(
    leg: &str, client_ip: std::net::IpAddr, ctx: &RouteContext<Context>,
) -> Result<Option<Response>> {
    let kv = ctx.env.kv(CIDR_CACHE_KV_BINDING)?;
    let fetch_url = telegram_cidrs::cidr_list_url(&ctx.env);
    match telegram_cidrs::is_telegram_ip(&kv, client_ip, &fetch_url, &ctx.data).await {
        TelegramIpCheck::Telegram => Ok(None),
        TelegramIpCheck::NotTelegram => {
            console_log!("rejected: leg={leg} reason=ip_not_in_telegram_range ip={client_ip}");
            error_response(StatusCode::FORBIDDEN).map(Some)
        }
        TelegramIpCheck::CacheUnavailable => {
            console_log!("rejected: leg={leg} reason=cidr_cache_unavailable ip={client_ip}");
            let mut response = error_response(StatusCode::SERVICE_UNAVAILABLE)?;
            response.headers_mut().set(http::header::RETRY_AFTER.as_str(), CACHE_UNAVAILABLE_RETRY_AFTER_SECONDS)?;
            Ok(Some(response))
        }
    }
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
    let Some(body) = read_capped_body(&mut req).await? else {
        console_log!(
            "rejected: leg=aesgcm reason=payload_too_large ip={client_ip} host={}",
            endpoint.host_str().unwrap_or("?")
        );
        return error_response(StatusCode::PAYLOAD_TOO_LARGE);
    };

    // Keep this last: an unrecognized IP can trigger a CIDR fetch, so only
    // otherwise-valid requests may reach it.
    if let Some(rejection) = reject_unless_telegram_ip("aesgcm", client_ip, &ctx).await? {
        return Ok(rejection);
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

    let Some(body) = read_capped_body(&mut req).await? else {
        console_log!(
            "rejected: leg=put reason=payload_too_large ip={client_ip} host={}",
            endpoint.host_str().unwrap_or("?")
        );
        return error_response(StatusCode::PAYLOAD_TOO_LARGE);
    };

    // Keep this last: an unrecognized IP can trigger a CIDR fetch, so only
    // otherwise-valid requests may reach it.
    if let Some(rejection) = reject_unless_telegram_ip("put", client_ip, &ctx).await? {
        return Ok(rejection);
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
