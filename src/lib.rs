#![warn(clippy::pedantic)]
// `use worker::*` is the crate's own idiom; naming every re-export individually
// buys nothing. This isn't a published library, so a per-fn `# Errors` section
// would be noise.
#![allow(clippy::wildcard_imports, clippy::missing_errors_doc)]
//
// Web Push rewrite proxy for a UnifiedPush distributor (e.g. Sunup, ntfy):
// folds the `Encryption`/`Crypto-Key` headers Telegram sends into the body,
// since UnifiedPush distributors strip headers. No FCM/VAPID leg — only real
// UnifiedPush distributors are targeted.

mod cidr_state;
mod clock;
mod correlator;
mod outbound;
mod telegram_cidrs;

use std::time::Duration;

use clock::Deadline;
pub use correlator::Correlator;
use futures_util::StreamExt;
use http::StatusCode;
use telegram_cidrs::{CidrAllowlist, TelegramIpCheck};
use thiserror::Error;
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
    /// Worker to the Correlator Durable Object.
    pub(crate) const X_RELAY_TARGET: HeaderName = HeaderName::from_static("x-relay-target");
    /// Internal header carrying how much of the request's time budget is left,
    /// in milliseconds, from the Worker to the Correlator Durable Object.
    pub(crate) const X_RELAY_BUDGET_MS: HeaderName = HeaderName::from_static("x-relay-budget-ms");
}

/// Real `WebPush` ciphertext is small; anything past this is treated as
/// abuse rather than buffered and forwarded.
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

/// Why a forwarding target was refused. Logged, never sent to the caller; the
/// messages double as the reason in that log line, so they stay short and free
/// of spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum EndpointRejection {
    /// The endpoint isn't a URL
    #[error("unparseable")]
    Unparseable,

    /// The scheme is neither http nor https
    #[error("unsupported_scheme")]
    UnsupportedScheme,

    /// The URL embeds credentials
    #[error("has_credentials")]
    HasCredentials,

    /// The URL has no host
    #[error("no_host")]
    NoHost,

    /// The host is a literal IP address that isn't public
    #[error("non_public_ip")]
    NonPublicIp,
}

/// Rejects anything that isn't a plain http(s) URL with a host and no
/// embedded credentials. Literal private/loopback IPs are rejected below;
/// a domain name that merely resolves to one is not caught, since Workers'
/// `fetch()` gives no hook into DNS resolution to check that at connect time.
fn validate_endpoint(raw: &str) -> std::result::Result<url::Url, EndpointRejection> {
    let parsed = url::Url::parse(raw).map_err(|_| EndpointRejection::Unparseable)?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(EndpointRejection::UnsupportedScheme);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(EndpointRejection::HasCredentials);
    }
    match parsed.host() {
        None => return Err(EndpointRejection::NoHost),
        Some(url::Host::Ipv4(ip)) if !is_ip_safe(std::net::IpAddr::V4(ip)) => {
            return Err(EndpointRejection::NonPublicIp);
        }
        Some(url::Host::Ipv6(ip)) if !is_ip_safe(std::net::IpAddr::V6(ip)) => {
            return Err(EndpointRejection::NonPublicIp);
        }
        _ => {}
    }
    Ok(parsed)
}

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

/// The wrangler var holding the most time, in milliseconds, a request may take
/// before it's answered, so Telegram isn't kept waiting on a slow push server
/// or CIDR refresh.
const REQUEST_BUDGET_MS_VAR: &str = "MAX_RESPONSE_MS";
/// The request budget when `REQUEST_BUDGET_MS_VAR` is unset or unusable.
pub(crate) const DEFAULT_REQUEST_BUDGET: Duration = Duration::from_secs(5);

/// How long a request may take: the `REQUEST_BUDGET_MS_VAR` var if it holds a
/// positive number of milliseconds, otherwise `DEFAULT_REQUEST_BUDGET`.
fn request_budget(env: &Env) -> Duration {
    let configured = env.var(REQUEST_BUDGET_MS_VAR).ok().map(|value| value.to_string());
    parse_request_budget(configured.as_deref()).unwrap_or_else(|| {
        if let Some(value) = configured {
            console_error!(
                "config: ignoring {REQUEST_BUDGET_MS_VAR}={value}, which isn't a positive number of milliseconds"
            );
        }
        DEFAULT_REQUEST_BUDGET
    })
}

/// `value` as a budget, if it is a positive number of milliseconds.
fn parse_request_budget(value: Option<&str>) -> Option<Duration> {
    value?.trim().parse::<u64>().ok().filter(|millis| *millis > 0).map(Duration::from_millis)
}

/// How long a client is told to wait before retrying when its IP couldn't be
/// verified.
const UNVERIFIABLE_RETRY_AFTER_SECONDS: &str = "60";

/// Which of the two routes a request came in on, for log lines only.
#[derive(Debug, Clone, Copy)]
enum Leg {
    Aesgcm,
    Put,
}

impl std::fmt::Display for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aesgcm => "aesgcm",
            Self::Put => "put",
        })
    }
}

/// `None` if `client_ip` is a Telegram IP, otherwise the response to send
/// instead of forwarding.
async fn reject_unless_telegram_ip(
    leg: Leg, client_ip: std::net::IpAddr, deadline: Deadline, ctx: &RouteContext<Context>,
) -> Result<Option<Response>> {
    match CidrAllowlist::new(&ctx.env)?.is_telegram_ip(client_ip, &ctx.data, deadline).await {
        TelegramIpCheck::Telegram => Ok(None),
        TelegramIpCheck::NotTelegram => {
            console_log!("rejected: leg={leg} reason=ip_not_in_telegram_range ip={client_ip}");
            error_response(StatusCode::FORBIDDEN).map(Some)
        }
        TelegramIpCheck::Unverifiable => {
            console_log!("rejected: leg={leg} reason=cannot_verify_ip ip={client_ip}");
            let mut response = error_response(StatusCode::SERVICE_UNAVAILABLE)?;
            response.headers_mut().set(http::header::RETRY_AFTER.as_str(), UNVERIFIABLE_RETRY_AFTER_SECONDS)?;
            Ok(Some(response))
        }
    }
}

/// SSRF-prevention ranges not covered by Rust's built-in methods, taken from
/// IANA's IPv4 and IPv6 Special-Purpose Address Registries
/// (<https://www.iana.org/assignments/iana-ipv4-special-registry/> and
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>): every
/// block those list as not globally reachable, plus ranges that embed an IPv4
/// address, which a translator could turn into a private one.
mod unsafe_ranges {
    use std::sync::LazyLock;

    use ipnetwork::IpNetwork;

    const UNSAFE_V4_CIDRS: &[&str] = &[
        "0.0.0.0/8",      // "This network", RFC 791 section 3.2
        "100.64.0.0/10",  // Shared address space (CGNAT), RFC 6598
        "192.0.0.0/24",   // IETF protocol assignments, RFC 6890 section 2.1
        "192.88.99.0/24", // Deprecated 6to4 relay anycast, RFC 7526
        "198.18.0.0/15",  // Benchmarking, RFC 2544
        "240.0.0.0/4",    // Reserved for future use, RFC 1112 section 4
    ];

    const UNSAFE_V6_CIDRS: &[&str] = &[
        "64:ff9b::/96",    // IPv4/IPv6 translation, RFC 6052 section 2.1 (embeds an IPv4 address)
        "64:ff9b:1::/48",  // Local-use IPv4/IPv6 translation, RFC 8215
        "100::/64",        // Discard-only, RFC 6666
        "100:0:0:1::/64",  // Dummy IPv6 prefix, RFC 9780
        "2001::/23",       // IETF protocol assignments, RFC 2928; includes Teredo (RFC 4380)
        "2001:db8::/32",   // Documentation, RFC 3849
        "2002::/16",       // 6to4, RFC 3056 section 2 (embeds an IPv4 address); deprecated by RFC 7526
        "3fff::/20",       // Documentation, RFC 9637
        "fec0::/10",       // Site-local, deprecated by RFC 3879
        "::ffff:0:0:0/96", // IPv4-translated addresses (SIIT), RFC 2765 section 2.1 (embeds an IPv4 address)
    ];

    /// The networks the given CIDR literals denote.
    fn parse_all(cidrs: &[&str]) -> Vec<IpNetwork> {
        cidrs.iter().map(|cidr| cidr.parse().expect("hardcoded CIDR literal must be valid")).collect()
    }

    pub static UNSAFE_V4: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| parse_all(UNSAFE_V4_CIDRS));
    pub static UNSAFE_V6: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| parse_all(UNSAFE_V6_CIDRS));
}

/// True if `ip` is a public, routable address. Uses Rust's built-in methods
/// for the ranges they cover (loopback, private, link-local, multicast,
/// documentation, broadcast, unspecified, unique-local, IPv4-mapped) plus the
/// ranges in `unsafe_ranges`.
fn is_ip_safe(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
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
            !unsafe_ranges::UNSAFE_V4.iter().any(|net| net.contains(ip))
        }
        std::net::IpAddr::V6(v6) => {
            // to_ipv4() matches both IPv4-compatible (::/96) and IPv4-mapped
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
    [b"aesgcm\nEncryption: ", encryption.as_bytes(), b"\nCrypto-Key: ", crypto_key.as_bytes(), b"\n", body].concat()
}

/// `value` if it can be folded into the body: aesgcm (draft-ietf-webpush-
/// encryption-04) needs both the `Encryption` header (the salt) and the
/// `Crypto-Key` header (the sender's key) to decrypt, so a missing or empty
/// one makes the notification undecryptable. A value with a control
/// character is refused too, since the folded body is line-based and it could
/// add lines of its own.
fn folding_header_value(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty() && !v.chars().any(char::is_control))
}

/// Look up the endpoint's Correlator instance and hand it a pre-shaped
/// internal request: `X-Relay-Target` carries the validated endpoint,
/// `X-Relay-Budget-Ms` how much of the request's time is left, the method
/// (POST/PUT) tells the Durable Object which branch to run, and the body is
/// whatever that branch should forward if it decides to.
async fn call_correlator(
    env: &Env, endpoint: &url::Url, method: Method, body: Vec<u8>, deadline: Deadline,
) -> Result<Response> {
    let namespace = env.durable_object(CORRELATOR_BINDING)?;
    let stub = namespace.id_from_name(endpoint.as_str())?.get_stub()?;

    let headers = Headers::new();
    headers.set(header_names::X_RELAY_TARGET.as_str(), endpoint.as_str())?;
    headers.set(header_names::X_RELAY_BUDGET_MS.as_str(), &deadline.remaining().as_millis().to_string())?;

    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers).with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));

    let req = Request::new_with_init("https://do/relay", &init)?;
    match stub.fetch_with_request(req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            console_error!("correlator_call: outcome=failed error={e}");
            error_response(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// POST /aesgcm?e=<url-encoded-endpoint>
///
/// Structural validation (the `?e=` param, the target endpoint, the aesgcm
/// headers, body size) runs before the Telegram-IP check: those are free,
/// local checks, and a malformed request from an unrecognized IP shouldn't
/// get to spend a CIDR-list fetch. Only a request that's otherwise
/// well-formed enough to forward reaches the one check that can trigger
/// outbound traffic to Telegram.
async fn handle_aesgcm(mut req: Request, ctx: RouteContext<Context>) -> Result<Response> {
    let deadline = Deadline::after(request_budget(&ctx.env));
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
    let endpoint = match validate_endpoint(&endpoint_raw) {
        Ok(endpoint) => endpoint,
        Err(rejection) => {
            console_log!("rejected: leg=aesgcm reason=invalid_endpoint detail={rejection} ip={client_ip}");
            return error_response(StatusCode::FORBIDDEN);
        }
    };

    let (Some(encryption), Some(crypto_key)) = (
        folding_header_value(req.headers().get(header_names::ENCRYPTION.as_str())?),
        folding_header_value(req.headers().get(header_names::CRYPTO_KEY.as_str())?),
    ) else {
        console_log!("rejected: leg=aesgcm reason=missing_or_invalid_encryption_headers ip={client_ip}");
        return error_response(StatusCode::BAD_REQUEST);
    };
    let Some(body) = read_capped_body(&mut req).await? else {
        console_log!(
            "rejected: leg=aesgcm reason=payload_too_large ip={client_ip} host={}",
            endpoint.host_str().unwrap_or("?")
        );
        return error_response(StatusCode::PAYLOAD_TOO_LARGE);
    };

    // Keep this last: an unrecognized IP can trigger a CIDR fetch, so only
    // otherwise-valid requests may reach it.
    if let Some(rejection) = reject_unless_telegram_ip(Leg::Aesgcm, client_ip, deadline, &ctx).await? {
        return Ok(rejection);
    }

    let folded = fold_aesgcm_body(&encryption, &crypto_key, &body);

    call_correlator(&ctx.env, &endpoint, Method::Post, folded, deadline).await
}

/// PUT /<url-encoded-endpoint> — Simple Push (`token_type=4`) leg.
///
/// Same ordering rationale as `handle_aesgcm`: structural validation before
/// the one check that can trigger outbound traffic to Telegram.
async fn handle_put(mut req: Request, ctx: RouteContext<Context>) -> Result<Response> {
    let deadline = Deadline::after(request_budget(&ctx.env));
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
    let Some(decoded) = percent_decode(encoded) else {
        console_log!("rejected: leg=put reason=invalid_percent_encoding ip={client_ip}");
        return error_response(StatusCode::FORBIDDEN);
    };

    let endpoint = match validate_endpoint(&decoded) {
        Ok(endpoint) => endpoint,
        Err(rejection) => {
            console_log!("rejected: leg=put reason=invalid_endpoint detail={rejection} ip={client_ip}");
            return error_response(StatusCode::FORBIDDEN);
        }
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
    if let Some(rejection) = reject_unless_telegram_ip(Leg::Put, client_ip, deadline, &ctx).await? {
        return Ok(rejection);
    }

    call_correlator(&ctx.env, &endpoint, Method::Put, body, deadline).await
}

/// The target endpoint URL travels url-encoded in the PUT path, so it needs
/// decoding before it's usable as a URL. Percent-decoded bytes that aren't
/// valid UTF-8 mean the path was malformed, not something to paper over —
/// reject it rather than substituting replacement characters and feeding
/// mangled input into URL parsing.
fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s).decode_utf8().ok().map(std::borrow::Cow::into_owned)
}

/// The Worker's fetch entry point: routes Telegram's POST and PUT requests.
#[event(fetch)]
pub async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    // `ctx` rides as the router's per-request data (`RouteContext::data`) so
    // handlers can reach `ctx.wait_until` for CIDR list refreshes -- the router
    // itself has no notion of the fetch event's Context otherwise.
    Router::with_data(ctx).post_async("/aesgcm", handle_aesgcm).put_async("/*path", handle_put).run(req, env).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_safe_public_addresses() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "192.0.1.1", // just outside 192.0.0.0/24
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2001:200::1", // just outside 2001::/23
        ] {
            assert!(is_ip_safe(ip.parse().expect("test address literal must parse")), "ip: {ip}");
        }
    }

    #[test]
    fn test_is_ip_safe_rejects_non_public_ipv4() {
        for ip in [
            "0.0.0.1",         // "this network"
            "10.0.0.1",        // private
            "100.64.0.1",      // CGNAT
            "127.0.0.1",       // loopback
            "169.254.169.254", // link-local
            "172.16.0.1",      // private
            "192.0.0.192",     // IETF protocol assignments
            "192.0.2.1",       // TEST-NET-1
            "192.88.99.1",     // deprecated 6to4 relay anycast
            "192.168.1.1",     // private
            "198.18.0.1",      // benchmarking
            "198.51.100.1",    // TEST-NET-2
            "203.0.113.1",     // TEST-NET-3
            "224.0.0.1",       // multicast
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ] {
            assert!(!is_ip_safe(ip.parse().expect("test address literal must parse")), "ip: {ip}");
        }
    }

    #[test]
    fn test_is_ip_safe_rejects_non_public_ipv6() {
        for ip in [
            "::1",              // loopback
            "::",               // unspecified
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:0:7f00:1",  // IPv4-translated loopback
            "64:ff9b::7f00:1",  // NAT64 of 127.0.0.1
            "64:ff9b:1::1",     // local-use translation
            "100::1",           // discard-only
            "100:0:0:1::1",     // dummy prefix
            "2001::1",          // Teredo
            "2001:db8::1",      // documentation
            "2002:7f00:1::",    // 6to4 of 127.0.0.1
            "3fff::1",          // documentation
            "fc00::1",          // unique-local
            "fe80::1",          // link-local
            "fec0::1",          // deprecated site-local
            "ff02::1",          // multicast
        ] {
            assert!(!is_ip_safe(ip.parse().expect("test address literal must parse")), "ip: {ip}");
        }
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
            assert_eq!(percent_decode(input).expect("test input must decode"), expected, "input: {input}");
        }
    }

    #[test]
    fn test_percent_decode_invalid_hex_passes_through() {
        assert_eq!(percent_decode("%XY").expect("invalid hex is passed through"), "%XY");
        assert_eq!(percent_decode("%1G").expect("invalid hex is passed through"), "%1G");
    }

    #[test]
    fn test_percent_decode_rejects_invalid_utf8() {
        // %C3 alone is an incomplete 2-byte UTF-8 sequence.
        assert!(percent_decode("%C3").is_none());
    }

    #[test]
    fn test_fold_aesgcm_body_format() {
        let encryption = "salt=abc";
        let crypto_key = "dh=xyz";
        let body = b"ciphertext";

        assert_eq!(
            fold_aesgcm_body(encryption, crypto_key, body),
            b"aesgcm\nEncryption: salt=abc\nCrypto-Key: dh=xyz\nciphertext"
        );
    }

    #[test]
    fn test_parse_request_budget() {
        assert_eq!(parse_request_budget(Some("2500")), Some(Duration::from_millis(2500)));
        assert_eq!(parse_request_budget(Some(" 5000 ")), Some(Duration::from_millis(5000)));
        for unusable in [None, Some(""), Some("0"), Some("-1"), Some("5s"), Some("2.5")] {
            assert_eq!(parse_request_budget(unusable), None, "value: {unusable:?}");
        }
    }

    #[test]
    fn test_folding_header_value() {
        let cases = [
            (Some("salt=abc"), true),
            (Some("dh=xyz; p256ecdsa=abc"), true),
            (None, false),
            (Some(""), false),
            (Some("salt=abc\nCrypto-Key: dh=evil"), false), // would add a line to the folded body
            (Some("salt=abc\r"), false),
            (Some("salt=\u{0}abc"), false),
        ];
        for (input, expected) in cases {
            assert_eq!(folding_header_value(input.map(String::from)).is_some(), expected, "input: {input:?}");
        }
    }

    #[test]
    fn test_validate_endpoint_accepts_public_hosts_and_literal_ips() {
        for endpoint in ["http://example.com", "https://example.com:8080", "http://8.8.8.8"] {
            assert!(validate_endpoint(endpoint).is_ok(), "endpoint: {endpoint}");
        }
    }

    #[test]
    fn test_validate_endpoint_rejection_reasons() {
        let cases = [
            ("not a url", EndpointRejection::Unparseable),
            ("http://", EndpointRejection::Unparseable), // an empty host
            ("ftp://example.com", EndpointRejection::UnsupportedScheme),
            ("file:///etc/passwd", EndpointRejection::UnsupportedScheme),
            ("http://user:pass@example.com", EndpointRejection::HasCredentials),
            ("http://127.0.0.1", EndpointRejection::NonPublicIp),
            ("http://[::1]", EndpointRejection::NonPublicIp),
            // The url crate normalises these alternative notations of 127.0.0.1
            // (and 0.0.0.0) to a literal IPv4 host, which is then refused.
            ("http://2130706433/", EndpointRejection::NonPublicIp), // decimal
            ("http://0x7f.1/", EndpointRejection::NonPublicIp),     // hex with short form
            ("http://0177.0.0.1/", EndpointRejection::NonPublicIp), // octal
            ("http://127.1/", EndpointRejection::NonPublicIp),      // short form
            ("http://127.0.0.1./", EndpointRejection::NonPublicIp), // trailing dot
            ("http://[::ffff:127.0.0.1]/", EndpointRejection::NonPublicIp), // IPv4-mapped
            ("http://0/", EndpointRejection::NonPublicIp),
        ];
        for (endpoint, expected) in cases {
            assert_eq!(
                validate_endpoint(endpoint).expect_err("the endpoint is refused"),
                expected,
                "endpoint: {endpoint}"
            );
        }
    }
}
