#![warn(clippy::pedantic)]
// `use worker::*` is the crate's own idiom; naming every re-export individually
// buys nothing. This isn't a published library, so a per-fn `# Errors` section
// would be noise.
#![allow(clippy::wildcard_imports, clippy::missing_errors_doc)]
// SPDX-FileCopyrightText: 2026 Francis
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Web Push relay for a UnifiedPush distributor (e.g. Sunup, ntfy): folds the
// `Encryption`/`Crypto-Key` headers Telegram sends into the body, since
// UnifiedPush distributors strip headers. See src/correlator.rs for the
// wake-up correlation this depends on. No FCM/VAPID leg — only real
// UnifiedPush distributors are targeted.

mod correlator;

pub use correlator::Correlator;
use ipnetwork::IpNetwork;
use worker::*;

/// Real `WebPush` ciphertext is small; anything past this is treated as
/// abuse rather than buffered and forwarded. 16KB covers real Telegram
/// notifications with headroom; anything larger is likely garbage.
const MAX_BODY_BYTES: usize = 16_384;

/// Bootstrap Telegram CIDR list, embedded at build time from
/// data/telegram-cidrs.txt. Fetch fresh list on schedule; if that fails, fall
/// back to this.
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

/// Fetch fresh Telegram CIDR list from remote, or return cached version.
/// Parses and validates all entries before caching. Falls back to bootstrap if
/// both fail.
async fn get_telegram_cidr_list(kv: &KvStore) -> Result<String> {
    const KV_KEY: &str = "telegram_cidrs";
    const FETCH_URL: &str = "https://core.telegram.org/resources/cidr.txt";

    // Try fetching fresh and parsing
    if let Ok(mut resp) = Fetch::Url(FETCH_URL.parse().map_err(|_| Error::RustError("bad url".into()))?).send().await {
        if (200..300).contains(&resp.status_code()) {
            if let Ok(body) = resp.text().await {
                if let Some(parsed) = parse_cidr_list(&body) {
                    let _ = kv.put(KV_KEY, &parsed);
                    return Ok(parsed);
                }
            }
        }
    }

    // Fetch failed, try cache (already validated at storage time)
    if let Ok(Some(cached)) = kv.get(KV_KEY).text().await {
        return Ok(cached);
    }

    // Last resort: bootstrap (pre-validated at build time)
    Ok(TELEGRAM_CIDR_BOOTSTRAP.to_string())
}

/// Extract client IP from request, preferring CF-Connecting-IP header
/// (set by Cloudflare's edge) over other sources.
fn get_client_ip(req: &Request) -> Option<String> {
    req.headers().get("cf-connecting-ip").ok().flatten().or_else(|| req.headers().get("x-forwarded-for").ok().flatten())
}

/// Cached SSRF-prevention ranges not covered by Rust's built-in methods.
mod unsafe_ranges {
    use std::sync::LazyLock;

    use ipnetwork::IpNetwork;

    pub static UNSAFE_V4: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
        vec![
            "0.0.0.0/8".parse().unwrap(),     // This host
            "100.64.0.0/10".parse().unwrap(), // Shared address space (CGNAT)
            "198.18.0.0/15".parse().unwrap(), // Benchmarking
        ]
    });

    pub static UNSAFE_V6: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
        vec![
            "::/96".parse().unwrap(),          // IPv4-compatible
            "::ffff:0:0/96".parse().unwrap(),  // IPv4-mapped
            "64:ff9b::/96".parse().unwrap(),   // NAT64
            "64:ff9b:1::/48".parse().unwrap(), // NAT64/Well-known prefix
            "fc00::/7".parse().unwrap(),       // Unique local (ULA)
            "fe80::/10".parse().unwrap(),      // Link-local
        ]
    });
}

/// True if `ip` is a public, routable address. Uses Rust's built-in methods
/// for standard ranges (loopback, private, link-local, multicast,
/// documentation, broadcast, unspecified) plus cached ipnetwork ranges Rust
/// doesn't cover.
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
            // Use Rust's built-in methods for standard ranges
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
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
    let namespace = env.durable_object("CORRELATOR")?;
    let stub = namespace.id_from_name(endpoint.as_str())?.get_stub()?;

    let headers = Headers::new();
    headers.set("X-Relay-Target", endpoint.as_str())?;

    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers).with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));

    let req = Request::new_with_init("https://do/relay", &init)?;
    stub.fetch_with_request(req).await
}

/// POST /aesgcm?e=<url-encoded-endpoint>
async fn handle_aesgcm(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(client_ip_str) = get_client_ip(&req) else {
        return Response::error("Forbidden", 403);
    };
    let Ok(client_ip) = client_ip_str.parse::<std::net::IpAddr>() else {
        return Response::error("Forbidden", 403);
    };

    let kv = ctx.env.kv("CIDR_CACHE")?;
    let cidr_list = get_telegram_cidr_list(&kv).await?;
    if !is_telegram_ip_with_list(client_ip, &cidr_list) {
        return Response::error("Forbidden", 403);
    }

    let url = req.url()?;
    let endpoint_raw = match url.query_pairs().find(|(k, _)| k == "e") {
        Some((_, v)) => v.into_owned(),
        None => return Response::error("missing ?e= parameter", 400),
    };
    let Ok(endpoint) = validate_endpoint(&endpoint_raw) else {
        return Response::error("Forbidden", 403);
    };

    let encryption = req.headers().get("encryption")?.unwrap_or_default();
    let crypto_key = req.headers().get("crypto-key")?.unwrap_or_default();
    let body = req.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        return Response::error("Payload Too Large", 413);
    }
    let folded = fold_aesgcm_body(&encryption, &crypto_key, &body);

    call_correlator(&ctx.env, &endpoint, Method::Post, folded).await
}

/// PUT /<url-encoded-endpoint> — Simple Push (`token_type=4`) leg.
async fn handle_put(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(client_ip_str) = get_client_ip(&req) else {
        return Response::error("Forbidden", 403);
    };
    let Ok(client_ip) = client_ip_str.parse::<std::net::IpAddr>() else {
        return Response::error("Forbidden", 403);
    };

    let kv = ctx.env.kv("CIDR_CACHE")?;
    let cidr_list = get_telegram_cidr_list(&kv).await?;
    if !is_telegram_ip_with_list(client_ip, &cidr_list) {
        return Response::error("Forbidden", 403);
    }

    let path = req.path();
    let encoded = path.strip_prefix('/').unwrap_or(&path);
    let decoded = percent_decode(encoded);

    let Ok(endpoint) = validate_endpoint(&decoded) else {
        return Response::error("Forbidden", 403);
    };

    let body = req.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        return Response::error("Payload Too Large", 413);
    }
    call_correlator(&ctx.env, &endpoint, Method::Put, body).await
}

/// The target endpoint URL travels url-encoded in the PUT path, so it needs
/// decoding before it's usable as a URL.
fn percent_decode(s: &str) -> String {
    // Slices `s[i+1..i+3]` by byte offset would panic if that range lands
    // mid-character (e.g. `%` followed by a multibyte UTF-8 byte) — decode
    // the two hex digits from raw bytes instead, which has no such boundary
    // to violate.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                // hi, lo are each 0..=15, so hi * 16 + lo is 0..=255.
                #[allow(clippy::cast_possible_truncation)]
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    Router::new().post_async("/aesgcm", handle_aesgcm).put_async("/*path", handle_put).run(req, env).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cidr_line_ipv4_block() {
        assert!(validate_cidr_line("91.108.56.0/22"));
        assert!(validate_cidr_line("0.0.0.0/0"));
        assert!(validate_cidr_line("192.168.1.0/24"));
    }

    #[test]
    fn test_validate_cidr_line_ipv6_block() {
        assert!(validate_cidr_line("2001:b28:f23d::/48"));
        assert!(validate_cidr_line("::/0"));
        assert!(validate_cidr_line("fe80::/10"));
    }

    #[test]
    fn test_validate_cidr_line_plain_ip() {
        assert!(validate_cidr_line("1.2.3.4"));
        assert!(validate_cidr_line("2001:db8::1"));
    }

    #[test]
    fn test_validate_cidr_line_invalid() {
        assert!(!validate_cidr_line(""));
        assert!(!validate_cidr_line("not-an-ip"));
        assert!(!validate_cidr_line("1.2.3.4/33")); // IPv4 prefix too large
        assert!(!validate_cidr_line("2001:db8::/129")); // IPv6 prefix too large
        assert!(!validate_cidr_line("1.2.3.4/abc")); // Invalid prefix
    }

    #[test]
    fn test_parse_cidr_list_valid() {
        let list = "91.108.56.0/22\n91.108.4.0/22\n1.2.3.4";
        let result = parse_cidr_list(list);
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert!(parsed.contains("91.108.56.0/22"));
        assert!(parsed.contains("1.2.3.4"));
    }

    #[test]
    fn test_parse_cidr_list_skips_empty_lines() {
        let list = "91.108.56.0/22\n\n91.108.4.0/22";
        let result = parse_cidr_list(list);
        assert!(result.is_some());
        let parsed = result.unwrap();
        // Should have exactly 2 entries (empty line skipped)
        assert_eq!(parsed.lines().count(), 2);
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
    fn test_is_telegram_ip_with_list_ipv4() {
        let cidr_list = "91.108.56.0/22\n91.108.4.0/22\n149.154.160.0/20";
        let ip: std::net::IpAddr = "91.108.56.100".parse().unwrap();
        assert!(is_telegram_ip_with_list(ip, cidr_list));

        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!is_telegram_ip_with_list(ip, cidr_list));
    }

    #[test]
    fn test_is_telegram_ip_with_list_ipv6() {
        let cidr_list = "2001:b28:f23d::/48\n2001:67c:4e8::/48";
        let ip: std::net::IpAddr = "2001:b28:f23d::1".parse().unwrap();
        assert!(is_telegram_ip_with_list(ip, cidr_list));

        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_telegram_ip_with_list(ip, cidr_list));
    }

    #[test]
    fn test_is_telegram_ip_with_list_plain_ip() {
        let cidr_list = "1.2.3.4\n5.6.7.8/32";
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert!(is_telegram_ip_with_list(ip, cidr_list));

        let ip: std::net::IpAddr = "1.2.3.5".parse().unwrap();
        assert!(!is_telegram_ip_with_list(ip, cidr_list));
    }

    #[test]
    fn test_is_telegram_ip_with_list_mixed() {
        let cidr_list = "91.108.56.0/22\n1.2.3.4\n2001:b28:f23d::/48";
        let ip: std::net::IpAddr = "91.108.56.100".parse().unwrap();
        assert!(is_telegram_ip_with_list(ip, cidr_list));

        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert!(is_telegram_ip_with_list(ip, cidr_list));

        let ip: std::net::IpAddr = "2001:b28:f23d::1".parse().unwrap();
        assert!(is_telegram_ip_with_list(ip, cidr_list));
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
    }

    #[test]
    fn test_percent_decode_basic() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn test_percent_decode_url() {
        assert_eq!(percent_decode("https%3A%2F%2Fexample.com"), "https://example.com");
    }

    #[test]
    fn test_percent_decode_special_chars() {
        assert_eq!(percent_decode("%2B%3D%26"), "+=&");
    }

    #[test]
    fn test_percent_decode_invalid_hex() {
        // Invalid hex codes should pass through as-is
        assert_eq!(percent_decode("%XY"), "%XY");
        assert_eq!(percent_decode("%1G"), "%1G");
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
