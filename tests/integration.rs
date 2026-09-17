// SPDX-FileCopyrightText: 2026 Francis
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Exercises the real worker::* code paths unit tests can't reach: header
// reading, KV, Durable Object correlation, and real outbound fetch()es.
// Runs the actual compiled Worker under `wrangler dev` (Miniflare, with KV
// and Durable Objects fully emulated locally) and drives it with real HTTP
// requests against a mock UnifiedPush distributor.
//
// Requires Node/npm (for `npx wrangler`) and cargo (to install worker-build,
// done automatically below) -- ignored by default.
// Run with: cargo test --test integration -- --ignored

use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");
const WORKER_PORT: u16 = 18787;
const READY_TIMEOUT: Duration = Duration::from_secs(45);
/// Per-request timeout for every HTTP call this test makes. Without this,
/// ureq blocks with no timeout at all -- a single hung request (e.g. the
/// worker's own outbound fetch never returning) would hang the whole test
/// indefinitely instead of failing with a clear error.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A Telegram IP from data/telegram-cidrs.txt's bootstrap list.
const TELEGRAM_IP: &str = "91.108.56.1";

/// Manages a `wrangler dev` child process covering the whole test run:
/// rebuilds the worker, starts it, and waits until it responds to requests.
/// Killed on drop; the port is also force-freed since workerd/esbuild
/// children can outlive the parent being killed.
struct WranglerDev {
    child: Child,
}

impl WranglerDev {
    fn start() -> Self {
        free_port(WORKER_PORT);

        // Matches wrangler.toml's own [build] command: install (a no-op if
        // already present) rather than requiring a separate manual step.
        let status = Command::new("cargo")
            .args(["install", "-q", "worker-build"])
            .status()
            .expect("failed to run `cargo install worker-build` (is cargo installed?)");
        assert!(status.success(), "cargo install worker-build failed");

        let status = Command::new("worker-build")
            .arg("--release")
            .current_dir(PROJECT_DIR)
            .status()
            .expect("failed to run worker-build");
        assert!(status.success(), "worker-build failed");

        let child = Command::new("npx")
            .args(["wrangler", "dev", "--port", &WORKER_PORT.to_string()])
            .current_dir(PROJECT_DIR)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Its own process group, so the whole tree (node, workerd,
            // esbuild -- which land on their own ports, e.g. an inspector
            // port) can be killed together on Drop instead of leaving
            // orphans that accumulate and slow down every later run.
            .process_group(0)
            .spawn()
            .expect("failed to spawn `npx wrangler dev` (is Node/npm installed?)");

        let dev = Self { child };
        Self::wait_until_ready();
        dev
    }

    /// Polls the worker until it answers an HTTP request at all -- any
    /// status counts, we're only checking the local server is up.
    fn wait_until_ready() {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let result = ureq::get(&worker_url("/")).timeout(REQUEST_TIMEOUT).call();
            if matches!(result, Ok(_) | Err(ureq::Error::Status(_, _))) {
                return;
            }
            assert!(Instant::now() < deadline, "wrangler dev did not become ready within {READY_TIMEOUT:?}");
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for WranglerDev {
    fn drop(&mut self) {
        // Kill the whole process group (negative PID), not just the tracked
        // child: with process_group(0) its PID doubles as the group ID, and
        // killing only the tracked child (a thin npx/sh -c wrapper) leaves
        // its node/workerd descendants running -- confirmed by orphaned
        // workerd processes piling up across runs and slowing down every
        // later one.
        let pgid = self.child.id();
        let _ = Command::new("kill").args(["-9", "--", &format!("-{pgid}")]).status();

        // Don't block indefinitely on wait(): bound it, then fall back to
        // free_port() regardless, since that kills by socket rather than by
        // PID and so isn't fooled by anything the process-group kill missed.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        free_port(WORKER_PORT);
    }
}

/// Best-effort: kill whatever's bound to `port`. wrangler dev's workerd/
/// esbuild children can outlive the `npx wrangler` parent process being
/// killed, so this also guards against a leftover process from a previous
/// crashed test run blocking this one from starting.
fn free_port(port: u16) {
    let _ = Command::new("fuser").args(["-k", &format!("{port}/tcp")]).status();
    std::thread::sleep(Duration::from_millis(500));
}

/// A minimal HTTP server standing in for a `UnifiedPush` distributor,
/// recording what it receives instead of doing anything with it.
struct MockDistributor {
    port: u16,
    request_count: Arc<AtomicUsize>,
    last_body: Arc<Mutex<Option<Vec<u8>>>>,
}

impl MockDistributor {
    /// Starts a mock distributor. If `redirect_to` is set, every request
    /// gets a 302 pointing there instead of a 200 -- for testing that the
    /// relay won't follow a distributor's attempt to redirect it somewhere
    /// its SSRF check on the original URL never validated.
    fn start(redirect_to: Option<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
        let port = listener.local_addr().unwrap().port();
        drop(listener); // just needed a free port; tiny_http binds its own

        let server = tiny_http::Server::http(("127.0.0.1", port)).expect("failed to start mock distributor");
        let request_count = Arc::new(AtomicUsize::new(0));
        let last_body = Arc::new(Mutex::new(None));

        let count = Arc::clone(&request_count);
        let body_store = Arc::clone(&last_body);
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                count.fetch_add(1, Ordering::SeqCst);
                let mut body = Vec::new();
                let _ = request.as_reader().read_to_end(&mut body);
                *body_store.lock().unwrap() = Some(body);

                let response =
                    Response::from_string("").with_status_code(if redirect_to.is_some() { 302 } else { 200 });
                let response = match redirect_to {
                    Some(location) => response
                        .with_header(tiny_http::Header::from_bytes(&b"Location"[..], location.as_bytes()).unwrap()),
                    None => response,
                };
                let _ = request.respond(response);
            }
        });

        Self { port, request_count, last_body }
    }

    /// This must be a hostname, not a literal IP: the relay's SSRF check
    /// (`validate_endpoint`/`is_ip_safe`) rejects literal loopback IPs like
    /// 127.0.0.1 outright, but only checks literal IPs -- a hostname like
    /// "localhost" passes that check untouched (the documented DNS-rebinding
    /// gap), and under wrangler dev's local execution "localhost" really
    /// does reach this same machine, unlike in production Cloudflare Workers.
    fn url(&self) -> String { format!("http://localhost:{}/distributor", self.port) }

    fn request_count(&self) -> usize { self.request_count.load(Ordering::SeqCst) }

    fn last_body(&self) -> Vec<u8> { self.last_body.lock().unwrap().clone().expect("distributor received no request") }
}

use tiny_http::Response;

fn worker_url(path: &str) -> String { format!("http://127.0.0.1:{WORKER_PORT}{path}") }

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn status_of(result: Result<ureq::Response, ureq::Error>) -> u16 {
    match result {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("request failed: {e}"),
    }
}

#[test]
#[ignore = "requires Node/npm; run with `cargo test --test integration -- --ignored`"]
fn integration_test() {
    let _dev = WranglerDev::start();

    rejects_missing_cf_connecting_ip();
    rejects_non_telegram_ip();
    rejects_literal_private_ip_target();
    forwards_put_to_valid_target();
    rejects_redirecting_distributor();
    post_suppresses_following_put();
}

fn rejects_missing_cf_connecting_ip() {
    let resp = ureq::put(&worker_url(&format!("/{}", encode("http://example.com/"))))
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "PUT with no CF-Connecting-IP should be rejected");
}

fn rejects_non_telegram_ip() {
    let resp = ureq::put(&worker_url(&format!("/{}", encode("http://example.com/"))))
        .set("CF-Connecting-IP", "8.8.8.8")
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "PUT from a non-Telegram IP should be rejected");
}

fn rejects_literal_private_ip_target() {
    let resp = ureq::put(&worker_url(&format!("/{}", encode("http://127.0.0.1:9/"))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "a literal loopback IP as the target should be rejected");
}

fn forwards_put_to_valid_target() {
    let distributor = MockDistributor::start(None);

    let resp = ureq::put(&worker_url(&format!("/{}", encode(&distributor.url()))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("wake-up-body");

    assert_eq!(status_of(resp), 201, "a valid forward should succeed");
    assert_eq!(distributor.request_count(), 1, "the mock distributor should have received exactly one request");
    assert_eq!(distributor.last_body(), b"wake-up-body");
}

fn rejects_redirecting_distributor() {
    let distributor = MockDistributor::start(Some("http://127.0.0.1:1/somewhere-unvalidated"));

    let resp = ureq::put(&worker_url(&format!("/{}", encode(&distributor.url()))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");

    assert_eq!(status_of(resp), 502, "a distributor that tries to redirect us should be rejected, not followed");
}

fn post_suppresses_following_put() {
    let distributor = MockDistributor::start(None);
    let target = encode(&distributor.url());

    let post_resp = ureq::post(&worker_url(&format!("/aesgcm?e={target}")))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .set("Encryption", "salt=abc")
        .set("Crypto-Key", "dh=xyz")
        .timeout(REQUEST_TIMEOUT)
        .send_string("ciphertext");
    assert_eq!(status_of(post_resp), 201, "the POST leg should forward successfully");

    let put_resp = ureq::put(&worker_url(&format!("/{target}")))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("wake-up-body");
    assert_eq!(status_of(put_resp), 200, "the PUT leg should be suppressed as a duplicate of the POST");

    assert_eq!(
        distributor.request_count(),
        1,
        "only the POST's content should reach the distributor, not a duplicate wake-up"
    );
}
