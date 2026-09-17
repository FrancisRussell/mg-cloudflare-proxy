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
// done automatically below). Gated behind the integration-tests feature
// (see Cargo.toml's required-features on this target) so a plain
// `cargo test` doesn't even attempt to build or run it.
// Run with: cargo test --features integration-tests --test integration
//
// Unix-only: process groups and the process-group kill below aren't
// portable. On other platforms this compiles to an empty, harmless test
// binary rather than failing to build.
#![cfg(unix)]

use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::StatusCode;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tiny_http::Response;

const PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");
const READY_TIMEOUT: Duration = Duration::from_secs(45);
/// Per-request timeout for every HTTP call this test makes. Without this,
/// ureq blocks with no timeout at all -- a single hung request (e.g. the
/// worker's own outbound fetch never returning) would hang the whole test
/// indefinitely instead of failing with a clear error.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often `wait_until_ready()` and Drop's reap loop poll.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long Drop waits for the killed process to actually be reaped before
/// giving up (it's already dead at this point; this is just avoiding a
/// zombie, not waiting for anything uncertain).
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// A Telegram IP from data/telegram-cidrs.txt's bootstrap list.
const TELEGRAM_IP: &str = "91.108.56.1";

/// PGID of the currently-running `wrangler dev` process group, or 0 if none.
/// Shared with the SIGINT handler installed in `integration_test`: a signal
/// terminates the process without unwinding, so `Drop for WranglerDev` never
/// runs on Ctrl+C -- without this, an interrupted run leaks the whole
/// wrangler/node/workerd tree.
static WRANGLER_PGID: AtomicU32 = AtomicU32::new(0);

/// Kills whatever process group `WRANGLER_PGID` currently names, if any.
/// Shared between the normal `Drop` path and the SIGINT handler so there's
/// one definition of "how to tear down the tree" instead of two.
fn kill_wrangler_process_group() {
    let pgid = WRANGLER_PGID.swap(0, Ordering::SeqCst);
    if pgid != 0 {
        // A negative PID targets the whole process group, per kill(2).
        // pgid fits in i32: it's a real PID, which the OS caps well under
        // i32::MAX.
        #[allow(clippy::cast_possible_wrap)]
        let group = Pid::from_raw(-(pgid as i32));
        if let Err(e) = signal::kill(group, Signal::SIGKILL) {
            eprintln!("warning: failed to kill wrangler dev process group {pgid}: {e}");
        }
    }
}

/// Installs a SIGINT handler that tears down the process tree before
/// exiting, so interrupting a hung/slow test (e.g. during the readiness
/// wait) doesn't leak it. Must be called at most once per process (the
/// underlying `ctrlc::set_handler` errors on a second call); the single
/// `#[test] fn integration_test` here is the only caller.
fn install_sigint_cleanup() {
    ctrlc::set_handler(|| {
        kill_wrangler_process_group();
        std::process::exit(130); // 128 + SIGINT, the conventional Ctrl+C exit
                                 // code
    })
    .expect("failed to install SIGINT handler");
}

/// Asks the OS for a free port rather than using a fixed one: a fixed port
/// means racing a previous run's leftover process for it (and needing to
/// clean that up), where a fresh one from the OS just doesn't collide.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().unwrap().port()
}

/// Manages a `wrangler dev` child process covering the whole test run:
/// rebuilds the worker, starts it, and waits until it responds to requests.
/// The whole process tree is killed on drop.
struct WranglerDev {
    child: Child,
    port: u16,
}

impl WranglerDev {
    fn start() -> Self {
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

        let port = pick_free_port();
        let child = Command::new("npx")
            .args(["wrangler", "dev", "--port", &port.to_string()])
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
        // process_group(0) makes the child's PGID equal its own PID.
        WRANGLER_PGID.store(child.id(), Ordering::SeqCst);

        let mut dev = Self { child, port };
        dev.wait_until_ready();
        dev
    }

    /// Polls the worker until it answers an HTTP request at all -- any
    /// status counts, we're only checking the local server is up. Also
    /// checks the child hasn't already exited, so a process that dies
    /// immediately (e.g. `npx` failing outright) fails fast with its exit
    /// status instead of burning the full timeout on a dead process and
    /// reporting a misleading "never became ready".
    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Ok(Some(exit_status)) = self.child.try_wait() {
                panic!("wrangler dev exited early with {exit_status}");
            }
            let result = ureq::get(&worker_url(self.port, "/")).timeout(REQUEST_TIMEOUT).call();
            if matches!(result, Ok(_) | Err(ureq::Error::Status(_, _))) {
                return;
            }
            assert!(Instant::now() < deadline, "wrangler dev did not become ready within {READY_TIMEOUT:?}");
            std::thread::sleep(POLL_INTERVAL);
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
        // later one. Shared with the SIGINT handler (see WRANGLER_PGID) so
        // there's one definition of "how to tear down the tree".
        kill_wrangler_process_group();

        // Don't block indefinitely on wait(): the group kill above has
        // proven reliable across repeated runs, so this is just letting the
        // now-dead process get reaped rather than leaving a zombie, bounded
        // in case it's slow.
        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(REAP_POLL_INTERVAL);
        }
    }
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
    /// gets a redirect pointing there instead of a plain 200 -- for testing
    /// that the relay won't follow a distributor's attempt to redirect it
    /// somewhere its SSRF check on the original URL never validated.
    ///
    /// Its background thread and `tiny_http::Server` are never explicitly
    /// torn down -- harmless today since there's a single `#[test] fn` and
    /// the whole process exits right after, but if this file ever grows a
    /// second `#[test] fn` (which `cargo test` runs concurrently, as
    /// separate threads within one shared process by default), every
    /// `MockDistributor` from every test would then leak for the remainder
    /// of the whole `cargo test` run rather than being scoped to just one.
    fn start(redirect_to: Option<&'static str>) -> Self {
        let port = pick_free_port();
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

                let status = if redirect_to.is_some() { StatusCode::FOUND } else { StatusCode::OK };
                let response = Response::from_string("").with_status_code(status.as_u16());
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

fn worker_url(port: u16, path: &str) -> String { format!("http://127.0.0.1:{port}{path}") }

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
fn integration_test() {
    install_sigint_cleanup();

    let dev = WranglerDev::start();
    let port = dev.port;

    rejects_missing_cf_connecting_ip(port);
    rejects_non_telegram_ip(port);
    rejects_literal_private_ip_target(port);
    forwards_put_to_valid_target(port);
    rejects_redirecting_distributor(port);
    post_suppresses_following_put(port);
}

fn rejects_missing_cf_connecting_ip(port: u16) {
    let resp = ureq::put(&worker_url(port, &format!("/{}", encode("http://example.com/"))))
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "PUT with no CF-Connecting-IP should be rejected");
}

fn rejects_non_telegram_ip(port: u16) {
    let resp = ureq::put(&worker_url(port, &format!("/{}", encode("http://example.com/"))))
        .set("CF-Connecting-IP", "8.8.8.8")
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "PUT from a non-Telegram IP should be rejected");
}

fn rejects_literal_private_ip_target(port: u16) {
    let resp = ureq::put(&worker_url(port, &format!("/{}", encode("http://127.0.0.1:9/"))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "a literal loopback IP as the target should be rejected");
}

fn forwards_put_to_valid_target(port: u16) {
    let distributor = MockDistributor::start(None);

    let resp = ureq::put(&worker_url(port, &format!("/{}", encode(&distributor.url()))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("wake-up-body");

    assert_eq!(status_of(resp), 201, "a valid forward should succeed");
    assert_eq!(distributor.request_count(), 1, "the mock distributor should have received exactly one request");
    assert_eq!(distributor.last_body(), b"wake-up-body");
}

fn rejects_redirecting_distributor(port: u16) {
    let distributor = MockDistributor::start(Some("http://127.0.0.1:1/somewhere-unvalidated"));

    let resp = ureq::put(&worker_url(port, &format!("/{}", encode(&distributor.url()))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");

    assert_eq!(status_of(resp), 502, "a distributor that tries to redirect us should be rejected, not followed");
    assert_eq!(
        distributor.request_count(),
        1,
        "the relay should have actually dialed the distributor and seen its 302"
    );
}

fn post_suppresses_following_put(port: u16) {
    let distributor = MockDistributor::start(None);
    let target = encode(&distributor.url());

    let post_resp = ureq::post(&worker_url(port, &format!("/aesgcm?e={target}")))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .set("Encryption", "salt=abc")
        .set("Crypto-Key", "dh=xyz")
        .timeout(REQUEST_TIMEOUT)
        .send_string("ciphertext");
    assert_eq!(status_of(post_resp), 201, "the POST leg should forward successfully");

    let put_resp = ureq::put(&worker_url(port, &format!("/{target}")))
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
