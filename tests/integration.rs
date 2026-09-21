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

use std::io::Read;
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

/// The compiled-in bootstrap list, for building the mock CIDR server's
/// response: it must be a superset of this (not just the two mock IPs
/// appended below), since a successful fetch replaces whatever's cached
/// entirely -- other scenarios in this same `wrangler dev` run still need
/// `TELEGRAM_IP` to resolve after `fetches_cidr_list_only_for_unrecognized_ip`
/// has already cached a fetched list.
const TELEGRAM_CIDR_BOOTSTRAP: &str = include_str!("../data/telegram-cidrs.txt");

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
    /// Captured stdout+stderr, printed only if the test panics (see Drop) --
    /// `cargo test`'s own output capturing doesn't reach a child process's
    /// inherited file descriptors, only the test's own print!/println!
    /// calls, so quiet-on-success has to be done ourselves.
    output: Arc<Mutex<Vec<u8>>>,
    /// Local KV/DO state directory (`--persist-to`), unique per run and
    /// removed on drop -- wrangler otherwise defaults to `.wrangler/state`
    /// in the project dir, which would carry KV entries over between
    /// separate test runs (e.g. a previously-cached CIDR list) instead of
    /// each run starting from a clean slate.
    persist_dir: std::path::PathBuf,
}

/// Drains `pipe` into `output` on a background thread until it hits EOF
/// (the child closing that fd, normally on exit). Reading continuously
/// rather than only at the end avoids the child blocking because nothing's
/// draining a full OS pipe buffer.
fn spawn_output_reader(mut pipe: impl Read + Send + 'static, output: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => output.lock().unwrap().extend_from_slice(&buf[..n]),
            }
        }
    });
}

impl WranglerDev {
    /// `cidr_list_url` overrides wrangler.toml's own `CIDR_LIST_URL` default
    /// (Telegram's real endpoint) for the whole run, so the CIDR-fetch
    /// scenario can point it at a local mock server instead.
    /// `bootstrap_last_checked`
    /// overrides `TELEGRAM_CIDR_BOOTSTRAP_LAST_CHECKED` -- the real, checked-in
    /// value is always recent in a healthy repo, which would make "the
    /// bootstrap is stale enough to fetch" undemonstrable and date-dependent
    /// otherwise.
    fn start(cidr_list_url: &str, bootstrap_last_checked: &str) -> Self {
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

        let persist_dir = std::env::temp_dir().join(format!("mg-cloudflare-relay-test-{}", std::process::id()));
        std::fs::create_dir_all(&persist_dir).expect("failed to create --persist-to directory");

        let port = pick_free_port();
        let mut child = Command::new("npx")
            .args([
                "wrangler",
                "dev",
                "--port",
                &port.to_string(),
                "--var",
                &format!("CIDR_LIST_URL:{cidr_list_url}"),
                "--var",
                &format!("CIDR_LIST_BOOTSTRAP_LAST_CHECKED:{bootstrap_last_checked}"),
                "--persist-to",
                persist_dir.to_str().expect("temp dir path must be valid UTF-8"),
            ])
            .current_dir(PROJECT_DIR)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group, so the whole tree (node, workerd,
            // esbuild -- which land on their own ports, e.g. an inspector
            // port) can be killed together on Drop instead of leaving
            // orphans that accumulate and slow down every later run.
            .process_group(0)
            .spawn()
            .expect("failed to spawn `npx wrangler dev` (is Node/npm installed?)");
        // process_group(0) makes the child's PGID equal its own PID.
        WRANGLER_PGID.store(child.id(), Ordering::SeqCst);

        let output = Arc::new(Mutex::new(Vec::new()));
        spawn_output_reader(child.stdout.take().expect("child spawned with piped stdout"), Arc::clone(&output));
        spawn_output_reader(child.stderr.take().expect("child spawned with piped stderr"), Arc::clone(&output));

        let mut dev = Self { child, port, output, persist_dir };
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

        // Only shown on failure: quiet on the happy path, but the whole
        // point of capturing this was to have it on hand exactly when
        // something -- ours or wrangler's own -- went wrong.
        if std::thread::panicking() {
            let output = self.output.lock().unwrap();
            eprintln!("--- wrangler dev output ---\n{}", String::from_utf8_lossy(&output));
        }

        let _ = std::fs::remove_dir_all(&self.persist_dir);
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

/// A minimal HTTP server standing in for Telegram's CIDR list endpoint,
/// always serving the same fixed body and recording how many times it was
/// hit and the `If-Modified-Since` (if any) each request carried -- used to
/// verify the relay only fetches when it actually needs to, and does so
/// conditionally (see the doc comment on `is_telegram_ip` in src/lib.rs).
///
/// Realistic tests of the actual conditional-refetch/304 path would need to
/// force the 24h staleness window, which isn't practical to simulate here
/// (no way to fast-forward the Worker's own clock) -- what's checked
/// instead is that the very first-ever fetch, with nothing cached yet,
/// sends no conditional header at all.
///
/// Same leaked-background-thread caveat as `MockDistributor` above: fine for
/// this file's single `#[test] fn`, but would need explicit teardown if a
/// second one is ever added.
struct MockCidrServer {
    port: u16,
    request_count: Arc<AtomicUsize>,
    last_if_modified_since: Arc<Mutex<Option<String>>>,
}

impl MockCidrServer {
    fn start(body: String) -> Self {
        let port = pick_free_port();
        let server = tiny_http::Server::http(("127.0.0.1", port)).expect("failed to start mock CIDR server");
        let request_count = Arc::new(AtomicUsize::new(0));
        let last_if_modified_since = Arc::new(Mutex::new(None));

        let count = Arc::clone(&request_count);
        let if_modified_since_store = Arc::clone(&last_if_modified_since);
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                count.fetch_add(1, Ordering::SeqCst);
                let seen = request
                    .headers()
                    .iter()
                    .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("if-modified-since"))
                    .map(|h| h.value.as_str().to_string());
                *if_modified_since_store.lock().unwrap() = seen;

                let _ = request.respond(Response::from_string(body.clone()));
            }
        });

        Self { port, request_count, last_if_modified_since }
    }

    /// A hostname, not a literal IP, for the same reason as
    /// `MockDistributor::url` -- see its doc comment.
    fn url(&self) -> String { format!("http://localhost:{}/cidr.txt", self.port) }

    fn request_count(&self) -> usize { self.request_count.load(Ordering::SeqCst) }

    fn last_if_modified_since(&self) -> Option<String> { self.last_if_modified_since.lock().unwrap().clone() }
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

/// IPv4 addresses from the RFC 5737 documentation range -- guaranteed not to
/// appear in Telegram's real bootstrap list. `_A`/`_B` are included in the
/// mock CIDR server's list (see `integration_test`), so they become
/// recognized once that's been fetched; `_UNKNOWN` never is, so it stays
/// unrecognized even after a fetch.
const MOCK_CIDR_IP_A: &str = "192.0.2.5";
const MOCK_CIDR_IP_B: &str = "192.0.2.10";
const MOCK_CIDR_IP_UNKNOWN: &str = "192.0.2.99";

#[test]
fn integration_test() {
    install_sigint_cleanup();

    // A superset of the real bootstrap list (see TELEGRAM_CIDR_BOOTSTRAP's
    // doc comment) plus the two mock-only IPs above.
    let mock_cidr_list = format!("{TELEGRAM_CIDR_BOOTSTRAP}\n{MOCK_CIDR_IP_A}\n{MOCK_CIDR_IP_B}");
    let cidr_server = MockCidrServer::start(mock_cidr_list);
    // Deliberately stale (well past CIDR_LIST_MAX_AGE's 24h, well short of
    // CIDR_LIST_FORCE_REFETCH_MAX_AGE's 30 days) so the "bootstrap is stale
    // enough to fetch" scenario is deterministic regardless of how recently
    // data/telegram-cidrs.txt.last-checked's real value happens to have been
    // updated.
    let stale_bootstrap_last_checked = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc2822();
    let dev = WranglerDev::start(&cidr_server.url(), &stale_bootstrap_last_checked);
    let port = dev.port;

    // Must run before any other scenario: it depends on the CIDR cache
    // still being empty (nothing fetched yet) at the start.
    fetches_cidr_list_only_for_unrecognized_ip(port, &cidr_server);

    rejects_absent_cf_connecting_ip(port);
    rejects_non_telegram_ip(port);
    rejects_literal_private_ip_target(port);
    forwards_put_to_valid_target(port);
    rejects_redirecting_distributor(port);
    post_suppresses_following_put(port);
}

/// An unrecognized IP against a never-fetched cache triggers exactly one
/// blocking fetch (and is still correctly rejected if it's genuinely not in
/// the fetched list either); once that fetch has populated the cache,
/// further requests -- whether from a bootstrap-only IP or one only the
/// fetch itself revealed -- are all accepted without triggering another
/// fetch. See `is_telegram_ip` in src/lib.rs.
///
/// Doesn't cover the separate `CidrListFreshness::VeryStale` background
/// re-fetch (a recognized-but-never-confirmed IP still kicks off a
/// `ctx.wait_until` refresh) -- there's no way to deterministically observe
/// a `wait_until` task's completion from outside the Worker, and forcing the
/// real trigger for it (the cache exceeding
/// `CIDR_LIST_FORCE_REFETCH_MAX_AGE_MS`, 30 days) isn't practical here either.
/// That threshold classification is covered at the unit level instead (see
/// `test_is_cidr_list_fresh_*` in src/lib.rs).
fn fetches_cidr_list_only_for_unrecognized_ip(port: u16, cidr_server: &MockCidrServer) {
    let distributor = MockDistributor::start(None);
    let target = encode(&distributor.url());

    let resp = ureq::put(&worker_url(port, &format!("/{target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "an IP absent from even the freshly-fetched list should stay rejected");
    assert_eq!(cidr_server.request_count(), 1, "an unrecognized IP with no prior fetch should trigger exactly one");
    assert!(
        cidr_server.last_if_modified_since().is_some(),
        "even the very first-ever fetch should send If-Modified-Since: current_cidr_list synthesizes and \
         persists a backdated timestamp before fetch_fresh_cidr_list ever runs (see its doc comment in \
         src/lib.rs), specifically so a never-fetched cache still participates in conditional GET"
    );

    let resp = ureq::put(&worker_url(port, &format!("/{target}")))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 201, "a bootstrap-list IP should be accepted");
    assert_eq!(cidr_server.request_count(), 1, "a recognized IP against a now-fresh cache shouldn't trigger a fetch");

    let resp = ureq::put(&worker_url(port, &format!("/{target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_A)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 201, "an IP only the fetched list (not bootstrap) recognizes should be accepted");
    assert_eq!(cidr_server.request_count(), 1, "still no further fetch");

    let resp = ureq::put(&worker_url(port, &format!("/{target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_B)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 201, "a different IP already in the now-cached list should be accepted");
    assert_eq!(cidr_server.request_count(), 1, "still no further fetch");
}

/// Doesn't set `CF-Connecting-IP` at all -- but this can't actually verify
/// `get_client_ip` returning `None` (the genuinely-absent-header path), since
/// under `wrangler dev` the header gets set anyway: `CF-Connecting-IP`'s
/// purpose is reflecting the real connecting peer, and Miniflare does that
/// faithfully even locally, where the peer is genuinely 127.0.0.1 over a real
/// loopback connection. So this exercises the same "IP not in Telegram's
/// range" rejection as `rejects_non_telegram_ip`, just via a different IP --
/// kept as a separate test because the two have distinct intent even though
/// they collapse to the same code path here (no way to actually omit what
/// Miniflare will reflect from a real, unspoofed local test client).
fn rejects_absent_cf_connecting_ip(port: u16) {
    let resp = ureq::put(&worker_url(port, &format!("/{}", encode("http://example.com/"))))
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "PUT with no explicit CF-Connecting-IP should be rejected");
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
