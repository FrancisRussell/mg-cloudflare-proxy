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

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::StatusCode;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tiny_http::Response;

const PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");
/// The `worker-build` version to install, matching wrangler.toml's build
/// command.
const WORKER_BUILD_CRATE: &str = "worker-build@0.8.6";
const READY_TIMEOUT: Duration = Duration::from_secs(45);
/// Per-request timeout for every HTTP call this test makes. Without this,
/// ureq blocks with no timeout at all -- a single hung request (e.g. the
/// worker's own outbound fetch never returning) would hang the whole test
/// indefinitely instead of failing with a clear error.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often `wait_until_ready()` and Drop's reap loop poll.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CONDITION_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long Drop waits for the killed process to actually be reaped before
/// giving up (it's already dead at this point; this is just avoiding a
/// zombie, not waiting for anything uncertain).
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// A range the mock CIDR server always serves, and an IP inside it. Every
/// list the mock serves must include this range: a fetch replaces the cached
/// list entirely, and scenarios outside the CIDR ones still need
/// `TELEGRAM_IP` to be recognized.
const TELEGRAM_CIDR_RANGE: &str = "91.108.56.0/22";
const TELEGRAM_IP: &str = "91.108.56.1";

/// KV keys the Worker caches the CIDR list under. Must match
/// `CIDR_LIST_KV_KEY`, `CIDR_LIST_FETCHED_AT_KV_KEY` and
/// `CIDR_LIST_FAILED_AT_KV_KEY` in src/, which this test can't import (the
/// crate only builds for wasm).
const CIDR_LIST_KV_KEY: &str = "telegram_cidrs";
const CIDR_LIST_FETCHED_AT_KV_KEY: &str = "telegram_cidrs_fetched_at";
const CIDR_LIST_FAILED_AT_KV_KEY: &str = "telegram_cidrs_failed_at";

/// Cache ages that put the cache in each freshness class whatever the Worker's
/// jitter draws: past the fresh window but well inside the force-refetch
/// window, and well past the force-refetch window.
const STALE_CACHE_AGE: Duration = Duration::from_hours(2 * 24);
const VERY_STALE_CACHE_AGE: Duration = Duration::from_hours(31 * 24);

/// The most time the Worker is told a request may take, shorter than its
/// default so the timeout scenarios don't take long.
const TEST_RESPONSE_BUDGET: Duration = Duration::from_secs(3);
/// How far past the response budget a timeout answer may arrive.
const BUDGET_TOLERANCE: Duration = Duration::from_millis(1500);

/// A time since a failed fetch that is past the retry interval whatever its
/// jitter.
const LONG_AFTER_FAILURE: Duration = Duration::from_hours(8);

/// A body size comfortably over the Worker's request body limit.
const OVERSIZED_BODY_BYTES: usize = 64 * 1024;

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
    listener.local_addr().expect("a bound listener has an address").port()
}

/// Manages a `wrangler dev` child process covering the whole test run:
/// rebuilds the worker, starts it, and waits until it responds to requests.
/// The whole process tree is killed on drop.
struct WranglerDev {
    child: Child,
    port: u16,
    /// The `CIDR_LIST_URL` the Worker was started with, so a restart reuses it.
    cidr_list_url: String,
    /// The copy of wrangler.toml `wrangler dev` runs from; see
    /// `write_test_wrangler_config`.
    config_path: std::path::PathBuf,
    /// The id of the CIDR cache KV namespace, as `wrangler dev`'s local
    /// explorer API knows it.
    kv_namespace_id: String,
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
                Ok(n) => output.lock().expect("a thread panicked while holding the lock").extend_from_slice(&buf[..n]),
            }
        }
    });
}

/// Writes a copy of wrangler.toml for `wrangler dev` to run from, without its
/// `[build]` section, which would rebuild the Worker on every (re)start when
/// this test has already built it. `main` is made absolute, since the copy
/// lives elsewhere.
fn write_test_wrangler_config(dir: &std::path::Path) -> std::path::PathBuf {
    let original = std::fs::read_to_string(std::path::Path::new(PROJECT_DIR).join("wrangler.toml"))
        .expect("failed to read wrangler.toml");
    let mut copy = String::new();
    let mut in_build_section = false;
    for line in original.lines() {
        if line.starts_with('[') {
            in_build_section = line.trim() == "[build]";
        }
        if in_build_section {
            continue;
        }
        if let Some(main) = line.strip_prefix("main = \"") {
            writeln!(copy, "main = \"{PROJECT_DIR}/{main}").expect("writing to a String can't fail");
        } else {
            copy.push_str(line);
            copy.push('\n');
        }
    }
    let path = dir.join("wrangler.test.toml");
    std::fs::write(&path, copy).expect("failed to write the test wrangler config");
    path
}

/// Spawns `npx wrangler dev` in its own process group, feeding its output
/// into `output`.
fn spawn_wrangler_dev(
    port: u16, cidr_list_url: &str, persist_dir: &std::path::Path, config_path: &std::path::Path,
    output: &Arc<Mutex<Vec<u8>>>,
) -> Child {
    let mut child = Command::new("npx")
        .args([
            "wrangler",
            "dev",
            "--config",
            config_path.to_str().expect("temp dir path must be valid UTF-8"),
            "--port",
            &port.to_string(),
            "--var",
            &format!("CIDR_LIST_URL:{cidr_list_url}"),
            "--var",
            &format!("MAX_RESPONSE_MS:{}", TEST_RESPONSE_BUDGET.as_millis()),
            "--persist-to",
            persist_dir.to_str().expect("temp dir path must be valid UTF-8"),
        ])
        .current_dir(PROJECT_DIR)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own process group, so the whole tree (node, workerd, esbuild --
        // which land on their own ports, e.g. an inspector port) can be
        // killed together on Drop instead of leaving orphans that accumulate
        // and slow down every later run.
        .process_group(0)
        .spawn()
        .expect("failed to spawn `npx wrangler dev` (is Node/npm installed?)");
    // process_group(0) makes the child's PGID equal its own PID.
    WRANGLER_PGID.store(child.id(), Ordering::SeqCst);

    spawn_output_reader(child.stdout.take().expect("child spawned with piped stdout"), Arc::clone(output));
    spawn_output_reader(child.stderr.take().expect("child spawned with piped stderr"), Arc::clone(output));
    child
}

impl WranglerDev {
    /// `cidr_list_url` overrides wrangler.toml's own `CIDR_LIST_URL` default
    /// (Telegram's real endpoint) for the whole run, so the CIDR-fetch
    /// scenarios can point it at a local mock server instead. The local KV
    /// namespace starts empty; see `seed_cidr_cache`.
    fn start(cidr_list_url: &str) -> Self {
        // Matches wrangler.toml's own [build] command: install (a no-op if
        // already present) rather than requiring a separate manual step.
        let status = Command::new("cargo")
            .args(["install", "-q", "--locked", WORKER_BUILD_CRATE])
            .status()
            .expect("failed to run `cargo install worker-build` (is cargo installed?)");
        assert!(status.success(), "cargo install worker-build failed");

        let status = Command::new("worker-build")
            .arg("--release")
            .current_dir(PROJECT_DIR)
            .status()
            .expect("failed to run worker-build");
        assert!(status.success(), "worker-build failed");

        let persist_dir = std::env::temp_dir().join(format!("mg-cloudflare-proxy-test-{}", std::process::id()));
        std::fs::create_dir_all(&persist_dir).expect("failed to create --persist-to directory");

        let config_path = write_test_wrangler_config(&persist_dir);

        let port = pick_free_port();
        let output = Arc::new(Mutex::new(Vec::new()));
        let child = spawn_wrangler_dev(port, cidr_list_url, &persist_dir, &config_path, &output);
        let mut dev = Self {
            child,
            port,
            cidr_list_url: cidr_list_url.to_string(),
            config_path,
            kv_namespace_id: String::new(),
            output,
            persist_dir,
        };
        dev.wait_until_ready();
        dev.kv_namespace_id = dev.find_kv_namespace_id();
        dev
    }

    /// Restarts `wrangler dev` on the same port and with the same KV state,
    /// which gives the Worker a fresh isolate that has to load everything
    /// from KV again. The Worker keeps what it has loaded in memory, so this
    /// is how a scenario makes it notice KV contents changed behind its back.
    fn restart(&mut self) {
        kill_wrangler_process_group();
        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline && !matches!(self.child.try_wait(), Ok(Some(_))) {
            std::thread::sleep(REAP_POLL_INTERVAL);
        }
        self.child =
            spawn_wrangler_dev(self.port, &self.cidr_list_url, &self.persist_dir, &self.config_path, &self.output);
        self.wait_until_ready();
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

    /// Runs the deploy-time seed script (scripts/seed-cidr-cache.sh) against
    /// this run's local KV namespace, fetching from `cidr_list_url`.
    fn seed_cidr_cache(&self, cidr_list_url: &str) {
        let mut cmd = Command::new("bash");
        cmd.arg("scripts/seed-cidr-cache.sh")
            .env("CIDR_LIST_URL", cidr_list_url)
            .env("CIDR_CACHE_DIR", self.persist_dir.join("cidr-cache-dir"));
        self.run_against_local_kv(cmd, "seed-cidr-cache.sh");
    }

    /// The base URL of `wrangler dev`'s local explorer API for this run's KV
    /// namespace. Going through the running Worker's own storage is far quicker
    /// than a `wrangler kv` command, which pays Node's whole startup each time.
    fn kv_api_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/cdn-cgi/local/explorer/api/storage/kv/namespaces/{}",
            self.port, self.kv_namespace_id
        )
    }

    /// The id the local explorer API gives the CIDR cache namespace.
    fn find_kv_namespace_id(&self) -> String {
        let url = format!("http://127.0.0.1:{}/cdn-cgi/local/explorer/api/storage/kv/namespaces", self.port);
        let listing = ureq::get(&url)
            .timeout(REQUEST_TIMEOUT)
            .call()
            .unwrap_or_else(|e| panic!("wrangler dev's local explorer API is unavailable ({e}); is wrangler current?"))
            .into_string()
            .expect("the namespace listing is readable");
        let after_id = listing.split_once("\"id\":\"").expect("the namespace listing has an id").1;
        after_id.split_once('"').expect("the id is quoted").0.to_string()
    }

    /// The raw value currently stored under `key`, or an empty string if
    /// there is none.
    fn kv_get(&self, key: &str) -> String {
        match ureq::get(&format!("{}/values/{key}", self.kv_api_url())).timeout(REQUEST_TIMEOUT).call() {
            Ok(resp) => resp.into_string().expect("the value is readable"),
            Err(ureq::Error::Status(404, _)) => String::new(),
            Err(e) => panic!("reading {key} from KV failed: {e}"),
        }
    }

    /// Writes a raw value straight into the local CIDR cache namespace, to
    /// put it in states (e.g. an old timestamp) that can't be reached by
    /// waiting.
    fn kv_put(&self, key: &str, value: &str) {
        ureq::put(&format!("{}/values/{key}", self.kv_api_url()))
            .timeout(REQUEST_TIMEOUT)
            .send_string(value)
            .unwrap_or_else(|e| panic!("writing {key} to KV failed: {e}"));
    }

    fn kv_delete(&self, key: &str) {
        ureq::delete(&format!("{}/values/{key}", self.kv_api_url()))
            .timeout(REQUEST_TIMEOUT)
            .call()
            .unwrap_or_else(|e| panic!("deleting {key} from KV failed: {e}"));
    }

    fn kv_put_many(&self, entries: &[(&str, &str)]) {
        for (key, value) in entries {
            self.kv_put(key, value);
        }
    }

    fn kv_delete_many(&self, keys: &[&str]) {
        for key in keys {
            self.kv_delete(key);
        }
    }

    /// Makes the cache look as if Telegram last confirmed the list, and last
    /// answered at all, `age` ago, then restarts so the Worker loads that.
    fn age_cidr_cache_and_restart(&mut self, age: Duration) {
        let timestamp = fetched_at_value(age);
        self.set_cidr_times(&timestamp, &timestamp);
        self.restart();
    }

    /// Sets when Telegram last confirmed the cached list and when the last
    /// fetch failed. A failure time that isn't later than the confirmation
    /// counts as no failure, which is how a scenario clears one without a
    /// separate delete.
    fn set_cidr_times(&self, fetched_at: &str, failed_at: &str) {
        self.kv_put_many(&[(CIDR_LIST_FETCHED_AT_KV_KEY, fetched_at), (CIDR_LIST_FAILED_AT_KV_KEY, failed_at)]);
    }

    /// Runs the seed script's `cmd` with the flags that point wrangler's KV
    /// commands at the namespace this `wrangler dev` reads (`--local
    /// --preview`, under this run's `--persist-to` directory), returning its
    /// stdout and panicking with its output if it fails.
    fn run_against_local_kv(&self, mut cmd: Command, what: &str) -> String {
        let output = cmd
            .args(["--local", "--preview", "--persist-to"])
            .arg(&self.persist_dir)
            .current_dir(PROJECT_DIR)
            .output()
            .unwrap_or_else(|e| panic!("failed to run {what}: {e}"));
        assert!(
            output.status.success(),
            "{what} failed with {}:\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
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
            let output = self.output.lock().expect("a thread panicked while holding the lock");
            eprintln!("--- wrangler dev output ---\n{}", String::from_utf8_lossy(&output));
        }

        let _ = std::fs::remove_dir_all(&self.persist_dir);
    }
}

/// A minimal HTTP server standing in for a `UnifiedPush` distributor,
/// recording what it receives instead of doing anything with it.
/// The body and `Retry-After` a `MockDistributor` answers with.
#[derive(Debug, Clone, Copy, Default)]
struct Reply {
    body: &'static str,
    retry_after: Option<&'static str>,
}

struct MockDistributor {
    port: u16,
    request_count: Arc<AtomicUsize>,
    last_body: Arc<Mutex<Option<Vec<u8>>>>,
}

impl MockDistributor {
    /// Starts a mock distributor. If `redirect_to` is set, every request
    /// gets a redirect pointing there instead of a plain 200 -- for testing
    /// that the proxy won't follow a distributor's attempt to redirect it
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
        Self::start_with(redirect_to, Duration::ZERO, StatusCode::OK, Reply::default())
    }

    /// A distributor that waits `response_delay` before answering every
    /// request with `status`, for exercising requests that are still being
    /// forwarded when another arrives.
    fn start_slow(response_delay: Duration, status: StatusCode) -> Self {
        Self::start_with(None, response_delay, status, Reply::default())
    }

    /// A distributor that refuses every push with `status` and `reply`, as a
    /// rate-limiting push server would.
    fn start_refusing(status: StatusCode, reply: Reply) -> Self {
        Self::start_with(None, Duration::ZERO, status, reply)
    }

    fn start_with(
        redirect_to: Option<&'static str>, response_delay: Duration, status: StatusCode, reply: Reply,
    ) -> Self {
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
                *body_store.lock().expect("a thread panicked while holding the lock") = Some(body);

                std::thread::sleep(response_delay);
                let status = if redirect_to.is_some() { StatusCode::FOUND } else { status };
                let response = Response::from_string(reply.body).with_status_code(status.as_u16());
                let response = match reply.retry_after {
                    Some(seconds) => response.with_header(
                        tiny_http::Header::from_bytes(&b"Retry-After"[..], seconds.as_bytes())
                            .expect("a static header is valid"),
                    ),
                    None => response,
                };
                let response = match redirect_to {
                    Some(location) => response.with_header(
                        tiny_http::Header::from_bytes(&b"Location"[..], location.as_bytes())
                            .expect("the location is a valid header value"),
                    ),
                    None => response,
                };
                let _ = request.respond(response);
            }
        });

        Self { port, request_count, last_body }
    }

    /// This must be a hostname, not a literal IP: the proxy's SSRF check
    /// (`validate_endpoint`/`is_ip_safe`) rejects literal loopback IPs like
    /// 127.0.0.1 outright, but only checks literal IPs -- a hostname like
    /// "localhost" passes that check untouched (the documented DNS-rebinding
    /// gap), and under wrangler dev's local execution "localhost" really
    /// does reach this same machine, unlike in production Cloudflare Workers.
    fn url(&self) -> String { format!("http://localhost:{}/distributor", self.port) }

    fn request_count(&self) -> usize { self.request_count.load(Ordering::SeqCst) }

    fn last_body(&self) -> Vec<u8> {
        self.last_body
            .lock()
            .expect("a thread panicked while holding the lock")
            .clone()
            .expect("distributor received no request")
    }
}

/// A minimal HTTP server standing in for Telegram's CIDR list endpoint,
/// serving a body and status that tests can change, and recording how many
/// times it was hit and the `If-Modified-Since` (if any) the latest request
/// carried -- used to verify the proxy only fetches when it actually needs to,
/// and sends a conditional header only when it has a genuine fetch to refer to.
/// Never answers 304.
///
/// Same leaked-background-thread caveat as `MockDistributor` above: fine for
/// this file's single `#[test] fn`, but would need explicit teardown if a
/// second one is ever added.
struct MockCidrServer {
    port: u16,
    request_count: Arc<AtomicUsize>,
    last_if_modified_since: Arc<Mutex<Option<String>>>,
    body: Arc<Mutex<String>>,
    status: Arc<AtomicU16>,
    unreachable: Arc<AtomicBool>,
    silent: Arc<AtomicBool>,
    response_delay: Arc<AtomicU64>,
}

impl MockCidrServer {
    fn start(body: String) -> Self {
        // A hand-rolled server rather than `tiny_http`, so that "unreachable"
        // can close a connection without answering.
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to start mock CIDR server");
        let port = listener.local_addr().expect("a bound listener has an address").port();
        let request_count = Arc::new(AtomicUsize::new(0));
        let last_if_modified_since = Arc::new(Mutex::new(None));

        let body = Arc::new(Mutex::new(body));
        let status = Arc::new(AtomicU16::new(StatusCode::OK.as_u16()));
        let unreachable = Arc::new(AtomicBool::new(false));
        let silent = Arc::new(AtomicBool::new(false));
        let response_delay = Arc::new(AtomicU64::new(0));

        let count = Arc::clone(&request_count);
        let if_modified_since_store = Arc::clone(&last_if_modified_since);
        let body_store = Arc::clone(&body);
        let status_store = Arc::clone(&status);
        let unreachable_flag = Arc::clone(&unreachable);
        let silent_flag = Arc::clone(&silent);
        let delay_millis = Arc::clone(&response_delay);
        std::thread::spawn(move || {
            let mut held_open = Vec::new();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
                let Some(request_head) = read_request_head(&mut stream) else { continue };

                count.fetch_add(1, Ordering::SeqCst);
                *if_modified_since_store.lock().expect("a thread panicked while holding the lock") =
                    header_value(&request_head, "if-modified-since");

                if unreachable_flag.load(Ordering::SeqCst) {
                    // Dropping the stream closes the connection without an
                    // answer.
                    continue;
                }
                if silent_flag.load(Ordering::SeqCst) {
                    held_open.push(stream);
                    continue;
                }
                std::thread::sleep(Duration::from_millis(delay_millis.load(Ordering::SeqCst)));

                let body = body_store.lock().expect("a thread panicked while holding the lock").clone();
                let status = StatusCode::from_u16(status_store.load(Ordering::SeqCst)).expect("a valid status");
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or(""),
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        Self { port, request_count, last_if_modified_since, body, status, unreachable, silent, response_delay }
    }

    fn set_body(&self, body: String) { *self.body.lock().expect("a thread panicked while holding the lock") = body; }

    fn set_status(&self, status: StatusCode) { self.status.store(status.as_u16(), Ordering::SeqCst); }

    /// While set, requests are counted and their connections held open without
    /// ever being answered.
    fn set_silent(&self, silent: bool) { self.silent.store(silent, Ordering::SeqCst); }

    /// How long the server waits before answering each request.
    fn set_response_delay(&self, delay: Duration) {
        self.response_delay.store(u64::try_from(delay.as_millis()).expect("a small delay"), Ordering::SeqCst);
    }

    /// While set, requests are counted but the connection is closed without an
    /// answer, so a fetch fails outright.
    fn set_unreachable(&self, unreachable: bool) { self.unreachable.store(unreachable, Ordering::SeqCst); }

    /// A hostname, not a literal IP, for the same reason as
    /// `MockDistributor::url` -- see its doc comment.
    fn url(&self) -> String { format!("http://localhost:{}/cidr.txt", self.port) }

    fn request_count(&self) -> usize { self.request_count.load(Ordering::SeqCst) }

    fn last_if_modified_since(&self) -> Option<String> {
        self.last_if_modified_since.lock().expect("a thread panicked while holding the lock").clone()
    }
}

/// Reads a request up to the end of its headers, or `None` if the connection
/// ends or times out first.
fn read_request_head(stream: &mut impl Read) -> Option<String> {
    const HEADER_END: &[u8] = b"\r\n\r\n";
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(HEADER_END.len()).any(|window| window == HEADER_END) {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// The value of header `name` (lowercase) in a raw request head, if present.
fn header_value(request_head: &str, name: &str) -> Option<String> {
    request_head.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
    })
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
/// be in any real Telegram range. The mock CIDR server's first list includes
/// `_A` only, and its second list adds `_B`; `_UNKNOWN` is never listed.
const MOCK_CIDR_IP_A: &str = "192.0.2.5";
const MOCK_CIDR_IP_B: &str = "192.0.2.10";
const MOCK_CIDR_IP_UNKNOWN: &str = "192.0.2.99";

#[test]
fn integration_test() {
    install_sigint_cleanup();

    let initial_cidr_list = format!("{TELEGRAM_CIDR_RANGE}\n{MOCK_CIDR_IP_A}");
    let cidr_server = MockCidrServer::start(initial_cidr_list);
    let mut dev = WranglerDev::start(&cidr_server.url());
    let port = dev.port;

    // These share one CIDR cache, and each leaves it in the state the next
    // relies on, so they must run in this order and before the scenarios
    // below (which need `TELEGRAM_IP` recognized).
    seeding_makes_recognized_ips_need_no_fetch(port, &dev, &cidr_server);
    warm_isolate_answers_from_memory_without_kv(port, &dev);
    unrecognized_ip_against_fresh_cache_does_not_fetch(port, &cidr_server);
    invalid_requests_from_unrecognized_ip_do_not_fetch(port, &mut dev, &cidr_server);
    unrecognized_ip_against_stale_cache_fetches(port, &mut dev, &cidr_server);
    refresh_consults_kv_before_fetching(port, &mut dev, &cidr_server);
    failed_fetch_does_not_advance_the_confirmed_time(port, &mut dev, &cidr_server);
    unreachable_telegram_records_a_failure_and_holds_off_the_next(port, &mut dev, &cidr_server);
    silent_telegram_holds_up_the_request_only_for_the_budget(port, &mut dev, &cidr_server);
    concurrent_unrecognized_ips_share_one_refresh(port, &mut dev, &cidr_server);
    recognized_ip_against_very_stale_cache_refetches_in_background(port, &mut dev, &cidr_server);
    unrecognized_ip_against_empty_cache_fetches_unconditionally(port, &mut dev, &cidr_server);
    seeding_does_not_overwrite_newer_cache(&dev, &cidr_server);

    rejects_non_telegram_ip(port);
    rejects_literal_private_ip_target(port);
    forwards_put_to_valid_target(port);
    rejects_redirecting_distributor(port);
    post_suppresses_following_put(port);
    put_waits_for_a_slow_post_and_is_suppressed_when_it_succeeds(port);
    put_forwards_after_a_slow_post_that_fails(port);
    refusal_passes_on_only_status_and_retry_after(port);
    unreachable_push_server_answers_bad_gateway(port);
    unanswering_push_server_answers_gateway_timeout(port);
}

/// PUTs to a throwaway distributor from `client_ip`, returning the proxy's
/// status. What the distributor does with it doesn't matter to the CIDR
/// scenarios, only whether the proxy let the request through.
fn put_from(port: u16, client_ip: &str) -> u16 {
    let distributor = MockDistributor::start(None);
    let resp = ureq::put(&worker_url(port, &format!("/{}", encode(&distributor.url()))))
        .set("CF-Connecting-IP", client_ip)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    status_of(resp)
}

/// A timestamp `age` ago, in the millisecond-string form the Worker stores.
fn fetched_at_value(age: Duration) -> String {
    let fetched_at = std::time::SystemTime::now() - age;
    fetched_at.duration_since(std::time::UNIX_EPOCH).expect("the clock is after the epoch").as_millis().to_string()
}

/// Polls until `condition` holds, for observing effects of a `ctx.wait_until`
/// task, which finishes after the response has already been sent.
fn wait_for(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(CONDITION_POLL_INTERVAL);
    }
}

/// After the deploy-time seed script has run, IPs from the seeded list are
/// accepted with no fetch by the Worker itself.
fn seeding_makes_recognized_ips_need_no_fetch(port: u16, dev: &WranglerDev, cidr_server: &MockCidrServer) {
    dev.seed_cidr_cache(&cidr_server.url());
    let fetches_after_seed = cidr_server.request_count();
    assert_eq!(fetches_after_seed, 1, "the seed script should fetch the list once");

    assert_eq!(put_from(port, TELEGRAM_IP), 201);
    assert_eq!(put_from(port, MOCK_CIDR_IP_A), 201);
    assert_eq!(cidr_server.request_count(), fetches_after_seed, "recognized IPs shouldn't trigger a fetch");

    dev.seed_cidr_cache(&cidr_server.url());
    assert_eq!(
        cidr_server.request_count(),
        fetches_after_seed,
        "re-seeding with a recent local copy shouldn't refetch"
    );
}

/// An IP missing from a fresh cache is rejected without asking Telegram
/// again: a flood of unrecognized IPs mustn't turn into a flood of fetches.
fn unrecognized_ip_against_fresh_cache_does_not_fetch(port: u16, cidr_server: &MockCidrServer) {
    let fetches_before = cidr_server.request_count();
    assert_eq!(put_from(port, MOCK_CIDR_IP_B), 403);
    assert_eq!(cidr_server.request_count(), fetches_before);
}

/// A request failing a structural check is rejected before the allowlist is
/// consulted, so a prober from an unrecognized IP can't spend a CIDR fetch on
/// it. That includes a body over the size limit, whether declared up front or
/// streamed without a length.
fn invalid_requests_from_unrecognized_ip_do_not_fetch(port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer) {
    dev.age_cidr_cache_and_restart(STALE_CACHE_AGE);
    let fetches_before = cidr_server.request_count();
    let target = encode(&MockDistributor::start(None).url());
    let oversized = vec![b'x'; OVERSIZED_BODY_BYTES];

    let resp = ureq::post(&worker_url(port, &format!("/aesgcm?e={target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
        .set("Encryption", "salt=abc")
        .set("Crypto-Key", "dh=xyz")
        .timeout(REQUEST_TIMEOUT)
        .send_bytes(&oversized);
    assert_eq!(status_of(resp), 413, "an oversized POST body should be rejected");

    let resp = ureq::put(&worker_url(port, &format!("/{target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
        .timeout(REQUEST_TIMEOUT)
        .send_bytes(&oversized);
    assert_eq!(status_of(resp), 413, "an oversized PUT body should be rejected");

    let resp = ureq::put(&worker_url(port, "/not-a-url"))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
        .timeout(REQUEST_TIMEOUT)
        .send_string("body");
    assert_eq!(status_of(resp), 403, "a PUT with an invalid endpoint should be rejected");

    let resp = ureq::post(&worker_url(port, &format!("/aesgcm?e={target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
        .timeout(REQUEST_TIMEOUT)
        .send_string("ciphertext");
    assert_eq!(status_of(resp), 400, "a POST without the aesgcm headers should be rejected");

    let resp = ureq::put(&worker_url(port, &format!("/{target}")))
        .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
        .timeout(REQUEST_TIMEOUT)
        .send(std::io::Cursor::new(oversized.clone()));
    assert_eq!(status_of(resp), 413, "an oversized PUT body sent without a length should be rejected");

    // Under `wrangler dev`, answering a chunked upload before it finishes can
    // leave the local proxy's connection to the Worker dead, failing whatever
    // request comes next. Spend one request on absorbing that.
    let _ = ureq::get(&worker_url(port, "/")).timeout(REQUEST_TIMEOUT).call();

    assert_eq!(cidr_server.request_count(), fetches_before, "none of those should have triggered a fetch");

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 403);
    assert_eq!(
        cidr_server.request_count(),
        fetches_before + 1,
        "a well-formed request from the same IP does fetch, so the checks above weren't passing only because the cache was fresh"
    );
}

/// Once the cache has gone stale, an unrecognized IP triggers a blocking,
/// conditional fetch, and is accepted if the refreshed list now contains it.
fn unrecognized_ip_against_stale_cache_fetches(port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer) {
    cidr_server.set_body(format!("{TELEGRAM_CIDR_RANGE}\n{MOCK_CIDR_IP_A}\n{MOCK_CIDR_IP_B}"));
    dev.age_cidr_cache_and_restart(STALE_CACHE_AGE);
    let fetches_before = cidr_server.request_count();

    assert_eq!(put_from(port, MOCK_CIDR_IP_B), 201, "an IP only the refreshed list contains should be accepted");
    assert_eq!(cidr_server.request_count(), fetches_before + 1);
    assert!(
        cidr_server.last_if_modified_since().is_some(),
        "a refresh of a cache with a real fetch time should be conditional"
    );

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 403, "an IP in neither list should stay rejected");
    assert_eq!(cidr_server.request_count(), fetches_before + 1, "the refresh should have made the cache fresh again");
}

/// A fetch that fails is recorded as a failure, which holds off further
/// fetches, but leaves the time Telegram last confirmed the list alone. That
/// time is what the next refresh sends as `If-Modified-Since`: advancing it on
/// a failure would let Telegram answer 304 for changes made since the list was
/// really last held, keeping an out-of-date list. With the list unconfirmed and
/// the refresh failed, an unrecognized IP can't be judged, so it gets a 503.
fn failed_fetch_does_not_advance_the_confirmed_time(port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer) {
    let confirmed_at = fetched_at_value(STALE_CACHE_AGE);
    dev.set_cidr_times(&confirmed_at, &confirmed_at);
    dev.restart();
    cidr_server.set_status(StatusCode::SERVICE_UNAVAILABLE);
    let fetches_before = cidr_server.request_count();

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 503);
    assert_eq!(cidr_server.request_count(), fetches_before + 1);
    let if_modified_since_before_failure = cidr_server.last_if_modified_since();
    assert!(if_modified_since_before_failure.is_some());
    assert_eq!(dev.kv_get(CIDR_LIST_FETCHED_AT_KV_KEY).trim(), confirmed_at, "a failed fetch confirmed nothing");
    assert_ne!(dev.kv_get(CIDR_LIST_FAILED_AT_KV_KEY).trim(), confirmed_at, "the failure should be recorded");

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 503);
    assert_eq!(cidr_server.request_count(), fetches_before + 1, "the failure should hold off another fetch");

    // The retry interval has passed: only the failure's age matters now, not
    // the list's.
    dev.kv_put(CIDR_LIST_FAILED_AT_KV_KEY, &fetched_at_value(LONG_AFTER_FAILURE));
    dev.restart();
    cidr_server.set_status(StatusCode::OK);
    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 403);
    assert_eq!(cidr_server.request_count(), fetches_before + 2);
    assert_eq!(
        cidr_server.last_if_modified_since(),
        if_modified_since_before_failure,
        "the refresh after a failure should still be conditioned on when the list was last confirmed"
    );
    assert!(
        dev.kv_get(CIDR_LIST_FAILED_AT_KV_KEY).trim().parse::<u64>().is_err(),
        "a successful fetch should clear the recorded failure"
    );
}

/// Telegram not answering at all is recorded as a failure like any other
/// failure, so an outage isn't hit by every request; once the retry interval
/// has passed the next request tries again.
fn unreachable_telegram_records_a_failure_and_holds_off_the_next(
    port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer,
) {
    let confirmed_at = fetched_at_value(STALE_CACHE_AGE);
    dev.set_cidr_times(&confirmed_at, &confirmed_at);
    dev.restart();
    cidr_server.set_unreachable(true);
    let fetches_before = cidr_server.request_count();

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 503);
    assert_eq!(cidr_server.request_count(), fetches_before + 1);
    assert_eq!(dev.kv_get(CIDR_LIST_FETCHED_AT_KV_KEY).trim(), confirmed_at, "nothing was confirmed");
    assert_ne!(dev.kv_get(CIDR_LIST_FAILED_AT_KV_KEY).trim(), confirmed_at, "the failure should be recorded");

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 503);
    assert_eq!(cidr_server.request_count(), fetches_before + 1, "the failure should hold off another fetch");

    cidr_server.set_unreachable(false);
    dev.kv_put(CIDR_LIST_FAILED_AT_KV_KEY, &fetched_at_value(LONG_AFTER_FAILURE));
    dev.restart();
    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 403);
    assert_eq!(
        cidr_server.request_count(),
        fetches_before + 2,
        "once the interval has passed, the next request retries"
    );
}

/// A Telegram endpoint that accepts the connection and never answers holds up
/// the request only for the response budget, which then gets a 503. The
/// refresh carries on in the background until the fetch times out, and its
/// failure is recorded then.
fn silent_telegram_holds_up_the_request_only_for_the_budget(
    port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer,
) {
    /// Longer than the response budget, so the Worker's answer is the one seen.
    const CLIENT_PATIENCE: Duration = Duration::from_secs(30);
    /// Longer than the Worker's CIDR fetch timeout.
    const BACKGROUND_FETCH_PATIENCE: Duration = Duration::from_secs(30);

    let confirmed_at = fetched_at_value(STALE_CACHE_AGE);
    dev.set_cidr_times(&confirmed_at, &confirmed_at);
    dev.restart();
    cidr_server.set_silent(true);

    let started = Instant::now();
    let status = status_of(
        ureq::put(&worker_url(port, &format!("/{}", encode(&MockDistributor::start(None).url()))))
            .set("CF-Connecting-IP", MOCK_CIDR_IP_UNKNOWN)
            .timeout(CLIENT_PATIENCE)
            .send_string("body"),
    );
    let elapsed = started.elapsed();
    cidr_server.set_silent(false);

    assert_eq!(status, 503, "an IP that can't be judged because Telegram hasn't answered");
    assert!(elapsed <= TEST_RESPONSE_BUDGET + BUDGET_TOLERANCE, "answered long after the budget: {elapsed:?}");
    assert_eq!(dev.kv_get(CIDR_LIST_FAILED_AT_KV_KEY).trim(), confirmed_at, "the fetch is still running");

    let give_up = Instant::now() + BACKGROUND_FETCH_PATIENCE;
    while dev.kv_get(CIDR_LIST_FAILED_AT_KV_KEY).trim() == confirmed_at {
        assert!(Instant::now() < give_up, "the background refresh never recorded its failure");
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Requests for unrecognized IPs that arrive together while the list is being
/// refreshed share that one refresh instead of each fetching.
fn concurrent_unrecognized_ips_share_one_refresh(port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer) {
    dev.age_cidr_cache_and_restart(STALE_CACHE_AGE);
    cidr_server.set_response_delay(Duration::from_secs(1));
    let fetches_before = cidr_server.request_count();

    let requests: Vec<_> = (0..3).map(|_| std::thread::spawn(move || put_from(port, MOCK_CIDR_IP_UNKNOWN))).collect();
    let statuses: Vec<u16> = requests.into_iter().map(|r| r.join().expect("a request thread panicked")).collect();
    cidr_server.set_response_delay(Duration::ZERO);

    assert_eq!(statuses, [403, 403, 403]);
    assert_eq!(cidr_server.request_count(), fetches_before + 1, "the requests should have shared one fetch");
}

/// A refresh asks KV before Telegram: another isolate may already have
/// refreshed the list, and the timestamps it left in KV say whether a fetch is
/// still due.
fn refresh_consults_kv_before_fetching(port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer) {
    // A stale list that doesn't include B.
    dev.kv_put(CIDR_LIST_KV_KEY, &format!("{TELEGRAM_CIDR_RANGE}\n{MOCK_CIDR_IP_A}"));
    dev.age_cidr_cache_and_restart(STALE_CACHE_AGE);
    // Loads the stale state into the isolate; a recognized IP starts no
    // refresh.
    assert_eq!(put_from(port, TELEGRAM_IP), 201);
    let fetches_before = cidr_server.request_count();

    // Meanwhile, another isolate refreshed the list, which now includes B.
    let just_now = fetched_at_value(Duration::ZERO);
    dev.kv_put_many(&[
        (CIDR_LIST_KV_KEY, &format!("{TELEGRAM_CIDR_RANGE}\n{MOCK_CIDR_IP_A}\n{MOCK_CIDR_IP_B}")),
        (CIDR_LIST_FETCHED_AT_KV_KEY, &just_now),
        (CIDR_LIST_FAILED_AT_KV_KEY, &just_now),
    ]);

    assert_eq!(put_from(port, MOCK_CIDR_IP_B), 201, "the newer list in KV should be adopted");
    assert_eq!(cidr_server.request_count(), fetches_before, "and Telegram shouldn't have been asked");
}

/// Once an isolate has loaded the list it answers from memory: removing it
/// from KV changes nothing until the isolate restarts.
fn warm_isolate_answers_from_memory_without_kv(port: u16, dev: &WranglerDev) {
    let list = dev.kv_get(CIDR_LIST_KV_KEY);
    dev.kv_delete(CIDR_LIST_KV_KEY);
    assert_eq!(put_from(port, TELEGRAM_IP), 201);
    dev.kv_put(CIDR_LIST_KV_KEY, list.trim_end());
}

/// A recognized IP is answered immediately even when the cache is very
/// stale, but still prompts a refresh, so a reassigned Telegram range can't
/// stay trusted indefinitely.
fn recognized_ip_against_very_stale_cache_refetches_in_background(
    port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer,
) {
    dev.age_cidr_cache_and_restart(VERY_STALE_CACHE_AGE);
    let fetches_before = cidr_server.request_count();

    assert_eq!(put_from(port, TELEGRAM_IP), 201);
    wait_for("the background refetch", || cidr_server.request_count() > fetches_before);
    assert_eq!(cidr_server.request_count(), fetches_before + 1);

    assert_eq!(put_from(port, TELEGRAM_IP), 201);
    assert_eq!(
        cidr_server.request_count(),
        fetches_before + 1,
        "the background refetch should have made the cache fresh again"
    );
}

/// With nothing cached (e.g. the seed step was skipped), an unrecognized IP
/// still gets a correct answer via a fetch -- unconditional, since there's
/// no earlier fetch to refer to -- and that fetch populates the cache.
fn unrecognized_ip_against_empty_cache_fetches_unconditionally(
    port: u16, dev: &mut WranglerDev, cidr_server: &MockCidrServer,
) {
    dev.kv_delete_many(&[CIDR_LIST_KV_KEY, CIDR_LIST_FETCHED_AT_KV_KEY, CIDR_LIST_FAILED_AT_KV_KEY]);
    dev.restart();
    let fetches_before = cidr_server.request_count();

    assert_eq!(put_from(port, MOCK_CIDR_IP_UNKNOWN), 403);
    assert_eq!(cidr_server.request_count(), fetches_before + 1);
    assert_eq!(cidr_server.last_if_modified_since(), None, "with nothing cached, there's no fetch to condition on");

    assert_eq!(put_from(port, TELEGRAM_IP), 201, "the fetch should have populated the cache");
    assert_eq!(cidr_server.request_count(), fetches_before + 1);
}

/// By now the Worker has refreshed the cache itself, more recently than the
/// seed script's local copy was fetched; re-seeding mustn't replace that with
/// the older list.
fn seeding_does_not_overwrite_newer_cache(dev: &WranglerDev, cidr_server: &MockCidrServer) {
    let list_before = dev.kv_get(CIDR_LIST_KV_KEY);
    assert!(list_before.contains(MOCK_CIDR_IP_B), "test precondition: the cached list is the Worker's newer fetch");
    let fetches_before = cidr_server.request_count();

    dev.seed_cidr_cache(&cidr_server.url());

    assert_eq!(dev.kv_get(CIDR_LIST_KV_KEY), list_before);
    assert_eq!(cidr_server.request_count(), fetches_before, "the local copy is still recent, so no fetch");
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
        "the proxy should have actually dialed the distributor and seen its 302"
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

/// A push server slower to answer than the correlation wait, so the POST is
/// still being forwarded when its PUT has finished waiting.
const SLOW_PUSH_SERVER_DELAY: Duration = Duration::from_millis(700);
/// How long after starting the POST the PUT is sent: after the POST has
/// reached the correlator, well inside the push server's delay.
const PUT_SENT_AFTER_POST: Duration = Duration::from_millis(100);

/// Sends a POST and, shortly after, the PUT for the same endpoint, returning
/// the PUT's status and the POST's status.
fn post_then_put_while_post_in_flight(port: u16, target: &str) -> (u16, u16) {
    let post_thread = {
        let target_for_post = target.to_string();
        std::thread::spawn(move || {
            status_of(
                ureq::post(&worker_url(port, &format!("/aesgcm?e={target_for_post}")))
                    .set("CF-Connecting-IP", TELEGRAM_IP)
                    .set("Encryption", "salt=abc")
                    .set("Crypto-Key", "dh=xyz")
                    .timeout(REQUEST_TIMEOUT)
                    .send_string("ciphertext"),
            )
        })
    };
    std::thread::sleep(PUT_SENT_AFTER_POST);
    let put_status = status_of(
        ureq::put(&worker_url(port, &format!("/{target}")))
            .set("CF-Connecting-IP", TELEGRAM_IP)
            .timeout(REQUEST_TIMEOUT)
            .send_string("wake-up-body"),
    );
    (put_status, post_thread.join().expect("POST thread panicked"))
}

/// The PUT's own wait ends while the POST is still being forwarded. It must
/// keep waiting for that POST rather than forwarding a duplicate wake-up.
fn put_waits_for_a_slow_post_and_is_suppressed_when_it_succeeds(port: u16) {
    let distributor = MockDistributor::start_slow(SLOW_PUSH_SERVER_DELAY, StatusCode::OK);

    let (put_answer, post_answer) = post_then_put_while_post_in_flight(port, &encode(&distributor.url()));

    assert_eq!(post_answer, 201, "the POST should forward successfully, just slowly");
    assert_eq!(put_answer, 200, "the PUT should be suppressed once its POST succeeds");
    assert_eq!(distributor.request_count(), 1, "only the POST should reach the push server");
}

/// A POST that fails records nothing, so waiting on it must not suppress the
/// PUT: the wake-up is then the only notification that gets through.
fn put_forwards_after_a_slow_post_that_fails(port: u16) {
    let distributor = MockDistributor::start_slow(SLOW_PUSH_SERVER_DELAY, StatusCode::INTERNAL_SERVER_ERROR);

    let (put_answer, post_answer) = post_then_put_while_post_in_flight(port, &encode(&distributor.url()));

    assert_eq!(post_answer, 500, "the push server's failure is passed back to the POST");
    assert_eq!(put_answer, 500, "the PUT was forwarded, so it gets the push server's answer");
    assert_eq!(distributor.request_count(), 2, "the failed POST must not have suppressed the PUT");
}

/// A refusing push server's status, and `Retry-After` for a rate limit, are
/// what the caller needs; whatever body it wrote is not relayed.
fn refusal_passes_on_only_status_and_retry_after(port: u16) {
    const RETRY_AFTER_SECONDS: &str = "30";
    let distributor = MockDistributor::start_refusing(
        StatusCode::TOO_MANY_REQUESTS,
        Reply { body: "details only the push server should see", retry_after: Some(RETRY_AFTER_SECONDS) },
    );

    let resp = ureq::put(&worker_url(port, &format!("/{}", encode(&distributor.url()))))
        .set("CF-Connecting-IP", TELEGRAM_IP)
        .timeout(REQUEST_TIMEOUT)
        .send_string("wake-up-body");

    let Err(ureq::Error::Status(status, resp)) = resp else { panic!("expected the refusal to be passed on") };
    assert_eq!(status, 429);
    assert_eq!(resp.header("Retry-After"), Some(RETRY_AFTER_SECONDS));
    assert_eq!(resp.into_string().expect("the response body is readable"), "", "the push server's body isn't relayed");
}

/// PUTs to `endpoint` from a Telegram IP, returning the proxy's status.
/// `timeout` is how long the test client itself waits.
fn put_to_endpoint(port: u16, endpoint: &str, timeout: Duration) -> u16 {
    status_of(
        ureq::put(&worker_url(port, &format!("/{}", encode(endpoint))))
            .set("CF-Connecting-IP", TELEGRAM_IP)
            .timeout(timeout)
            .send_string("wake-up-body"),
    )
}

/// A push server that can't be reached is the gateway's problem to report,
/// not an internal error: a host name that doesn't exist, and a port nothing
/// listens on, both answer 502.
fn unreachable_push_server_answers_bad_gateway(port: u16) {
    // `.invalid` is reserved (RFC 2606) and never resolves.
    assert_eq!(put_to_endpoint(port, "http://no-such-host.invalid/push", REQUEST_TIMEOUT), 502);
    // Port 1 is not expected to have a listener.
    assert_eq!(put_to_endpoint(port, "http://localhost:1/push", REQUEST_TIMEOUT), 502);
}

/// A push server that accepts the connection and never answers is given up on
/// once the response budget is spent, rather than holding the request open.
fn unanswering_push_server_answers_gateway_timeout(port: u16) {
    /// Longer than the Worker's response budget, so the Worker's answer is the
    /// one seen.
    const CLIENT_PATIENCE: Duration = Duration::from_secs(30);

    let silent = TcpListener::bind("127.0.0.1:0").expect("failed to bind the silent push server");
    let silent_port = silent.local_addr().expect("a bound listener has an address").port();
    std::thread::spawn(move || {
        // Holds every connection open without ever answering.
        let held: Vec<_> = silent.incoming().collect();
        drop(held);
    });

    let started = Instant::now();
    assert_eq!(put_to_endpoint(port, &format!("http://localhost:{silent_port}/push"), CLIENT_PATIENCE), 504);
    let elapsed = started.elapsed();
    assert!(elapsed + BUDGET_TOLERANCE >= TEST_RESPONSE_BUDGET, "answered before the budget: {elapsed:?}");
    assert!(elapsed <= TEST_RESPONSE_BUDGET + BUDGET_TOLERANCE, "answered long after the budget: {elapsed:?}");
}
