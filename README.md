# mg-cloudflare-relay

Adapts Mercurygram's legacy Telegram WebPush (aesgcm Draft-04) push
notifications into UnifiedPush. Deploy it under your own Cloudflare account
(as a Worker named `mercurygram-relay` by default) instead of routing
through Mercurygram's own public gateway,
[Mercurygram/aesgcm-proxy](https://github.com/Mercurygram/aesgcm-proxy).

Reimplements aesgcm-proxy's `/aesgcm` and PUT routes (see [NOTICE](./NOTICE)
for exactly what was ported). Does not implement the `/fcm/<token>`
(VAPID/FCM) leg — this relay targets a real UnifiedPush distributor (e.g.
[Sunup](https://codeberg.org/Sunup/android), self-hosted
[ntfy](https://ntfy.sh)) directly.

## Why a Durable Object

Telegram sends two separate requests per message: a content-bearing
`POST /aesgcm` and a bare `PUT` wake-up (used for events with no content,
e.g. secret chats). The original proxy suppresses the redundant wake-up
when the content already arrived, using an in-process
`Mutex<HashMap<endpoint, timestamp>>`. A Worker gives no such guarantee of
shared memory across requests/isolates, so this correlation state instead
lives in a Durable Object, one instance per endpoint — Cloudflare
guarantees both requests for the same endpoint route to the same instance.
See the doc comment at the top of `src/correlator.rs`.

## Setup

### 1. Create a KV namespace

Log in to your Cloudflare dashboard and create a new KV namespace (Workers &
AI → KV → Create namespace). Choose a name like `mercurygram-relay` and note
the namespace ID and preview ID — the `CIDR_CACHE` binding name is what the
code actually keys off, so the namespace's own name is free to stay generic
even though it's currently only used for the CIDR cache.

### 2. Configure wrangler and deploy

Update `wrangler.toml` with your KV namespace IDs:

```toml
[[kv_namespaces]]
binding = "CIDR_CACHE"
id = "your-namespace-id-here"
preview_id = "your-preview-namespace-id-here"
```

Then install dependencies and log in:

```sh
npm install
npx wrangler login
```

### 3. Seed the Telegram CIDR cache

The relay only accepts requests from Telegram's published IP ranges, cached
in the `CIDR_CACHE` namespace. Fill it before the first deploy so the Worker
starts with a warm cache rather than every early request fetching the list
at once:

```sh
npm run seed-cidr
```

This fetches the list from Telegram (needs network access) into
`~/.cache/mg-cloudflare-relay/` (`$XDG_CACHE_HOME` if set) and uploads it,
with its fetch time, to the namespace. Repeated runs reuse the local copy for a day rather than hitting Telegram again, and
skip the upload if the namespace already holds a list at least as new. Delete
that directory to force a fresh fetch. The namespace outlives redeploys, so the
seed is a one-off; the Worker keeps the cache current itself from then on
(see Security notes).

### 4. Deploy

```sh
npx wrangler deploy
```

### 5. Configure Mercurygram

Point Mercurygram (Settings → Mercurygram → Notifications → UnifiedPush) at
your chosen distributor, then set the gateway URL to your deployed Worker's
`*.workers.dev` URL (or a custom domain, at the cost of that domain being
visible to Telegram's servers directly — see the gateway-vs-distributor
discussion this project came out of).

## Local development

Run unit tests:

```sh
cargo test --lib
```

These cover CIDR validation, IP matching, endpoint validation, and header
folding — pure Rust logic with no `worker::*` types involved.

Run the integration test suite (builds the Worker, runs it under `wrangler
dev` with KV and Durable Objects fully emulated locally, and drives it with
real HTTP requests against a mock distributor):

```sh
npm install
cargo test --features integration-tests --test integration
```

(`worker-build` is installed automatically as part of the test, matching
`wrangler.toml`'s own `[build]` command — no separate step needed.)

This covers what the unit tests structurally can't reach — routing, header
reading, KV, Durable Object correlation, and real outbound `fetch()`s, and
is what verifies the redirect-rejection mitigation under Security notes
below (a plain unit test can't drive a real `fetch()` redirect). Gated
behind the `integration-tests` feature since it needs Node/npm installed —
a plain `cargo test` doesn't build or run it at all.
Unix-only (process groups aren't portable); compiles to an empty, harmless
test binary on other platforms.

Start the dev server for manual testing, seeding its local cache first
(`--preview` is the namespace `wrangler dev` reads):

```sh
npm run seed-cidr -- --local --preview
npx wrangler dev
```

## Security notes

The relay validates all inbound requests against Telegram's published CIDR
ranges before forwarding anything; requests from non-Telegram IPs are
rejected at the edge, before any Durable Object is even addressed. The list
is kept current on demand:

- A recognized IP is accepted without any fetch.
- An unrecognized IP against a list more than a day old triggers a fetch, so
  a newly added Telegram range is picked up promptly; at most one such fetch
  per day.
- A recognized IP against a list about a month old (with some random
  early jitter) still gets an immediate answer, but triggers a background
  fetch, so a range Telegram has dropped can't stay trusted indefinitely.
- If the cache is empty (the seed step was skipped), the first unrecognized
  IP simply fetches the list.

Mitigations in place against a few specific threats:

- **SSRF via the forwarding target**: `validate_endpoint`/`is_ip_safe`
  reject literal private, loopback, link-local, and other non-public IP
  ranges for both IPv4 and IPv6 equally, so a target URL can't point the
  relay's outbound `fetch()` at internal infrastructure.
- **SSRF via a redirecting distributor**: forwarding uses `redirect: manual`
  and rejects any 3xx response from the distributor outright rather than
  following it — the SSRF check above only validated the *original* target,
  so blindly following a redirect would let a malicious distributor route
  the request somewhere that check never saw.
- **Malformed input causing a panic**: the percent-decoder used on the PUT
  leg's path rejects invalid percent-encoded sequences with an error rather
  than panicking on attacker-controlled input.
- **Oversized payloads**: request bodies over `MAX_BODY_BYTES` (16KB, well
  above real Telegram `WebPush` ciphertext sizes) are rejected outright.

Known residual gaps, accepted rather than fixed:

- **DNS-rebinding**: a domain name that *resolves* to a private/internal
  IP isn't caught (only literal IPs in the URL are checked) — `fetch()`
  gives no hook to validate the resolved address at connect time the way
  the original proxy's custom DNS resolver does. In practice, setting your
  distributor to a real hostname (not a literal IP) mitigates this.
- **Durable Object cost scaling**: each distinct target-URL gets its own
  billed Durable Object instance, but that's only reachable after the
  Telegram-IP check passes — an external attacker can't reach it at all, so
  this is cost scaling with genuine usage (more real distributor targets in
  use), not an attacker-controlled cost multiplier.

## Logging and privacy

Every rejection logs its reason and the client IP. A successful forward logs
the distributor's *host* only — never the full target URL, path, or query
string, since UnifiedPush endpoint URLs are bearer-capability tokens: logging
one would be logging a credential. Forward logs also include the request
body size and both the distributor's response status and the relay's own.
CIDR-list fetch attempts log their outcome (success and entry count, a 304,
or the specific failure reason) but nothing about the request that triggered
them. Nothing here is stored beyond Cloudflare's normal `wrangler tail`/log
retention — the relay itself keeps no logs of its own.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE),
matching the upstream project this was ported from. See [NOTICE](./NOTICE)
for attribution details.
