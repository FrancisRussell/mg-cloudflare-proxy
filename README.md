# mg-cloudflare-proxy

An alternative push-notification gateway for
[Mercurygram](https://github.com/Mercurygram/Mercurygram), running on
Cloudflare Workers. Mercurygram depends on a gateway to deliver notifications
(its default is `https://p2p.belloworld.it/`), and if that one becomes
unavailable, this can be deployed in its place.

Ported from Mercurygram's own gateway,
[Mercurygram/aesgcm-proxy](https://github.com/Mercurygram/aesgcm-proxy) (see
[NOTICE](./NOTICE) for exactly what was ported).

## Background

Mercurygram is a Telegram client that adds support for receiving
notifications through [UnifiedPush](https://unifiedpush.org/), a push system
that doesn't depend on Google. A UnifiedPush app on your phone (a
"distributor", such as [ntfy](https://ntfy.sh) or
[Sunup](https://codeberg.org/Sunup/android)) works with a push server, which
gives Mercurygram a URL to register with Telegram. Notifications sent to that
URL reach your phone through the distributor app, instead of through Google's
Firebase Cloud Messaging (FCM).

Telegram's servers send these notifications in a form UnifiedPush can't carry
as-is. Each one is encrypted, and the details needed to decrypt it are in the
HTTP headers of the request, while UnifiedPush apps only pass on the request
body, so the details would be lost. A gateway (such as this project) bridges
the gap: Telegram sends to the gateway, which copies the details into the body
and forwards the result to the push server URL Mercurygram registered, so it
reaches your phone with everything Mercurygram needs to decrypt it. The
notifications stay encrypted end to end; the gateway never holds the keys to
read them.

## How it works

The gateway accepts Telegram's requests, checks that they come from Telegram's
published IP addresses and that the place it's asked to forward to is safe,
then forwards the notification to the UnifiedPush service you configured
Mercurygram to use.

According to `aesgcm-proxy`, Mercurygram registers a Simple Push token with
Telegram alongside its Web Push one. Due to this, Mercurygram's notifications
arrive as two kinds of request: a `POST` carrying the encrypted content (only
non-secret chats), and a `PUT` carrying a bare ping with no content.
`aesgcm-proxy` heuristically detects when these requests refer to the same
notification and coalesces them. It's not entirely clear why things are
implemented this way, but `mg-cloudflare-proxy` ports this behaviour.
`aesgcm-proxy` tracks this in its own memory, but a Cloudflare Worker has no
memory shared between requests, so here it's kept in a Durable Object, a
per-URL place to keep state that Cloudflare guarantees both requests reach.

## Setup

You'll need a Cloudflare account, Node.js/npm and a Rust toolchain, and a
UnifiedPush app installed on your phone.

### 1. Install dependencies

```sh
npm install
```

### 2. Deploy

```sh
npm run deploy
```

This logs in if needed, then finds the `CIDR_CACHE` KV namespace by name
(creating it if the account has none) and deploys against it, so re-running
this from a fresh clone reuses the same namespace instead of creating another
one. It also seeds the namespace with Telegram's published IP ranges before
deploying, so the Worker starts with a warm cache rather than every early
request fetching the list at once; the seed fetches into
`~/.cache/mg-cloudflare-proxy/` (`$XDG_CACHE_HOME` if set) and reuses that
local copy for a day rather than hitting Telegram again on every deploy
(delete that directory to force a fresh fetch). A failed seed doesn't stop
the deploy -- the Worker fills the cache itself from the first request (see
Security notes).

### 3. Configure Mercurygram

Point Mercurygram (Settings → Mercurygram → Notifications → UnifiedPush) at
your UnifiedPush app (e.g. Sunup), then set the gateway URL to your deployed Worker's
`*.workers.dev` URL, or a custom domain. Either way Telegram sees this URL,
since it's where Telegram sends the pushes. Check in your UnifiedPush
app that Mercurygram has successfully registered.

### 4. Test notifications

If you have multiple Telegram accounts, simply message one from the other to
create a test notification. If you do not have multiple accounts it's also
possible to create a bot account:

Message `@BotFather` and run `/newbot` to create a bot and API key. Send a
message to the bot from your Telegram account (bots cannot send to users that
have never messaged them). Then send yourself a test message through it:

```sh
export TELEGRAM_BOT_TOKEN=<token from BotFather>
scripts/send-test-push.py <your_telegram_username>
```

The token can also be kept in `~/.config/mg-cloudflare-proxy/test-push-token`
to avoid re-exporting it in every shell.

For this test you should ensure that Mercurygram is not running (not simply
backgrounded) otherwise it may receive the notification via a direct connection.
Note that for a cold notification, it may in fact take several seconds for this
to propagate to the phone. There may also be some Cloudflare latency when a worker
is used for the first time. Subsequent notifications are typically faster.

While doing this, it's also possible to see the logs from the worker by
running `npx wrangler tail` inside the repo.

`GET /health` returns a plain `200 OK` for external uptime monitoring, and
is accessible from any IP.

## Local development

Run unit tests:

```sh
cargo test --lib
```

These cover CIDR validation, IP matching, endpoint validation, and header
folding — pure Rust logic with no `worker::*` types involved.

Run the integration test suite (builds the Worker, runs it under `wrangler
dev` with KV and Durable Objects fully emulated locally, and drives it with
real HTTP requests against a mock push server):

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

Start the dev server for manual testing:

```sh
npx wrangler dev
```

Its local KV starts empty, so the first unrecognized IP fetches the CIDR
list itself, same as an unseeded deploy.

## Security notes

The proxy validates all inbound requests against Telegram's published CIDR
ranges before forwarding anything; requests from non-Telegram IPs are
rejected at the edge, before any Durable Object is even addressed. The list
is kept current on demand:

- A recognized IP is accepted without any fetch.
- An unrecognized IP against a list more than a day old triggers a fetch, so
  a newly added Telegram range is picked up promptly; at most one such fetch
  per day (excluding issues with Telegram's servers).
- A recognized IP against a list about a month old still gets an immediate
  answer, but triggers a background fetch, so a range Telegram has dropped
  can't stay trusted indefinitely.
- If the cache is empty (the seed step was skipped), the first unrecognized
  IP simply fetches the list.

Mitigations in place against a few specific threats:

- **SSRF via the forwarding target**: `validate_endpoint`/`is_ip_safe`
  reject literal private, loopback, link-local, and other non-public IPv4
  and IPv6 ranges. A Worker's `fetch()` can't reach private networks anyway,
  so this is defense in depth; the CIDR check above is what stops others
  using the proxy as a relay.
- **SSRF via a redirecting push server**: forwarding uses `redirect: manual`
  and rejects any 3xx response from the push server outright rather than
  following it — the SSRF check above only validated the *original* target,
  so blindly following a redirect would let a malicious push server route
  the request somewhere that check never saw.
- **Malformed input causing a panic**: the percent-decoder used on the PUT
  leg's path rejects sequences that decode to invalid UTF-8 rather than
  panicking on attacker-controlled input.
- **Oversized payloads**: request bodies over `MAX_BODY_BYTES` (16KB, well
  above real Telegram Web Push ciphertext sizes) are rejected outright.

Known residual gaps, accepted rather than fixed:

- **DNS-rebinding**: a domain name that *resolves* to a private/internal
  IP isn't caught (only literal IPs in the URL are checked) — `fetch()`
  gives no hook to validate the resolved address at connect time the way
  the original proxy's custom DNS resolver does. In practice, setting your
  push server to a real hostname (not a literal IP) mitigates this.
- **Durable Object cost scaling**: each distinct target-URL gets its own
  billed Durable Object instance, but that's only reachable after the
  Telegram-IP check passes — an external attacker can't reach it at all, so
  this is cost scaling with genuine usage (more real push server targets in
  use), not an attacker-controlled cost multiplier.
- **Arbitrary forwarding targets**: anyone who can register a Telegram device
  token can point it at any public host, using this Worker to send it a
  handful of opaque POSTs. There's no allowlist of permitted targets, because
  one would mean pre-registering a notifier before it works.

## Logging and privacy

Every rejection logs its reason and the client IP. A successful forward logs
the push server's *host* only — never the full target URL, path, or query
string, since UnifiedPush endpoint URLs are bearer-capability tokens: logging
one would be logging a credential. Forward logs also include the request
body size and both the push server's response status and the proxy's own.
CIDR-list fetch attempts log their outcome (success and entry count, a 304,
or the specific failure reason) but nothing about the request that triggered
them. Nothing here is stored beyond Cloudflare's normal `wrangler tail`/log
retention — the proxy itself keeps no logs of its own.

## Alternatives

Mercurygram's own repo also ships a Cloudflare Worker gateway, in JavaScript,
at
[`Gateways/CloudflareWorker`](https://github.com/Mercurygram/Mercurygram/tree/Mercurygram/Gateways/CloudflareWorker),
deployed by pasting `worker.mjs` into the Cloudflare dashboard and does not
require a KV namespace or Durable Object. It also optionally supports delivery
straight through Google's Firebase Cloud Messaging (FCM), which this project
deliberately doesn't.

Notable differences:

- **Telegram CIDR list caching.** This project uses a KV namespace to cache the
  list of Telegram CIDRs. This significantly reduces the number of pulls it does
  of that list from the Telegram servers.
- **PUT/POST correlation.** This implementation uses a Durable Object to
  correlate Simple Push and Web Push notifications. This means that correlation
  can occur correctly even if the notifications are routed to different
  isolates, which is untrue for `worker.mjs`. As mentioned above, it's not
  entirely clear why this is done, but a correlation failure possibly leads to
  duplicate notifications.
- **Logging.** A UnifiedPush endpoint URL is a bearer capability so this project
  only logs the push server's host and not the whole URL.
- **Retries.** If a push to a UnifiedPush endpoint fails in a way that
  suggests a retry might succeed, a single retry is made, provided there is
  time left within the request's time limit.

In all honesty however, this project would probably not exist if the author
had realized that
[`Gateways/CloudflareWorker`](https://github.com/Mercurygram/Mercurygram/tree/Mercurygram/Gateways/CloudflareWorker)
already existed at the time.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE),
matching the upstream project this was ported from. See [NOTICE](./NOTICE)
for attribution details.

## AI usage

This repository discloses AI involvement per the
[ai-disclosure](https://github.com/ggfevans/ai-disclosure) convention - see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) for details.
