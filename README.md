# mg-edge-relay

A Cloudflare Worker + Durable Object relay for Mercurygram's legacy WebPush
(aesgcm Draft-04) notifications, deployed under your own Cloudflare account
instead of relying on Mercurygram's public gateway.

Reimplements the `/aesgcm` and PUT routes of
[Mercurygram/aesgcm-proxy](https://github.com/Mercurygram/aesgcm-proxy) (see
[NOTICE](./NOTICE) for exactly what was ported). Does not implement the
`/fcm/<token>` (VAPID/FCM) leg — this relay targets a real UnifiedPush
distributor (e.g. [Sunup](https://codeberg.org/Sunup/android), self-hosted
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
AI → KV → Create namespace). Choose a name like `mg-edge-relay-cidrs` and note
the namespace ID and preview ID.

### 2. Configure wrangler and deploy

Update `wrangler.toml` with your KV namespace IDs:

```toml
[[kv_namespaces]]
binding = "CIDR_CACHE"
id = "your-namespace-id-here"
preview_id = "your-preview-namespace-id-here"
```

Then deploy:

```sh
npm install
npx wrangler login
npx wrangler deploy
```

The pre-deploy script (`npm run check-cidr`) keeps `data/telegram-cidrs.txt`
in sync with Telegram's published list: it skips the check entirely if run
within the last day, otherwise does a conditional fetch and updates the
file in place if the list has changed. No manual steps needed — the change
is picked up on the next build via `include_str!`.

### 3. Configure Mercurygram

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

Start the dev server:

```sh
npm install
npx wrangler dev
```

Tests cover CIDR validation, IP matching, endpoint validation, and header
folding. Integration testing (routes, KV, Durable Objects) requires deployment
to Cloudflare Workers.

## Security notes

Reviewed under an adversarial threat model before first deploy; two real
bugs were found and fixed (an IPv6-literal bypass of the private-IP filter
in `is_ip_safe`, and a panic-on-attacker-input DoS in the path
percent-decoder), plus a body-size cap and Telegram IP filtering were
added. The relay validates all inbound requests against Telegram's published
CIDR ranges (refreshed on a schedule); requests from non-Telegram IPs are
rejected at the edge.

Known residual gaps, accepted rather than fixed:

- **DNS-rebinding**: a domain name that *resolves* to a private/internal
  IP isn't caught (only literal IPs in the URL are checked) — `fetch()`
  gives no hook to validate the resolved address at connect time the way
  the original proxy's custom DNS resolver does. In practice, setting your
  distributor to a real hostname (not a literal IP) mitigates this.
- **Durable Object cost multiplier**: each distinct target-URL string gets
  its own billed Durable Object instance, so varying the target is cheaper
  for an attacker than for the account owner. This is a cost-nuisance risk
  on free tier, not a data or availability risk.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE),
matching the upstream project this was ported from. See [NOTICE](./NOTICE)
for attribution details.
