#!/bin/bash
set -euo pipefail

# Puts Telegram's published CIDR list, with a fetched-at timestamp, into the
# CIDR_CACHE KV namespace, so a freshly deployed Worker starts with a warm
# cache instead of every early request fetching the list at once. Run before
# the first deploy; the KV namespace outlives redeploys.
#
# The list is first fetched into a per-user cache directory (under
# XDG_CACHE_HOME, default ~/.cache), and only re-fetched (conditionally) once
# that copy is older than LOCAL_MAX_AGE_SECONDS, so repeated seeding or
# deploying doesn't keep hitting Telegram. The local copy's mtime is its
# fetched-at time (bumped when Telegram confirms the list is unchanged).
# Delete the cache directory to force a fresh fetch.
#
# The upload is skipped if KV already holds a list fetched at or after the
# local copy's fetch time: the Worker refreshes KV itself, and overwriting a
# newer list with an older one would lose that work.
#
# Extra arguments are passed through to `wrangler kv key put/get`, e.g.
# `--local --preview --persist-to <dir>` to target a local dev namespace. The
# default target is whatever wrangler picks for the current config.
#
# The KV key names must match CIDR_LIST_KV_KEY and CIDR_LIST_FETCHED_AT_KV_KEY
# in src/telegram_cidrs.rs, and timestamps are milliseconds since the epoch.
# Needs GNU `date` and `stat` (for `-d` and `-c`).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" # Wrangler finds wrangler.toml from here.
FETCH_URL="${CIDR_LIST_URL:-https://core.telegram.org/resources/cidr.txt}"
CACHE_DIR="${CIDR_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/mg-cloudflare-relay}"
LOCAL_LIST="$CACHE_DIR/telegram-cidrs.txt"
KV_BINDING="CIDR_CACHE"
LIST_KEY="telegram_cidrs"
FETCHED_AT_KEY="telegram_cidrs_fetched_at"
MILLIS_PER_SECOND=1000
LOCAL_MAX_AGE_SECONDS=$((24 * 60 * 60)) # Matches the Worker's own CIDR_LIST_MAX_AGE.
FETCH_TIMEOUT_SECONDS=30
HTTP_NOT_MODIFIED=304

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

now_millis() { echo $(($(date +%s) * MILLIS_PER_SECOND)); }

# Prints the local copy's fetched-at (ms), or nothing if there's no usable copy.
local_fetched_at() {
  [[ -s "$LOCAL_LIST" ]] || return 0
  echo $(($(stat -c %Y "$LOCAL_LIST") * MILLIS_PER_SECOND))
}

# Sanity check only; the Worker re-validates on every fetch it does itself.
looks_like_cidr_list() {
  grep -qE '^[0-9a-fA-F:.]+(/[0-9]+)?$' "$1" \
    && ! grep -vE '^[[:space:]]*$|^[0-9a-fA-F:.]+(/[0-9]+)?$' "$1" | grep -q .
}

# Refreshes the local copy unless it's recent enough.
refresh_local_copy() {
  local fetched_at
  fetched_at="$(local_fetched_at)"
  if [[ -n "$fetched_at" ]] && (($(now_millis) - fetched_at < LOCAL_MAX_AGE_SECONDS * MILLIS_PER_SECOND)); then
    echo "Local copy is recent enough; not fetching."
    return
  fi

  local curl_args=(-sS --max-time "$FETCH_TIMEOUT_SECONDS" -o "$WORK_DIR/body" -w '%{http_code}')
  if [[ -n "$fetched_at" ]]; then
    # Only ever a real fetch time, so a 304 can't vouch for a list we never got.
    curl_args+=(-H "If-Modified-Since: $(TZ=UTC date -d "@$((fetched_at / MILLIS_PER_SECOND))" '+%a, %d %b %Y %H:%M:%S GMT')")
  fi
  local status
  status="$(curl "${curl_args[@]}" "$FETCH_URL")" || {
    echo "ERROR: failed to fetch $FETCH_URL" >&2
    exit 1
  }

  mkdir -p "$CACHE_DIR"
  if [[ "$status" == "$HTTP_NOT_MODIFIED" && -n "$fetched_at" ]]; then
    echo "Telegram's list is unchanged."
    touch "$LOCAL_LIST"
  elif [[ "$status" == 2?? ]]; then
    tr -d '\r' <"$WORK_DIR/body" >"$WORK_DIR/clean"
    if ! looks_like_cidr_list "$WORK_DIR/clean"; then
      echo "ERROR: $FETCH_URL did not return a plain list of CIDR ranges" >&2
      exit 1
    fi
    mv "$WORK_DIR/clean" "$LOCAL_LIST"
  else
    echo "ERROR: $FETCH_URL returned HTTP $status" >&2
    exit 1
  fi
}

# Prints the fetched-at (ms) KV currently holds, or nothing if it has none.
kv_fetched_at() {
  local value
  value="$(npx wrangler kv key get --binding "$KV_BINDING" "$FETCHED_AT_KEY" "$@" 2>/dev/null)" || return 0
  [[ "$value" =~ ^[0-9]+$ ]] && echo "$value"
  return 0
}

refresh_local_copy
local_at="$(local_fetched_at)"

kv_at="$(kv_fetched_at "$@")"
if [[ -n "$kv_at" ]] && ((kv_at >= local_at)); then
  echo "KV already holds a list at least as new as the local copy; not uploading."
  exit 0
fi

# List first, timestamp second: a failure between the two leaves a list with
# no (or an older) timestamp, which the Worker treats as needing a refresh,
# never a timestamp vouching for a list that isn't there.
npx wrangler kv key put --binding "$KV_BINDING" "$LIST_KEY" --path "$LOCAL_LIST" "$@"
npx wrangler kv key put --binding "$KV_BINDING" "$FETCHED_AT_KEY" "$local_at" "$@"

echo "✓ Seeded $KV_BINDING with $(grep -cE '^[0-9a-fA-F:.]+' "$LOCAL_LIST") ranges from $FETCH_URL."
