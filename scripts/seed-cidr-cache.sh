#!/usr/bin/env bash
set -euo pipefail

# Puts Telegram's published CIDR list, with a fetched-at timestamp, into the
# CIDR_CACHE KV namespace, so a freshly deployed Worker starts with a warm
# cache instead of every early request fetching the list at once. Run before
# the first deploy; the KV namespace outlives redeploys.
#
# The list is first fetched into a per-user cache directory (CIDR_CACHE_DIR,
# else under XDG_CACHE_HOME, default ~/.cache), and only re-fetched
# (conditionally) once that copy is older than LOCAL_MAX_AGE_SECONDS, so
# repeated seeding or deploying doesn't keep hitting Telegram. The local
# copy's mtime is its fetched-at time, bumped when Telegram confirms the list
# is unchanged. Delete the cache directory to force a fresh fetch.
#
# The upload is skipped if KV already holds a list fetched at or after the
# local copy's fetch time: the Worker refreshes KV itself, and overwriting a
# newer list with an older one would lose that work.
#
# Extra arguments are passed through to `wrangler kv key put/get`, e.g.
# `--local --preview --persist-to <dir>` to target a local dev namespace. The
# default target is whatever wrangler picks for the current config. Wrangler
# runs from the repository root, so relative paths in those arguments are
# relative to it; CIDR_CACHE_DIR is relative to the caller's directory.
#
# The KV key names must match CIDR_LIST_KV_KEY and CIDR_LIST_FETCHED_AT_KV_KEY
# in src/telegram_cidrs.rs, and KV timestamps are milliseconds since the epoch.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FETCH_URL="${CIDR_LIST_URL:-https://core.telegram.org/resources/cidr.txt}"
CACHE_DIR="${CIDR_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME:?set HOME, XDG_CACHE_HOME or CIDR_CACHE_DIR}/.cache}/mg-cloudflare-proxy}"
KV_BINDING="CIDR_CACHE"
LIST_KEY="telegram_cidrs"
FETCHED_AT_KEY="telegram_cidrs_fetched_at"
MILLIS_PER_SECOND=1000
LOCAL_MAX_AGE_SECONDS=$((24 * 60 * 60)) # Matches the Worker's own CIDR_LIST_MAX_AGE.
FETCH_TIMEOUT_SECONDS=30
HTTP_NOT_MODIFIED=304
CIDR_LINE_REGEX='^[0-9a-fA-F:.]+(/[0-9]+)?$'

# Inside the cache directory so that moving a finished file into place is a
# rename, never a partial copy that a later run would mistake for a good list.
mkdir -p "$CACHE_DIR"
CACHE_DIR="$(cd "$CACHE_DIR" && pwd)" # Absolute, since wrangler runs from another directory.
LOCAL_LIST="$CACHE_DIR/telegram-cidrs.txt"
WORK_DIR="$(mktemp -d "$CACHE_DIR/.work.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

# Runs wrangler from the repository root, where wrangler.toml lives.
wrangler() { (cd "$REPO_ROOT" && npx --no-install wrangler "$@"); }

# A file's mtime in seconds since the epoch (GNU stat, else BSD stat).
mtime_seconds() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }

# Prints the local copy's fetched-at (seconds), or nothing if there's no copy.
local_fetched_at() {
  [[ -s "$LOCAL_LIST" ]] || return 0
  mtime_seconds "$LOCAL_LIST"
}

# Sanity check only; the Worker re-validates on every fetch it does itself.
looks_like_cidr_list() {
  grep -qE "$CIDR_LINE_REGEX" "$1" && ! grep -qvE "^[[:space:]]*\$|$CIDR_LINE_REGEX" "$1"
}

# Refreshes the local copy unless it's recent enough.
refresh_local_copy() {
  local fetched_at age
  fetched_at="$(local_fetched_at)"
  if [[ -n "$fetched_at" ]]; then
    age=$(($(date +%s) - fetched_at))
    if ((age >= 0 && age < LOCAL_MAX_AGE_SECONDS)); then
      echo "Local copy is recent enough; not fetching."
      return
    fi
  fi

  local curl_args=(-sS --max-time "$FETCH_TIMEOUT_SECONDS" -o "$WORK_DIR/body" -w '%{http_code}')
  # curl sends the local file's mtime as If-Modified-Since. That's only a true
  # claim when the mtime isn't in the future; otherwise a 304 could vouch for
  # a list we never held.
  if [[ -n "$fetched_at" ]] && ((age >= 0)); then
    curl_args+=(-z "$LOCAL_LIST")
  fi
  local status
  status="$(curl "${curl_args[@]}" "$FETCH_URL")" || {
    echo "ERROR: failed to fetch $FETCH_URL" >&2
    exit 1
  }

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
  if ! value="$(wrangler kv key get --binding "$KV_BINDING" "$FETCHED_AT_KEY" "$@" 2>"$WORK_DIR/kv-get.err")"; then
    echo "WARNING: couldn't read the KV timestamp, so uploading regardless:" >&2
    cat "$WORK_DIR/kv-get.err" >&2
    return 0
  fi
  [[ "$value" =~ ^[0-9]+$ ]] && echo "$value"
  return 0
}

refresh_local_copy
local_at_ms=$(($(local_fetched_at) * MILLIS_PER_SECOND))

kv_at_ms="$(kv_fetched_at "$@")"
if [[ -n "$kv_at_ms" ]] && ((kv_at_ms >= local_at_ms)); then
  echo "KV already holds a list at least as new as the local copy; not uploading."
  exit 0
fi

# List first, timestamp second: a failure between the two leaves a list with
# no (or an older) timestamp, which the Worker treats as needing a refresh,
# never a timestamp vouching for a list that isn't there.
wrangler kv key put --binding "$KV_BINDING" "$LIST_KEY" --path "$LOCAL_LIST" "$@"
wrangler kv key put --binding "$KV_BINDING" "$FETCHED_AT_KEY" "$local_at_ms" "$@"

echo "✓ Seeded $KV_BINDING with $(grep -cE "$CIDR_LINE_REGEX" "$LOCAL_LIST") ranges from $FETCH_URL."
