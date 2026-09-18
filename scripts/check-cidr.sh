#!/bin/bash
set -euo pipefail

# Keeps data/telegram-cidrs.txt in sync with Telegram's published list.
# Skips the network entirely if checked within MAX_AGE_DAYS. Otherwise does a
# conditional GET (If-Modified-Since, from the date stored in the timestamp
# file) -- on new content, overwrites the CIDR file and refreshes the
# timestamp; on 304 Not Modified, just refreshes the timestamp. lib.rs picks
# up a changed CIDR file automatically via include_str!, no code change
# needed.
#
# The timestamp file's own mtime is not used for anything: it's committed to
# git, and git resets file mtimes to checkout time on every clone/checkout,
# so mtime can't carry "when was this last checked" across a clone. The date
# has to live in the file's content instead.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIDR_FILE="$REPO_ROOT/data/telegram-cidrs.txt"
TIMESTAMP_FILE="$REPO_ROOT/data/telegram-cidrs.txt.last-checked"
NEW_FILE="$CIDR_FILE.new"
FETCH_URL="https://core.telegram.org/resources/cidr.txt"
MAX_AGE_DAYS=1

source "$SCRIPT_DIR/lib-http-date.sh"

# curl's --time-cond only recognizes a handful of date formats (see
# curl_getdate(3)); anything else is silently treated as a filename, and a
# non-existent filename is silently ignored, so we write and read HTTP-date
# format exactly to avoid retrying to parse it correctly.
write_timestamp() {
  date -u +"%a, %d %b %Y %H:%M:%S GMT" > "$TIMESTAMP_FILE"
}

if [[ -f "$TIMESTAMP_FILE" ]] && [[ $(days_since_http_date_file "$TIMESTAMP_FILE") -le $MAX_AGE_DAYS ]]; then
  echo "CIDR list checked within the last $MAX_AGE_DAYS days ($(cat "$TIMESTAMP_FILE")). Skipping fetch."
  echo "✓ CIDR check passed."
  exit 0
fi

echo "Checking Telegram CIDR list for updates..."

time_cond_args=()
if [[ -f "$TIMESTAMP_FILE" ]]; then
  time_cond_args=(--time-cond "$(cat "$TIMESTAMP_FILE")")
fi

http_code=$(curl -sS -o "$NEW_FILE" -w '%{http_code}' "${time_cond_args[@]}" "$FETCH_URL") || {
  echo "ERROR: Failed to fetch $FETCH_URL"
  rm -f "$NEW_FILE"
  exit 1
}

if [[ "$http_code" == "304" ]] || [[ ! -s "$NEW_FILE" ]]; then
  echo "CIDR list unchanged (304 Not Modified)."
  rm -f "$NEW_FILE"
  write_timestamp
  echo "✓ CIDR check passed."
  exit 0
fi

if [[ "$http_code" != "200" ]]; then
  echo "ERROR: unexpected HTTP status $http_code from $FETCH_URL"
  rm -f "$NEW_FILE"
  exit 1
fi

if [[ -f "$CIDR_FILE" ]] && diff -q "$CIDR_FILE" "$NEW_FILE" >/dev/null 2>&1; then
  echo "CIDR list unchanged."
  rm -f "$NEW_FILE"
else
  echo "CIDR list changed:"
  diff "$CIDR_FILE" "$NEW_FILE" || true
  mv "$NEW_FILE" "$CIDR_FILE"
  echo "Updated $CIDR_FILE."
fi

write_timestamp
echo "✓ CIDR check passed."
