#!/bin/bash
set -euo pipefail

# Pre-deploy check: verify Telegram CIDR list is current.
# Fetches latest if stale (> 7 days), fails deploy if list changed.

CIDR_FILE="data/telegram-cidrs.txt"
TIMESTAMP_FILE="data/telegram-cidrs.txt.last-checked"
FETCH_URL="https://core.telegram.org/resources/cidr.txt"
MAX_AGE_DAYS=7

# Helper to get file mod time, handling BSD/GNU date
mod_time_days_old() {
  local file="$1"
  if stat --version >/dev/null 2>&1; then
    # GNU stat
    local mtime=$(stat -c %Y "$file")
  else
    # BSD stat
    local mtime=$(stat -f %m "$file")
  fi
  local now=$(date +%s)
  echo $(( (now - mtime) / 86400 ))
}

# Check if we need to fetch (file missing or timestamp stale)
if [[ ! -f "$TIMESTAMP_FILE" ]] || [[ $(mod_time_days_old "$TIMESTAMP_FILE") -gt $MAX_AGE_DAYS ]]; then
  echo "Fetching Telegram CIDR list (last check: $(cat "$TIMESTAMP_FILE" 2>/dev/null || echo 'never'))..."

  if curl -f -s -o "$CIDR_FILE.new" "$FETCH_URL"; then
    # Compare against existing list
    if [[ -f "$CIDR_FILE" ]] && diff -q "$CIDR_FILE" "$CIDR_FILE.new" >/dev/null 2>&1; then
      echo "CIDR list unchanged."
      rm "$CIDR_FILE.new"
    else
      echo "ERROR: CIDR list has changed. Update bootstrap in src/lib.rs:"
      echo "  1. Review changes: diff $CIDR_FILE $CIDR_FILE.new"
      echo "  2. Update src/lib.rs to include new ranges"
      echo "  3. Run: cp $CIDR_FILE.new $CIDR_FILE && date +%Y-%m-%d > $TIMESTAMP_FILE"
      echo "  4. Redeploy"
      exit 1
    fi
  else
    echo "ERROR: Failed to fetch $FETCH_URL"
    exit 1
  fi

  # Update timestamp
  date +%Y-%m-%d > "$TIMESTAMP_FILE"
  echo "Timestamp updated: $(cat $TIMESTAMP_FILE)"
else
  echo "CIDR list is current ($(cat "$TIMESTAMP_FILE")). Skipping fetch."
fi

echo "✓ CIDR check passed."
