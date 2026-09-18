#!/bin/bash
set -euo pipefail

# Fails the build if data/telegram-cidrs.txt.last-checked is more than
# MAX_AGE_DAYS old. Run via wrangler.toml's [build] command, so every
# dev/deploy catches a neglected bootstrap before it ships. Does no network
# I/O itself -- a build step reaching out to a third-party endpoint is
# fragile (no guarantee of network access, and non-deterministic even when
# there is), so refreshing the file is a separate, deliberate action
# (scripts/check-cidr.sh, run manually or by periodic CI) rather than
# something the build does automatically.
#
# MAX_AGE_DAYS is tighter than it strictly needs to be: this timestamp also
# doubles as the runtime's own starting point for its 30-day
# CIDR_LIST_FORCE_REFETCH_MAX_AGE clock whenever nothing's cached yet (see
# src/telegram_cidrs.rs), so a stale bootstrap at deploy time eats directly
# into that budget. Keeping this well under 30 days preserves most of the
# margin that number was chosen for.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP_FILE="$REPO_ROOT/data/telegram-cidrs.txt.last-checked"
MAX_AGE_DAYS=14

source "$SCRIPT_DIR/lib-http-date.sh"

if [[ ! -f "$TIMESTAMP_FILE" ]]; then
  echo "ERROR: $TIMESTAMP_FILE is missing. Run \`npm run check-cidr\` (needs network access) to create it." >&2
  exit 1
fi

age_days=$(days_since_http_date_file "$TIMESTAMP_FILE")

if (( age_days > MAX_AGE_DAYS )); then
  echo "ERROR: data/telegram-cidrs.txt is $age_days days stale (last checked $(cat "$TIMESTAMP_FILE"))." >&2
  echo "Run \`npm run check-cidr\` (needs network access) to refresh it." >&2
  exit 1
fi

echo "✓ CIDR bootstrap data is $age_days days old (within the ${MAX_AGE_DAYS}-day limit)."
