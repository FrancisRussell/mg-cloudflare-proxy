#!/usr/bin/env bash
set -euo pipefail

# Deploys the Worker to the Cloudflare account wrangler is logged in to,
# without any per-account edits to wrangler.toml.
#
# The CIDR cache's KV namespace is found by its title, or created if the
# account has none, so deploying from a fresh clone reuses the existing
# namespace instead of making another. Its ID goes into a generated copy of
# wrangler.toml (git-ignored), which is what gets deployed. The cache is then
# seeded (see seed-cidr-cache.sh), and a failure there only costs the Worker a
# fetch of its own.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# The binding must match the `[[kv_namespaces]]` binding in wrangler.toml.
KV_BINDING="CIDR_CACHE"
NAMESPACE_TITLE="mercurygram-proxy-cidr-cache"
# Relative to the repository root, so that wrangler resolves the config's
# relative paths (the built Worker) the same way as for wrangler.toml itself.
DEPLOY_CONFIG="wrangler.deploy.toml"

# Runs wrangler from the repository root, where wrangler.toml lives.
wrangler() { (cd "$REPO_ROOT" && npx --no-install wrangler "$@"); }

# Prints the ID of the namespace titled $NAMESPACE_TITLE, or nothing if the
# account has none. Wrangler may print a banner before the JSON list, so the
# list is taken to start at the first line that begins with a bracket.
find_namespace_id() {
  wrangler kv namespace list | node -e '
    const output = require("fs").readFileSync(0, "utf8");
    const start = output.search(/^\[/m);
    if (start < 0) process.exit(1);
    const found = JSON.parse(output.slice(start)).find((ns) => ns.title === process.argv[1]);
    if (found) console.log(found.id);
  ' "$NAMESPACE_TITLE"
}

namespace_id="$(find_namespace_id)"
if [[ -z "$namespace_id" ]]; then
  echo "Creating KV namespace \"$NAMESPACE_TITLE\"."
  wrangler kv namespace create "$NAMESPACE_TITLE"
  namespace_id="$(find_namespace_id)"
fi
if [[ -z "$namespace_id" ]]; then
  echo "ERROR: KV namespace \"$NAMESPACE_TITLE\" wasn't found, even after creating it." >&2
  exit 1
fi

# Adds the namespace ID to the binding's table.
awk -v binding="binding = \"$KV_BINDING\"" -v id="$namespace_id" '
  { print }
  $0 == binding { print "id = \"" id "\"" }
' "$REPO_ROOT/wrangler.toml" >"$REPO_ROOT/$DEPLOY_CONFIG"
if ! grep -q "^id = \"$namespace_id\"\$" "$REPO_ROOT/$DEPLOY_CONFIG"; then
  echo "ERROR: couldn't add the namespace ID to the $KV_BINDING binding; is it in wrangler.toml?" >&2
  exit 1
fi

bash "$SCRIPT_DIR/seed-cidr-cache.sh" --config "$DEPLOY_CONFIG" --remote ||
  echo "WARNING: seeding the CIDR cache failed; the Worker will fetch the list itself." >&2

wrangler deploy --config "$DEPLOY_CONFIG"
