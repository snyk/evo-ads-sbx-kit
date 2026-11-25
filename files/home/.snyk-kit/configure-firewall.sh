#!/bin/sh
# Points npm, pip and uv at the tenant's Snyk Dependency Firewall registry.
# Runs as root from the kit's install hook. Writes no credential: the npm
# config references ${SNYK_DF_TOKEN} and the pip/uv index is built from it in
# each new agent shell, so only the variable (ideally an sbx custom-secret
# placeholder) ever reaches disk. SNYK_DF_TOKEN is the only name read: an sbx
# custom secret sets it for every sandbox process, which a shell-profile
# fallback could not.
#
# Inputs: SNYK_TENANT_ID (required), SNYK_API (optional, default
# https://api.snyk.io). SNYK_DF_NPMRC and SNYK_DF_PROFILE override the target
# files for tests.
set -eu

if [ -z "${SNYK_TENANT_ID:-}" ]; then
  echo "snyk-df: firewall requested but SNYK_TENANT_ID is not set; skipping Dependency Firewall configuration. Set SNYK_TENANT_ID and recreate the sandbox to enable it."
  exit 0
fi
case "$SNYK_TENANT_ID" in
  *[!0-9a-fA-F-]*)
    echo "snyk-df: ERROR SNYK_TENANT_ID must be a tenant UUID." >&2
    exit 1
    ;;
esac

api="${SNYK_API:-https://api.snyk.io}"
api="${api%/}"
case "$api" in
  https://*) ;;
  *) echo "snyk-df: ERROR SNYK_API must be an https:// URL." >&2; exit 1 ;;
esac

registry="$api/hidden/tenants/$SNYK_TENANT_ID/registry"
host_path="${registry#https://}"
npmrc="${SNYK_DF_NPMRC:-/home/agent/.npmrc}"
profile="${SNYK_DF_PROFILE:-/etc/sandbox-persistent.sh}"

# npm_portable keeps tarball URLs under the tenant registry, so lockfiles
# never point at registry.npmjs.org. npm expands ${SNYK_DF_TOKEN} at run time.
mkdir -p "$(dirname "$npmrc")"
cat > "$npmrc" <<NPMRC
registry=$registry/npm_portable/
//$host_path/npm_portable/:_authToken=\${SNYK_DF_TOKEN}
NPMRC
chmod 0600 "$npmrc"
if [ "$(id -u)" = 0 ] && [ -z "${SNYK_DF_NPMRC:-}" ]; then
  chown 1000:1000 "$npmrc"
fi

# pip and uv take the index from the environment. Docker sources this file
# in every new agent shell, before nvm.
touch "$profile"
tmp="$profile.snyk-df.$$"
sed '/^# snyk-df begin$/,/^# snyk-df end$/d' "$profile" > "$tmp"
cat >> "$tmp" <<PROFILE
# snyk-df begin
export SNYK_DF_REGISTRY="$registry"
export PIP_INDEX_URL="https://snyk:\${SNYK_DF_TOKEN:-}@$host_path/pypi/simple/"
export UV_INDEX_URL="\$PIP_INDEX_URL"
export UV_DEFAULT_INDEX="\$PIP_INDEX_URL"
# snyk-df end
PROFILE
cat "$tmp" > "$profile"
rm -f "$tmp"

echo "snyk-df: npm, pip and uv resolve through $registry"
