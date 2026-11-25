#!/usr/bin/env bash
# Live check for a sandbox created with SNYK_COMPONENTS including firewall:
#   cp tests/dependency-firewall-probe.sh /tmp/<workspace>/   (sbx cp leaves it unreadable)
#   sbx exec <sandbox> bash -lc "bash /tmp/<workspace>/dependency-firewall-probe.sh [blocked-npm-pkg]"
# Prints PASS/FAIL per check. Never prints the token or placeholder.
set -u
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@" || true; }

reg="${SNYK_DF_REGISTRY:-}"
[ -n "$reg" ] && ok "SNYK_DF_REGISTRY set" || bad "SNYK_DF_REGISTRY missing (profile not sourced?)"

grep -q "^registry=$reg/npm_portable/" ~/.npmrc 2>/dev/null && ok "npm registry points at Snyk" || bad "npm registry not set"
grep -q '_authToken=${SNYK_DF_TOKEN}' ~/.npmrc && ok ".npmrc holds only a variable reference" || bad ".npmrc auth line unexpected"
case "${PIP_INDEX_URL:-}" in *"/registry/pypi/simple/") ok "pip index points at Snyk";; *) bad "pip index not set";; esac
[ "${UV_DEFAULT_INDEX:-}" = "${PIP_INDEX_URL:-x}" ] && ok "uv index matches pip" || bad "uv index not set"

# Boundary: the public registries must be unreachable.
for u in https://registry.npmjs.org/lodash https://registry.yarnpkg.com/lodash https://pypi.org/simple/requests/ https://files.pythonhosted.org/; do
  c=$(code "$u"); case "$c" in 2*|3*) bad "direct $u reachable ($c)";; *) ok "direct $u blocked ($c)";; esac
done
out=$(npm view lodash version --registry https://registry.npmjs.org 2>&1); rc=$?
[ $rc -ne 0 ] && ok "npm --registry npmjs bypass refused" || bad "npm bypass succeeded: $out"
out=$(pip download --no-deps -d /tmp/pipdl --index-url https://pypi.org/simple requests 2>&1); rc=$?
[ $rc -ne 0 ] && ok "pip --index-url pypi.org bypass refused" || bad "pip bypass succeeded"

# Token hygiene: whatever the sandbox holds must not be a real Snyk token.
t="${SNYK_DF_TOKEN:-}"
if [ -z "$t" ]; then echo "INFO  SNYK_DF_TOKEN not wired (expected before the custom secret is set)"
else
  case "$t" in snyk_*|sny*) bad "SNYK_DF_TOKEN looks like a real token";; *) ok "SNYK_DF_TOKEN is a placeholder";; esac
fi

# Auth path: the Snyk registry should see an authenticated request.
#   401 = no/invalid credential reached Snyk
#   403 "not enabled for tenant" = credential reached Snyk, tenant lacks entitlement
#   200 = working end to end
for eco in npm pypi; do
  if [ $eco = npm ]; then body=$(curl -s --max-time 20 -H "Authorization: Bearer ${t}" "$reg/npm_portable/lodash")
  else body=$(curl -s --max-time 20 -u "snyk:${t}" "$reg/pypi/simple/requests/"); fi
  c=$(printf '%s' "$body" | grep -o '"status":"[0-9]*"' | head -1)
  detail=$(printf '%s' "$body" | grep -o '"detail":"[^"]*"' | head -1)
  echo "INFO  $eco via Snyk: ${c:-200-ish} ${detail}"
done
npm view lodash version >/tmp/npmview 2>&1 && ok "npm view lodash via firewall ($(cat /tmp/npmview))" || echo "INFO  npm view lodash: $(grep -m1 -E 'E[0-9]{3}|403|401' /tmp/npmview)"
pip download --no-deps -d /tmp/pipdl requests >/tmp/pipdl.log 2>&1 && ok "pip download requests via firewall" || echo "INFO  pip download requests: $(grep -m1 -iE '40[13]|error' /tmp/pipdl.log)"

if [ -n "${1:-}" ]; then
  npm view "$1" >/tmp/mal 2>&1 && bad "blocked package $1 resolved" || ok "blocked package $1 refused: $(grep -m1 -E 'E[0-9]{3}' /tmp/mal)"
fi
echo "summary: $pass pass, $fail fail"
