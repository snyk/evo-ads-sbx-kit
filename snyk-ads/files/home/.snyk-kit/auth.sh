#!/bin/sh
# An explicit push key selects enterprise authentication.
if [ -n "${SNYK_ADS_PUSH_KEY:-}" ]; then
  if ! printf '%s' "${SNYK_TENANT_ID:-}" | grep -Eqi '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    echo "snyk-ads: ERROR enterprise authentication requires a valid SNYK_TENANT_ID UUID." >&2
    exit 1
  fi
  echo enterprise
elif [ -n "${SNYK_TOKEN:-}" ]; then
  echo standalone
else
  echo "snyk-ads: ERROR set SNYK_TOKEN, or SNYK_TENANT_ID and SNYK_ADS_PUSH_KEY." >&2
  exit 1
fi
