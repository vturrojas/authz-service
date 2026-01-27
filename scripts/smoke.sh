#!/usr/bin/env bash
set -euo pipefail

# Simple smoke test for AuthZ Service
# Assumes the service is already running on localhost:8000

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:8000}"
POLICY_PATH="${AUTHZ_POLICY_PATH:-$ROOT_DIR/policies/sample_policy.json}"
AUDIT_PATH="${AUTHZ_AUDIT_PATH:-$ROOT_DIR/audit.jsonl}"
rm -f "$AUDIT_PATH"

have() { command -v "$1" >/dev/null 2>&1; }
hr() { echo "------------------------------------------------------------"; }

echo "AuthZ Service smoke test"
hr
echo "API_BASE_URL=$API_BASE_URL"
echo "AUTHZ_POLICY_PATH=$POLICY_PATH"
echo "AUTHZ_AUDIT_PATH=$AUDIT_PATH"
hr

if ! have curl; then
  echo "ERROR: curl is required"
  exit 1
fi

echo "[1/4] Health check"
health_headers="$(curl -sS -D - "$API_BASE_URL/healthz" || true)"
status_line="$(echo "$health_headers" | head -n 1)"
echo "$status_line"
if [[ "$status_line" != *"200"* ]]; then
  echo "Health check failed. Is the server running?"
  exit 1
fi
echo

echo "[2/4] Authorize allow-case (expects allow)"
CID_ALLOW="smoke-allow-$(date +%s)"
ALLOW_PAYLOAD='{
  "subject": {"id":"user:123","claims":{"role":"analyst"}},
  "action":"read",
  "resource":{"type":"report","id":"rpt:9","attrs":{"classification":"cui"}},
  "context":{"env":"dev"}
}'

ALLOW_RESPONSE="$(curl -sS -D - \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: $CID_ALLOW" \
  -X POST "$API_BASE_URL/v1/authorize" \
  -d "$ALLOW_PAYLOAD")"

echo "$ALLOW_RESPONSE" | head -n 20
echo

echo "[3/4] Authorize deny-case (expects deny if policy has prod deny rule)"
CID_DENY="smoke-deny-$(date +%s)"
DENY_PAYLOAD='{
  "subject": {"id":"user:123","claims":{"role":"analyst"}},
  "action":"read",
  "resource":{"type":"report","id":"rpt:9","attrs":{"classification":"cui"}},
  "context":{"env":"prod"}
}'

DENY_RESPONSE="$(curl -sS -D - \
  -H "Content-Type: application/json" \
  -H "X-Correlation-Id: $CID_DENY" \
  -X POST "$API_BASE_URL/v1/authorize" \
  -d "$DENY_PAYLOAD")"

echo "$DENY_RESPONSE" | head -n 20
echo

echo "[4/4] Audit check"
if [[ -f "$AUDIT_PATH" ]]; then
  echo "Audit file exists: $AUDIT_PATH"
  echo "Last 3 audit lines:"
  tail -n 3 "$AUDIT_PATH"
  echo
  echo "Correlation ID lookups:"
  grep "$CID_ALLOW" "$AUDIT_PATH" || true
  grep "$CID_DENY" "$AUDIT_PATH" || true
else
  echo "Audit file not found at: $AUDIT_PATH"
  echo "Did you start the server with AUTHZ_AUDIT_PATH set?"
fi

hr
echo "Smoke test complete"
