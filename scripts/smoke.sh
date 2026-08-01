#!/usr/bin/env bash
set -euo pipefail

# Simple smoke test for AuthZ Service
# Assumes the service is already running on localhost:8000

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:8000}"
POLICY_PATH="${AUTHZ_POLICY_PATH:-$ROOT_DIR/policies/sample_policy.json}"
AUDIT_PATH="${AUTHZ_AUDIT_PATH:-$ROOT_DIR/audit.jsonl}"
rm -f "$AUDIT_PATH"

SMOKE_TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$SMOKE_TMP_DIR"' EXIT

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

if ! have python3; then
  echo "ERROR: python3 is required"
  exit 1
fi

echo "[1/4] Health check"
curl --fail-with-body --silent --show-error \
  --output "$SMOKE_TMP_DIR/health.json" \
  "$API_BASE_URL/healthz"
python3 - "$SMOKE_TMP_DIR/health.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)

if response != {"ok": True}:
    raise SystemExit(f"Unexpected health response: {response!r}")
PY
python3 -m json.tool "$SMOKE_TMP_DIR/health.json"
echo

echo "[2/4] Authorize allow-case (expects allow)"
CID_ALLOW="smoke-allow-$(date +%s)"
ALLOW_PAYLOAD='{
  "subject": {"id":"user:123","claims":{"role":"analyst"}},
  "action":"read",
  "resource":{"type":"report","id":"rpt:9","attrs":{"classification":"cui"}},
  "context":{"env":"dev"}
}'

curl --fail-with-body --silent --show-error \
  --dump-header "$SMOKE_TMP_DIR/allow.headers" \
  --output "$SMOKE_TMP_DIR/allow.json" \
  --header "Content-Type: application/json" \
  --header "X-Correlation-Id: $CID_ALLOW" \
  --request POST "$API_BASE_URL/v1/authorize" \
  --data "$ALLOW_PAYLOAD"

python3 - "$SMOKE_TMP_DIR/allow.json" "$SMOKE_TMP_DIR/allow.headers" "$CID_ALLOW" <<'PY'
import json
import sys

body_path, headers_path, correlation_id = sys.argv[1:]
with open(body_path, encoding="utf-8") as response_file:
    response = json.load(response_file)

expected = {
    "decision": "allow",
    "reason": "matched_allow",
    "matched_rule_ids": ["allow-analyst-read-report"],
    "policy_id": "sample-policy",
    "policy_version": "v0",
}
for field, value in expected.items():
    if response.get(field) != value:
        raise SystemExit(
            f"Allow response mismatch for {field}: expected {value!r}, got {response.get(field)!r}"
        )

with open(headers_path, encoding="utf-8") as headers_file:
    headers = headers_file.read().splitlines()
actual_correlation_ids = [
    line.split(":", 1)[1].strip()
    for line in headers
    if line.lower().startswith("x-correlation-id:")
]
if actual_correlation_ids != [correlation_id]:
    raise SystemExit(
        f"Allow correlation ID mismatch: expected {correlation_id!r}, got {actual_correlation_ids!r}"
    )
PY
python3 -m json.tool "$SMOKE_TMP_DIR/allow.json"
echo

echo "[3/4] Authorize deny-case (expects deny if policy has prod deny rule)"
CID_DENY="smoke-deny-$(date +%s)"
DENY_PAYLOAD='{
  "subject": {"id":"user:123","claims":{"role":"analyst"}},
  "action":"read",
  "resource":{"type":"report","id":"rpt:9","attrs":{"classification":"cui"}},
  "context":{"env":"prod"}
}'

curl --fail-with-body --silent --show-error \
  --dump-header "$SMOKE_TMP_DIR/deny.headers" \
  --output "$SMOKE_TMP_DIR/deny.json" \
  --header "Content-Type: application/json" \
  --header "X-Correlation-Id: $CID_DENY" \
  --request POST "$API_BASE_URL/v1/authorize" \
  --data "$DENY_PAYLOAD"

python3 - "$SMOKE_TMP_DIR/deny.json" "$SMOKE_TMP_DIR/deny.headers" "$CID_DENY" <<'PY'
import json
import sys

body_path, headers_path, correlation_id = sys.argv[1:]
with open(body_path, encoding="utf-8") as response_file:
    response = json.load(response_file)

expected = {
    "decision": "deny",
    "reason": "explicit_deny",
    "matched_rule_ids": [
        "allow-analyst-read-report",
        "deny-prod-analyst-read-report",
    ],
    "policy_id": "sample-policy",
    "policy_version": "v0",
}
for field, value in expected.items():
    if response.get(field) != value:
        raise SystemExit(
            f"Deny response mismatch for {field}: expected {value!r}, got {response.get(field)!r}"
        )

with open(headers_path, encoding="utf-8") as headers_file:
    headers = headers_file.read().splitlines()
actual_correlation_ids = [
    line.split(":", 1)[1].strip()
    for line in headers
    if line.lower().startswith("x-correlation-id:")
]
if actual_correlation_ids != [correlation_id]:
    raise SystemExit(
        f"Deny correlation ID mismatch: expected {correlation_id!r}, got {actual_correlation_ids!r}"
    )
PY
python3 -m json.tool "$SMOKE_TMP_DIR/deny.json"
echo

echo "[4/4] Audit check"
if [[ ! -s "$AUDIT_PATH" ]]; then
  echo "ERROR: audit output is missing or empty at: $AUDIT_PATH"
  echo "Start the service with AUTHZ_AUDIT_PATH set to the same path."
  exit 1
fi

python3 - "$AUDIT_PATH" "$CID_ALLOW" "$CID_DENY" <<'PY'
import json
import sys

audit_path, allow_correlation_id, deny_correlation_id = sys.argv[1:]
records = []
with open(audit_path, encoding="utf-8") as audit_file:
    for line_number, line in enumerate(audit_file, start=1):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise SystemExit(f"Invalid audit JSON on line {line_number}: {error}") from error

expected_by_correlation_id = {
    allow_correlation_id: {
        "decision": "allow",
        "reason": "matched_allow",
        "matched_rule_ids": ["allow-analyst-read-report"],
        "policy_id": "sample-policy",
        "policy_version": "v0",
    },
    deny_correlation_id: {
        "decision": "deny",
        "reason": "explicit_deny",
        "matched_rule_ids": [
            "allow-analyst-read-report",
            "deny-prod-analyst-read-report",
        ],
        "policy_id": "sample-policy",
        "policy_version": "v0",
    },
}

for correlation_id, expected in expected_by_correlation_id.items():
    matches = [record for record in records if record.get("correlation_id") == correlation_id]
    if len(matches) != 1:
        raise SystemExit(
            f"Expected one audit record for {correlation_id!r}, found {len(matches)}"
        )
    record = matches[0]
    for field, value in expected.items():
        if record.get(field) != value:
            raise SystemExit(
                f"Audit mismatch for {correlation_id!r} field {field}: "
                f"expected {value!r}, got {record.get(field)!r}"
            )
PY

echo "Audit file verified: $AUDIT_PATH"
tail -n 2 "$AUDIT_PATH"

hr
echo "Smoke test complete"
