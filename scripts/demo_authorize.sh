#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

curl --fail-with-body --silent --show-error \
  --request POST "$BASE_URL/v1/authorize" \
  --header "Content-Type: application/json" \
  --header "X-Correlation-Id: demo-authz-request" \
  --data '{
    "subject": {"id": "user:123", "claims": {"role": "analyst"}},
    "action": "read",
    "resource": {
      "type": "report",
      "id": "rpt:9",
      "attrs": {"classification": "cui"}
    },
    "context": {"env": "prod"}
  }' | python3 -m json.tool
