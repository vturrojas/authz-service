# AuthZ Service (Policy-Driven Authorization)

A small backend service that makes deterministic authorization decisions from
explicit inputs (subject, action, resource, context) and records an auditable
decision trail.

This project is intentionally not an IAM platform.

---

## Purpose

Authorization is treated as a first-class backend domain:
- Explicit decision inputs
- Deny-by-default semantics
- Policy evaluation separated from enforcement
- Deterministic, auditable decisions

---

## Non-goals

- Not an identity system (no users, orgs, groups, SCIM)
- Not an authentication system (no login, MFA, sessions, SSO)
- Not a token authority or IdP
- Not a general-purpose policy engine or DSL
- Not an enterprise IAM product
- Not a security-marketing exercise

Rule of thumb:
If a feature models people or organizations more than decisions, it is out of scope.

---

## API (v0)

POST /v1/authorize

Inputs:
- subject
- action
- resource
- context

Outputs:
- decision (allow | deny)
- reason
- decision_id
- policy_version
- matched_rule_ids

---

## Policy model

- Ordered rules
- Effects: allow, deny
- Default: deny
- Explicit deny overrides allow
- Policy files are JSON
- Schema is strict (extra=forbid)
- Policy parsing converts DTO → domain model
- Active policy is loaded from AUTHZ_POLICY_PATH
- Reload uses file mtime checks; no watchers
- This is intentionally single-policy v0

---

## Evaluation semantics

- Deterministic
- Deny-by-default
- Same inputs + same policy set => same decision

--

## Audit trail

Each decision produces an append-only audit record including:
- inputs
- decision
- reason
- policy version
- timestamp
- correlation / decision id

---

## Tradeoffs

- Correctness favored over latency (no caching initially)
- Simplicity favored over expressiveness
- Operator usefulness favored over exhaustiveness

---

## Project layout

backend/app/domain   -> pure decision logic
backend/app/api      -> HTTP routes only
backend/app/services -> orchestration
backend/app/db       -> persistence
backend/tests        -> tests

---

## Operational conventions

Correlation ID: X-Correlation-Id accepted + echoed on all responses
Included in:
error bodies
audit records
Errors: {"error": {"code","message","details?","correlation_id"}}
Audit behavior: if auditing enabled and write fails → 500 (no silent loss)

---

## Quick smoke test

1. Start the service:
```bash
cd backend
export AUTHZ_POLICY_PATH=../policies/sample_policy.json
export AUTHZ_AUDIT_PATH=../audit.jsonl
fastapi dev app/main.py
```

2. Run:
```bash
./scripts/smoke.sh
```
