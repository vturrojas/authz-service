# Contributing

Contributions should preserve the service's narrow authorization boundary and
deterministic decision semantics.

## Development setup

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
cd ..
make ci
```

## Change expectations

- Keep authentication, token issuance or validation, and action enforcement
  outside this service.
- Base examples on checked-in schemas and policy fixtures.
- Add or update tests before changing behavior. Demonstrate the failing test,
  make the smallest implementation change, and rerun the full quality gate.
- Preserve deny-by-default, explicit-deny precedence, deterministic matched-rule
  ordering, and configured audit fail-closed behavior unless an approved design
  explicitly changes those contracts.
- Update documentation when a public interface or trust assumption changes.
- Do not commit credentials, local audit output, or other generated artifacts.

Before proposing a change, run `make ci` and exercise the documented demo against
a local service.

For possible vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of
opening exploit details in a public issue.
