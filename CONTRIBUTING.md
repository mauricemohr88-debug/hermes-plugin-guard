# Contributing

Thanks for helping make Hermes plugin review more repeatable. Small, focused pull requests are
easiest to review.

## Set up a development environment

```bash
git clone https://github.com/mauricemohr88-debug/hermes-plugin-guard.git
cd hermes-plugin-guard
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run the same checks as CI:

```bash
ruff check .
ruff format --check .
pytest --cov=hermes_plugin_guard --cov-report=term-missing
python -m build
```

To apply formatting locally:

```bash
ruff check --fix .
ruff format .
```

## Propose a change

1. Search existing issues and pull requests for related work.
2. Open an issue first for broad behavior changes or rule-ID changes.
3. Create a focused branch and keep unrelated formatting out of the change.
4. Add or update tests.
5. Update the README and changelog when user-visible behavior changes.
6. Explain the threat scenario, expected output, and false-positive tradeoff in the pull request.

## Detection-rule expectations

Rules are a public interface. New or changed rules should:

- use the next stable `HPG` identifier and keep existing IDs unchanged;
- describe observable behavior rather than label a plugin as malicious;
- include a concise remediation;
- report the narrowest useful file and line location;
- have a positive fixture that triggers and a nearby negative fixture that does not;
- avoid importing, executing, resolving, or installing target plugin code;
- stay deterministic and avoid network access;
- document important blind spots and expected false positives.

Prefer Python AST inspection over regular expressions when syntax matters. Secret detection and
non-Python metadata checks may use bounded text matching. Scanners must skip symlinks and handle
malformed or unexpectedly encoded input without crashing the entire run.

## Tests

Use synthetic values in fixtures. Never commit real credentials, private plugin code, or a token
that resembles a live credential more closely than the test requires.

Tests should cover exit behavior and every supported output format when a change touches reporting
or the CLI. Keep ordering deterministic so generated JSON and SARIF are stable.

## Reporting security issues

Follow [SECURITY.md](SECURITY.md). Please do not demonstrate an exploitable scanner issue in a
public issue or pull request before a fix is available.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
