# Security policy

## Supported versions

Security fixes are provided for the latest released minor version.

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | No |
| Earlier or unreleased snapshots | No |

Before reporting, please reproduce the issue against the latest release or the default branch
when it is safe to do so.

## Report a vulnerability privately

Do not open a public issue for a vulnerability, a scanner bypass with immediate security impact,
or exposed credentials.

Use the repository's
[private vulnerability reporting form](https://github.com/mauricemohr88-debug/hermes-plugin-guard/security/advisories/new).
Include:

- the affected version or commit;
- a concise impact statement;
- minimal reproduction steps or a safe test fixture;
- affected platforms and Python versions, if relevant;
- any mitigation you have already tested.

Never include live tokens, private keys, personal data, or proprietary plugin source. Replace
secrets with unmistakably fake values.

Reports are handled on a best-effort basis. The maintainer aims to acknowledge a complete report
within seven days, then coordinate validation, remediation, and disclosure with the reporter.
Please allow a reasonable remediation window before public disclosure.

## In scope

Examples include:

- executing or importing target plugin code during a scan;
- reading outside the requested scan root unexpectedly;
- following symlinks into sensitive locations;
- code execution, arbitrary file writes, or unsafe parsing caused by crafted scan input;
- materially incorrect SARIF or exit behavior that defeats a configured security gate;
- a reliable evasion of a documented rule where the implementation claims coverage.

False positives, feature requests, unsupported obfuscation techniques, and new heuristic ideas
without an immediate vulnerability can be reported through the public issue tracker.

## Scanner safety boundary

Hermes Plugin Guard is static analysis, not a sandbox or malware detector. A clean result is not a
security guarantee. Do not enable an untrusted plugin solely because it passes this scanner.
