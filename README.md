# Hermes Plugin Guard

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab.svg)](pyproject.toml)

![Hermes Plugin Guard social card](https://raw.githubusercontent.com/mauricemohr88-debug/hermes-plugin-guard/main/docs/social-card.svg)

Review a Hermes Agent plugin before you enable it.

Hermes Plugin Guard (`hpg`) is a local static scanner for
[NousResearch Hermes Agent](https://github.com/NousResearch/hermes-agent) plugins. It
checks plugin manifests, Python source, dependency declarations, likely secret material, and
basic repository hygiene. Target plugin code is read as data: it is never imported or executed.

This is an unofficial community project. It is not affiliated with, endorsed by, or maintained
by Nous Research.

## Why this exists

Hermes plugins are Python extensions, not isolated data files. A third-party plugin can register
tools and hooks and can run with the permissions of the Hermes process. Code review remains the
most important control; `hpg` adds a fast, repeatable first pass before enablement and in CI.

The scanner is designed to make high-risk patterns visible, including:

- direct subprocess calls that bypass Hermes' terminal-tool approval path;
- dynamic execution and unsafe deserialization;
- sensitive-path access, destructive filesystem operations, and disabled TLS verification;
- all-interface listeners, networking capability, and undeclared secret environment variables;
- privileged registration surfaces and work performed during import or registration;
- likely committed credentials and mutable remote dependencies;
- manifest drift, missing tests, and missing project policies.

## Install

Python 3.11 or newer is required.

Install the current release directly from GitHub with
[pipx](https://pipx.pypa.io/stable/) (recommended for command-line tools):

```bash
pipx install \
  "git+https://github.com/mauricemohr88-debug/hermes-plugin-guard.git@v0.1.0"
```

Or install from a local checkout:

```bash
git clone https://github.com/mauricemohr88-debug/hermes-plugin-guard.git
cd hermes-plugin-guard
python -m pip install .
```

Both `hpg` and `hermes-plugin-guard` invoke the same command.

## Usage

Scan one plugin directory:

```bash
hpg scan /path/to/my-plugin
```

Scan a repository containing multiple plugins and fail when a high or critical finding exists:

```bash
hpg scan /path/to/plugins-repository --fail-on high
```

Write machine-readable results:

```bash
hpg scan ./my-plugin --format json --output hpg.json
hpg scan ./my-plugin --format sarif --output hpg.sarif
```

Show GitHub workflow annotations:

```bash
hpg scan ./my-plugin --format github
```

Exclude a reviewed rule for one invocation:

```bash
hpg scan ./my-plugin --exclude HPG106 --exclude HPG203
```

List the complete rule catalog and remediation guidance:

```bash
hpg rules
```

The default failure threshold is `high`. Use `--fail-on critical`, `high`, `medium`,
`low`, `info`, or `none` to set policy. Exit code `0` means no finding reached the selected
threshold, `1` means the policy threshold was reached, and `2` indicates an invocation or scan
error.

## Output

`hpg` keeps rule IDs stable so findings can be discussed and tracked across runs.

| Format | Intended use |
| --- | --- |
| `text` | Human-readable local review (default) |
| `github` | File and line annotations in GitHub Actions logs |
| `json` | Automation, baselines, and custom reporting |
| `sarif` | SARIF-compatible code-scanning consumers |

JSON includes the scan root, plugin and file counts, severity totals, sorted findings, and a
stable fingerprint for each finding. SARIF includes rule metadata and source locations. Output is
deterministic for unchanged inputs.

## GitHub Actions

The repository includes a composite action:

```yaml
name: Plugin security

on:
  pull_request:

permissions:
  contents: read

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: mauricemohr88-debug/hermes-plugin-guard@v0.1.0
        with:
          path: path/to/plugin
          fail-on: high
          format: github
```

For stronger supply-chain controls, pin `hermes-plugin-guard` to a reviewed full commit SHA
instead of a moving tag.

Maintainers of this repository can copy the pinned
[`examples/ci.yml`](examples/ci.yml) template to `.github/workflows/ci.yml` to run the project's
lint, test, coverage, and packaging matrix on Python 3.11–3.13.

## Rules at a glance

| IDs | Area | Examples |
| --- | --- | --- |
| `HPG001`–`HPG006` | Manifest | Missing or invalid manifest, unknown kind, entry point and hook drift |
| `HPG101`–`HPG111` | Python | Execution, deserialization, processes, sensitive paths, network and privileged behavior |
| `HPG201`–`HPG203` | Supply chain | Likely secrets, mutable remote dependencies, unbounded versions |
| `HPG301`–`HPG303` | Project | License, security policy, and automated tests |

Run `hpg rules` for the current severity, explanation, and suggested remediation for every rule.

## Threat model

The scanner assumes a plugin directory may be untrusted and inspects it without importing its
Python modules. It aims to catch explicit, statically visible patterns that deserve human review.
It also helps maintainers enforce a consistent minimum policy in pull requests.

Scanning is a review aid, not a sandbox, signature verifier, malware detector, or proof that a
plugin is safe. Enabling a plugin still grants its code the permissions of the Hermes process.
Review the source, dependencies, requested environment variables, network destinations, and
maintainer history before installation.

## Limitations

- Static analysis cannot reliably resolve dynamically constructed names, paths, commands, or
  network destinations.
- A finding describes a risky capability or pattern, not necessarily a vulnerability.
- The absence of findings does not establish safety.
- Secret matching is heuristic and may produce false positives or miss encoded or split secrets.
- Dependency checks inspect declarations; they do not resolve, download, or audit dependency
  contents.
- Symlinks and oversized files are skipped rather than followed or executed.
- Suppressions are command-line policy choices and should be documented in the consuming project.

If a result looks wrong, please open an issue with the smallest safe reproducer. Never attach
live credentials or private plugin code to a public report.

## Development and contributing

Contributions are welcome, especially focused detection rules with both positive and negative
tests. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and design expectations,
[SECURITY.md](SECURITY.md) for private vulnerability reporting, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

## License

MIT. See [LICENSE](LICENSE).
