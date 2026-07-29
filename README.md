# Hermes Plugin Guard

[![CI](https://github.com/mauricemohr88-debug/hermes-plugin-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mauricemohr88-debug/hermes-plugin-guard/actions/workflows/ci.yml)
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

![20-second terminal demo of installing and running Hermes Plugin Guard](https://raw.githubusercontent.com/mauricemohr88-debug/hermes-plugin-guard/v0.1.3/docs/demo.gif)

## Five-minute beta test

If you maintain or use a Hermes plugin, one local scan is enough to help improve the rules.
Python 3.11 or newer and [pipx](https://pipx.pypa.io/stable/) are required.

1. Install the current release from PyPI:

   ```bash
   pipx install hermes-plugin-guard
   ```

2. Scan your plugin without failing the command on findings:

   ```bash
   hpg scan /absolute/path/to/your-plugin --fail-on none
   ```

3. Send a short
   [beta-test report](https://github.com/mauricemohr88-debug/hermes-plugin-guard/issues/new?template=beta-test.yml)
   with the rule IDs that were useful, noisy, or missing. A public plugin URL is helpful but not
   required.

The scan stays on your computer. `hpg` reads target files as data, does not import or execute
target plugin code, makes no network requests, includes no telemetry, and uploads neither source
code nor results. Do not paste private code, credentials, or unsanitized paths into a public issue.

Already installed? Use `pipx upgrade hermes-plugin-guard`. For a reproducible installation
directly from the tagged source, install the v0.1.3 GitHub release:

```bash
pipx install \
  "git+https://github.com/mauricemohr88-debug/hermes-plugin-guard.git@v0.1.3"
```

## Why this exists

Hermes plugins are Python extensions, not isolated data files. A third-party plugin can register
tools and hooks and can run with the permissions of the Hermes process. Code review remains the
most important control; `hpg` adds a fast, repeatable first pass before enablement and in CI.

The scanner is designed to make high-risk patterns visible, including:

- direct subprocess calls that bypass Hermes' terminal-tool approval path;
- dynamic execution and unsafe deserialization;
- sensitive-path access, destructive filesystem operations, and disabled TLS verification;
- all-interface listeners, networking capability, concrete outbound calls with redacted
  destinations, and undeclared secret environment variables;
- privileged registration and middleware surfaces, plus work performed during import or
  registration;
- likely committed credentials, mutable remote dependencies, and remote scripts piped to shells;
- plugin declaration drift, missing tests, and missing project policies.

## Install

Python 3.11 or newer is required.

Install the current release from
[PyPI](https://pypi.org/project/hermes-plugin-guard/) with
[pipx](https://pipx.pypa.io/stable/) (recommended for command-line tools):

```bash
pipx install hermes-plugin-guard
```

Alternatively, install reproducibly from the tagged GitHub source:

```bash
pipx install \
  "git+https://github.com/mauricemohr88-debug/hermes-plugin-guard.git@v0.1.3"
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

The scanner recognizes directory plugins using `plugin.yaml`, dashboard-only plugins using
`dashboard/manifest.json`, and pip-distributed plugins using
`[project.entry-points."hermes_agent.plugins"]` in `pyproject.toml`.

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: mauricemohr88-debug/hermes-plugin-guard@v0.1.3
        with:
          path: path/to/plugin
          fail-on: high
          format: github
```

For stronger supply-chain controls, pin `hermes-plugin-guard` to a reviewed full commit SHA
instead of a moving tag.

## Rules at a glance

| IDs | Area | Examples |
| --- | --- | --- |
| `HPG001`–`HPG006` | Declaration | Missing or invalid declarations, unknown kind, entry point and hook drift |
| `HPG101`–`HPG112` | Python | Execution, deserialization, processes, sensitive paths, network and privileged behavior |
| `HPG201`–`HPG204` | Supply chain | Likely secrets, mutable dependencies, unbounded versions, remote installers |
| `HPG301`–`HPG303` | Project | License, security policy, and automated tests |

Run `hpg rules` for the current severity, explanation, and suggested remediation for every rule.

### Network-egress inventory

`HPG106` reports that a plugin imports a network-capable module. `HPG112` is more specific: it
reports a concrete outbound request or connection and records the statically visible destination.
The scanner never resolves DNS or makes a request while doing this.

Destination evidence is deliberately limited to the scheme, hostname, and port. User information,
paths, query strings, fragments, headers, and payloads are never copied into a finding. Dynamic or
relative destinations are reported as `<dynamic destination>`. Loopback calls default to low,
encrypted external calls to medium, and explicitly cleartext HTTP, FTP, WebSocket, or gRPC and
link-local/cloud-metadata targets to high. Raw TCP and SMTP stay medium because the protocol may
upgrade to TLS after connecting.

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
- Egress checks cover common Python HTTP, WebSocket, socket, FTP, SMTP, and gRPC APIs. Calls hidden
  behind dependencies, arbitrary SDK wrappers, native extensions, or dashboard JavaScript can
  require manual review.
- A finding describes a risky capability or pattern, not necessarily a vulnerability.
- The absence of findings does not establish safety.
- Secret matching is heuristic and may produce false positives or miss encoded or split secrets.
- Dependency checks inspect `requirements*.txt`, `pyproject.toml`, and relevant `plugin.yaml`
  declarations; they do not resolve, download, or audit dependency contents.
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
