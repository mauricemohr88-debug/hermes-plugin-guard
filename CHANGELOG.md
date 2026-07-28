# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-07-28

### Added

- Recognize pip-distributed Hermes plugins declared through
  `[project.entry-points."hermes_agent.plugins"]`, including multiple entry points per package,
  without requiring `plugin.yaml`; validate entry-point and dashboard declarations additively when
  a plugin ships more than one supported declaration.
- Inspect `plugin.yaml` `pip_dependencies` and flag remote installer commands that download and
  pipe mutable scripts directly to a shell as `HPG204`.
- Report `register_middleware()` as a privileged execution surface.

### Changed

- Match the current Hermes contracts for `optional_env`, exclusive memory-provider lifecycle
  hooks, dashboard manifest required fields, and dashboard entry bundles.
- Stop treating Python docstrings as sensitive-path findings, and resolve literal `__import__()`
  targets so their process and network behavior is reported in addition to `HPG101`.
- Ignore a Python distribution's own extras when checking third-party dependency bounds and avoid
  secret-name findings for metadata variables ending in `_URL`, `_URI`, `_SCOPE`, `_ID`, `_NAME`,
  or `_PATH`.
- Bound every untrusted manifest parse by size and depth, including the dependency pass.

## [0.1.2] - 2026-07-25

### Added

- `HPG112` inventories concrete outbound Python network calls without executing code, resolving
  DNS, or making requests.
- Destination-aware findings redact credentials, paths, queries, fragments, headers, and payloads,
  and distinguish loopback, encrypted, cleartext, and link-local/cloud-metadata targets.

### Changed

- Recognize the current Hermes `pre_verify` and Kanban task hooks so valid plugin manifests do not
  receive `HPG006` compatibility findings.

## [0.1.1] - 2026-07-23

### Added

- Five-minute beta-test quickstart and a structured feedback issue form.
- A reproducible 20-second terminal demo for the README and community posts.
- Opt-in, tokenless PyPI Trusted Publishing workflow for published GitHub releases, including
  distribution attestations and a safe configuration gate.
- Maintainer release checklist for the one-time PyPI and GitHub environment setup.

### Changed

- Ignore tests, fixtures, caches, virtual environments, and generated directories during default
  behavior and secret scanning so development-only samples do not dominate plugin reports.
- Recognize nested plugin repositories and official dashboard-only plugins that use
  `dashboard/manifest.json`.
- Update the reusable GitHub Action and documentation examples to current Node 24-based action
  releases.
- Clarified that scans remain local, do not execute target plugin code, make no network requests,
  include no telemetry, and upload neither source nor results.
- Updated installation and GitHub Action examples for the v0.1.1 release.

## [0.1.0] - 2026-07-23

### Added

- Static discovery and validation of one plugin or a repository of plugins.
- Manifest checks for metadata, plugin kind, entry point, declared environment, and hook drift.
- AST-based checks for high-risk Python capabilities and load-time behavior.
- Heuristic scanning for committed secret material.
- Remote-dependency pinning and version-bound checks.
- Human-readable, JSON, SARIF, and GitHub annotation output.
- Configurable failure thresholds and per-rule command-line exclusions.
- Composite GitHub Action and pinned continuous-integration workflow.

[Unreleased]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/releases/tag/v0.1.0
