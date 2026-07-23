# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/releases/tag/v0.1.0
