# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-23

### Added

- Static discovery and validation of one plugin or a repository of plugins.
- Manifest checks for metadata, plugin kind, entry point, declared environment, and hook drift.
- AST-based checks for high-risk Python capabilities and load-time behavior.
- Heuristic scanning for committed secret material.
- Remote-dependency pinning and version-bound checks.
- Human-readable, JSON, SARIF, and GitHub annotation output.
- Configurable failure thresholds and per-rule command-line exclusions.
- Composite GitHub Action and pinned continuous-integration workflow template.

[Unreleased]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mauricemohr88-debug/hermes-plugin-guard/releases/tag/v0.1.0
