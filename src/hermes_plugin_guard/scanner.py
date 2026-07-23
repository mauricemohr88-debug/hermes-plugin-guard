"""Top-level, deterministic scan orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .catalog import get_rule
from .dependency_scan import inspect_dependencies
from .manifest import VALID_HOOKS, PluginMetadata, inspect_manifest
from .models import Finding, ScanResult, Severity
from .python_scan import inspect_python
from .secret_scan import MAX_TEXT_BYTES, inspect_file

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
IGNORED_DISCOVERY_PARTS = {"fixtures", "testdata"}


def scan(
    target: str | Path,
    *,
    excluded_rules: Iterable[str] = (),
) -> ScanResult:
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root}")

    excluded = {rule.upper() for rule in excluded_rules}
    result = ScanResult(root=root)
    plugin_roots = _discover_plugin_roots(root)
    result.plugin_count = len(plugin_roots)
    scan_roots = plugin_roots or [root]
    scanned_paths: set[Path] = set()
    all_metadata: list[PluginMetadata] = []

    for plugin_root in scan_roots:
        metadata, manifest_findings = inspect_manifest(plugin_root, root)
        all_metadata.append(metadata)
        result.findings.extend(manifest_findings)
        result.findings.extend(_symlink_findings(plugin_root, root))

        literal_hooks: dict[str, tuple[str, int]] = {}
        for path in _iter_files(plugin_root):
            resolved = path.resolve()
            if resolved in scanned_paths:
                continue
            scanned_paths.add(resolved)
            if _too_large(path):
                result.skipped_files += 1
                continue
            result.scanned_files += 1
            result.findings.extend(inspect_file(path, root))
            if path.suffix == ".py":
                inspection = inspect_python(path, root, metadata.declared_env)
                result.findings.extend(inspection.findings)
                literal_hooks.update(inspection.literal_hooks)

        result.findings.extend(_hook_drift(metadata, literal_hooks, root))
        result.findings.extend(inspect_dependencies(plugin_root, root))

    if plugin_roots and root not in plugin_roots:
        result.findings.extend(inspect_dependencies(root, root))
        for path in _iter_repository_metadata(root):
            resolved = path.resolve()
            if resolved in scanned_paths or _too_large(path):
                continue
            scanned_paths.add(resolved)
            result.scanned_files += 1
            result.findings.extend(inspect_file(path, root))

    result.findings.extend(_project_hygiene(root))
    result.findings = _deduplicate(
        finding for finding in result.findings if finding.rule_id not in excluded
    )
    return result


def _discover_plugin_roots(root: Path) -> list[Path]:
    if (root / "plugin.yaml").is_file() or (root / "plugin.yml").is_file():
        return [root]

    roots: set[Path] = set()
    manifests = list(root.rglob("plugin.yaml")) + list(root.rglob("plugin.yml"))
    for manifest in sorted(manifests):
        relative_parts = manifest.relative_to(root).parts
        if len(relative_parts) > 5:
            continue
        if _ignored_parts(relative_parts):
            continue
        roots.add(manifest.parent)
    return sorted(roots)


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if _ignored_parts(relative_parts):
            continue
        yield path


def _ignored_parts(parts: tuple[str, ...]) -> bool:
    if any(part in IGNORED_DIRECTORIES for part in parts):
        return True
    return "tests" in parts and any(part in IGNORED_DISCOVERY_PARTS for part in parts)


def _symlink_findings(plugin_root: Path, repository_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(plugin_root.rglob("*")):
        if not path.is_symlink():
            continue
        try:
            path.resolve(strict=True).relative_to(plugin_root.resolve())
        except (FileNotFoundError, OSError, ValueError):
            rule = get_rule("HPG002")
            findings.append(
                Finding(
                    rule_id="HPG002",
                    severity=rule.default_severity,
                    message="Symlink is broken or resolves outside the plugin root; it was not followed.",
                    path=_relative(path, repository_root),
                )
            )
    return findings


def _iter_repository_metadata(root: Path) -> Iterable[Path]:
    allowed = {
        ".env",
        ".npmrc",
        ".netrc",
        "action.yml",
        "action.yaml",
        "pyproject.toml",
        "requirements.txt",
    }
    for path in sorted(root.iterdir()):
        if path.is_file() and (
            path.name in allowed
            or path.name.startswith("requirements")
            or path.suffix.lower() in {".key", ".p12", ".pem"}
        ):
            yield path


def _too_large(path: Path) -> bool:
    try:
        return path.stat().st_size > MAX_TEXT_BYTES
    except OSError:
        return True


def _hook_drift(
    metadata: PluginMetadata,
    literal_hooks: dict[str, tuple[str, int]],
    root: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    actual = set(literal_hooks)
    for hook in sorted(actual - VALID_HOOKS):
        path, line = literal_hooks[hook]
        rule = get_rule("HPG006")
        findings.append(
            Finding(
                rule_id="HPG006",
                severity=rule.default_severity,
                message=f"Code registers unknown Hermes hook {hook!r}.",
                path=path,
                line=line,
                evidence=hook,
            )
        )
    for hook in sorted(actual - metadata.declared_hooks):
        path, line = literal_hooks[hook]
        rule = get_rule("HPG006")
        findings.append(
            Finding(
                rule_id="HPG006",
                severity=rule.default_severity,
                message=f"Hook {hook!r} is registered in code but absent from plugin.yaml.",
                path=path,
                line=line,
                evidence=hook,
            )
        )
    for hook in sorted(metadata.declared_hooks - actual):
        rule = get_rule("HPG006")
        findings.append(
            Finding(
                rule_id="HPG006",
                severity=Severity.LOW,
                message=f"Hook {hook!r} is declared but no literal ctx.register_hook call was found.",
                path=_relative(metadata.root / "plugin.yaml", root),
                evidence=hook,
            )
        )
    if "pre_gateway_dispatch" in actual:
        path, line = literal_hooks["pre_gateway_dispatch"]
        findings.append(
            Finding(
                rule_id="HPG110",
                severity=Severity.CRITICAL,
                message="pre_gateway_dispatch runs before gateway authentication and pairing.",
                path=path,
                line=line,
                evidence="pre_gateway_dispatch",
            )
        )
    return findings


def _project_hygiene(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not any((root / name).is_file() for name in ("LICENSE", "LICENSE.md", "LICENSE.txt")):
        findings.append(_project_finding("HPG301", "No LICENSE file was found."))
    if not (root / "SECURITY.md").is_file():
        findings.append(_project_finding("HPG302", "No SECURITY.md policy was found."))
    has_tests = (root / "tests").is_dir() or any(root.rglob("test_*.py"))
    if not has_tests:
        findings.append(_project_finding("HPG303", "No automated tests were found."))
    return findings


def _project_finding(rule_id: str, message: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.default_severity,
        message=message,
        path=".",
    )


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.severity,
            finding.message,
            finding.path,
            finding.line,
            finding.column,
        )
        unique[key] = finding
    return list(unique.values())


def _relative(path: Path, root: Path) -> str:
    try:
        # Keep the lexical in-tree path. Resolving an untrusted symlink here could
        # disclose an absolute host path in JSON, SARIF, or CI annotations.
        return path.absolute().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
