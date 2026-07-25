"""Hermes plugin manifest parsing and structural checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .catalog import get_rule
from .models import Finding

VALID_KINDS = {"standalone", "backend", "exclusive", "platform", "model-provider"}
VALID_HOOKS = {
    "pre_tool_call",
    "post_tool_call",
    "transform_terminal_output",
    "transform_tool_result",
    "transform_llm_output",
    "pre_llm_call",
    "post_llm_call",
    "pre_verify",
    "pre_api_request",
    "post_api_request",
    "api_request_error",
    "on_session_start",
    "on_session_end",
    "on_session_finalize",
    "on_session_reset",
    "subagent_start",
    "subagent_stop",
    "pre_gateway_dispatch",
    "pre_approval_request",
    "post_approval_response",
    "kanban_task_claimed",
    "kanban_task_completed",
    "kanban_task_blocked",
}
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
MAX_MANIFEST_BYTES = 256_000
DASHBOARD_MANIFEST = Path("dashboard") / "manifest.json"


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(slots=True)
class PluginMetadata:
    root: Path
    name: str = ""
    version: str = ""
    kind: str = "standalone"
    declared_hooks: set[str] = field(default_factory=set)
    declared_tools: set[str] = field(default_factory=set)
    declared_env: set[str] = field(default_factory=set)
    valid: bool = False


def _finding(rule_id: str, message: str, path: str, line: int = 1) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.default_severity,
        message=message,
        path=path,
        line=line,
    )


def _line_for_key(text: str, key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:", re.MULTILINE)
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item.strip() for item in value if isinstance(item, str) and item.strip()}


def _environment_names(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    names: set[str] = set()
    for item in value:
        if isinstance(item, str) and item.strip():
            names.add(item.strip())
        elif isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                names.add(name.strip())
    return names


def inspect_manifest(
    plugin_root: Path,
    repository_root: Path,
) -> tuple[PluginMetadata, list[Finding]]:
    manifest_path = plugin_root / "plugin.yaml"
    relative = _relative(manifest_path, repository_root)
    metadata = PluginMetadata(root=plugin_root)
    findings: list[Finding] = []

    if not manifest_path.is_file():
        alternate = plugin_root / "plugin.yml"
        if not alternate.is_file() and (plugin_root / DASHBOARD_MANIFEST).is_file():
            return _inspect_dashboard_manifest(plugin_root, repository_root)
        detail = ""
        if alternate.is_file():
            detail = (
                " Only plugin.yml exists; use plugin.yaml because Hermes installer paths "
                "do not consistently accept the .yml spelling."
            )
        findings.append(
            _finding(
                "HPG001",
                f"plugin.yaml was not found in the plugin directory.{detail}",
                relative,
            )
        )
        return metadata, findings

    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            findings.append(
                _finding(
                    "HPG002",
                    f"plugin.yaml exceeds the {MAX_MANIFEST_BYTES // 1000} KB safety limit.",
                    relative,
                )
            )
            return metadata, findings
        text = manifest_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        findings.append(_finding("HPG002", f"plugin.yaml could not be read: {exc}", relative))
        return metadata, findings

    try:
        data = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except (yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        mark = getattr(exc, "problem_mark", None)
        line = getattr(mark, "line", 0) + 1 if mark is not None else 1
        findings.append(
            _finding("HPG002", f"plugin.yaml contains invalid YAML: {exc}", relative, line)
        )
        return metadata, findings

    if not isinstance(data, dict):
        findings.append(
            _finding("HPG002", "plugin.yaml must contain a mapping at its root.", relative)
        )
        return metadata, findings

    for key in ("name", "version", "description"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            findings.append(
                _finding(
                    "HPG003",
                    f"Required manifest field {key!r} is missing or empty.",
                    relative,
                    _line_for_key(text, key),
                )
            )

    metadata.name = str(data.get("name") or "").strip()
    metadata.version = str(data.get("version") or "").strip()
    raw_kind = data.get("kind", "standalone")
    metadata.kind = raw_kind.strip().lower() if isinstance(raw_kind, str) else ""
    if metadata.kind not in VALID_KINDS:
        findings.append(
            _finding(
                "HPG004",
                f"Unknown plugin kind {raw_kind!r}; Hermes will coerce it to standalone.",
                relative,
                _line_for_key(text, "kind"),
            )
        )

    if metadata.version and not SEMVER_RE.fullmatch(metadata.version):
        findings.append(
            _finding(
                "HPG003",
                f"Version {metadata.version!r} is not semantic versioning (for example 1.2.3).",
                relative,
                _line_for_key(text, "version"),
            )
        )

    metadata.declared_hooks = _string_set(data.get("provides_hooks")) | _string_set(
        data.get("hooks")
    )
    metadata.declared_tools = _string_set(data.get("provides_tools")) | _string_set(
        data.get("tools")
    )
    metadata.declared_env = _environment_names(data.get("requires_env"))

    for hook in sorted(metadata.declared_hooks - VALID_HOOKS):
        findings.append(
            _finding(
                "HPG006",
                f"Manifest declares unknown hook {hook!r}.",
                relative,
                _line_for_key(text, "provides_hooks"),
            )
        )

    if not (plugin_root / "__init__.py").is_file():
        findings.append(
            _finding(
                "HPG005",
                "Directory plugin has no __init__.py entry point.",
                _relative(plugin_root / "__init__.py", repository_root),
            )
        )

    metadata.valid = not any(finding.rule_id in {"HPG001", "HPG002"} for finding in findings)
    return metadata, findings


def _inspect_dashboard_manifest(
    plugin_root: Path,
    repository_root: Path,
) -> tuple[PluginMetadata, list[Finding]]:
    """Inspect Hermes' dashboard-only plugin shape.

    Dashboard extensions are discovered from ``dashboard/manifest.json`` and
    legitimately do not need ``plugin.yaml`` or a package-level
    ``__init__.py``.
    """

    manifest_path = plugin_root / DASHBOARD_MANIFEST
    relative = _relative(manifest_path, repository_root)
    metadata = PluginMetadata(root=plugin_root, kind="dashboard")
    findings: list[Finding] = []

    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            findings.append(
                _finding(
                    "HPG002",
                    (
                        "dashboard/manifest.json exceeds the "
                        f"{MAX_MANIFEST_BYTES // 1000} KB safety limit."
                    ),
                    relative,
                )
            )
            return metadata, findings
        text = manifest_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        findings.append(
            _finding(
                "HPG002",
                f"dashboard/manifest.json could not be read: {exc}",
                relative,
            )
        )
        return metadata, findings

    try:
        data = json.loads(text, object_pairs_hook=_construct_unique_json_mapping)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        line = getattr(exc, "lineno", 1)
        findings.append(
            _finding(
                "HPG002",
                f"dashboard/manifest.json contains invalid JSON: {exc}",
                relative,
                line,
            )
        )
        return metadata, findings

    if not isinstance(data, dict):
        findings.append(
            _finding(
                "HPG002",
                "dashboard/manifest.json must contain an object at its root.",
                relative,
            )
        )
        return metadata, findings

    for key in ("name", "version", "description"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            findings.append(
                _finding(
                    "HPG003",
                    f"Required dashboard manifest field {key!r} is missing or empty.",
                    relative,
                    _line_for_json_key(text, key),
                )
            )

    metadata.name = str(data.get("name") or "").strip()
    metadata.version = str(data.get("version") or "").strip()
    if metadata.version and not SEMVER_RE.fullmatch(metadata.version):
        findings.append(
            _finding(
                "HPG003",
                (f"Version {metadata.version!r} is not semantic versioning (for example 1.2.3)."),
                relative,
                _line_for_json_key(text, "version"),
            )
        )

    metadata.valid = not any(finding.rule_id == "HPG002" for finding in findings)
    return metadata, findings


def _construct_unique_json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError(f"found duplicate key {key!r}")
        mapping[key] = value
    return mapping


def _line_for_json_key(text: str, key: str) -> int:
    match = re.search(rf'^\s*"{re.escape(key)}"\s*:', text, re.MULTILINE)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
