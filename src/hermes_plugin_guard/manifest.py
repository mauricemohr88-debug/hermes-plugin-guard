"""Hermes plugin manifest parsing and structural checks."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .catalog import get_rule
from .models import Finding

VALID_KINDS = {"standalone", "backend", "exclusive", "platform", "model-provider"}
HERMES_ENTRY_POINT_GROUP = "hermes_agent.plugins"
MEMORY_PROVIDER_HOOKS = {
    "on_memory_write",
    "on_pre_compress",
    "on_session_end",
    "prefetch",
    "queue_prefetch",
    "shutdown",
    "sync_turn",
    "system_prompt_block",
}
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
    declaration_source: str = ""
    declared_hooks: set[str] = field(default_factory=set)
    declared_tools: set[str] = field(default_factory=set)
    declared_env: set[str] = field(default_factory=set)
    has_hook_declarations: bool = True
    entry_point_count: int = 0
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


def _line_for_toml_key(text: str, key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=", re.MULTILINE)
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _line_for_toml_table(text: str, table: str) -> int:
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("[") and table in stripped:
            return line_number
    return 1


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


def _looks_like_memory_provider(plugin_root: Path) -> bool:
    init_path = plugin_root / "__init__.py"
    if not init_path.is_file():
        return False
    try:
        with init_path.open(encoding="utf-8") as stream:
            source = stream.read(8192)
    except (OSError, UnicodeError):
        return False
    return "register_memory_provider" in source or "MemoryProvider" in source


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
        entry_point_result = inspect_entry_point_manifest(plugin_root, repository_root)
        if entry_point_result is not None:
            return entry_point_result
        if (plugin_root / DASHBOARD_MANIFEST).is_file():
            return inspect_dashboard_manifest(plugin_root, repository_root)
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

    metadata.declaration_source = "plugin.yaml"
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
    is_memory_provider = (
        "kind" not in data
        and metadata.kind == "standalone"
        and _looks_like_memory_provider(plugin_root)
    )
    if is_memory_provider:
        # Match Hermes' own safe, no-import discovery heuristic. Memory
        # providers use a dedicated lifecycle instead of ctx.register_hook().
        metadata.kind = "exclusive"
        metadata.has_hook_declarations = False
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
    metadata.declared_env = _environment_names(data.get("requires_env")) | _environment_names(
        data.get("optional_env")
    )

    accepted_hooks = VALID_HOOKS | MEMORY_PROVIDER_HOOKS if is_memory_provider else VALID_HOOKS
    for hook in sorted(metadata.declared_hooks - accepted_hooks):
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


def has_hermes_entry_points(root: Path) -> bool:
    """Return whether *root* declares itself as a pip-distributed Hermes plugin."""

    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        return False
    try:
        with pyproject_path.open(encoding="utf-8") as stream:
            text = stream.read(MAX_MANIFEST_BYTES + 1)
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return HERMES_ENTRY_POINT_GROUP in text
    except (OSError, UnicodeError):
        return False

    project = data.get("project")
    entry_point_groups = project.get("entry-points") if isinstance(project, dict) else None
    return isinstance(entry_point_groups, dict) and HERMES_ENTRY_POINT_GROUP in entry_point_groups


def _hermes_entry_points(data: Any) -> dict[str, str]:
    if not isinstance(data, dict):
        return {}
    project = data.get("project")
    if not isinstance(project, dict):
        return {}
    entry_point_groups = project.get("entry-points")
    if not isinstance(entry_point_groups, dict):
        return {}
    raw_entries = entry_point_groups.get(HERMES_ENTRY_POINT_GROUP)
    if not isinstance(raw_entries, dict):
        return {}
    return {
        name.strip(): target.strip()
        for name, target in raw_entries.items()
        if isinstance(name, str) and name.strip() and isinstance(target, str) and target.strip()
    }


def inspect_entry_point_manifest(
    plugin_root: Path,
    repository_root: Path,
) -> tuple[PluginMetadata, list[Finding]] | None:
    """Inspect Hermes' supported pip entry-point package shape."""

    pyproject_path = plugin_root / "pyproject.toml"
    if not pyproject_path.is_file():
        return None
    relative = _relative(pyproject_path, repository_root)
    try:
        size = pyproject_path.stat().st_size
        with pyproject_path.open(encoding="utf-8") as stream:
            text = stream.read(MAX_MANIFEST_BYTES + 1)
    except (OSError, UnicodeError):
        return None

    metadata = PluginMetadata(
        root=plugin_root,
        kind="entrypoint",
        declaration_source="pyproject.toml",
        has_hook_declarations=False,
    )
    findings: list[Finding] = []
    if size > MAX_MANIFEST_BYTES:
        if HERMES_ENTRY_POINT_GROUP not in text:
            return None
        findings.append(
            _finding(
                "HPG002",
                f"pyproject.toml exceeds the {MAX_MANIFEST_BYTES // 1000} KB safety limit.",
                relative,
            )
        )
        return metadata, findings

    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        # Do not turn every malformed ordinary Python project into a Hermes
        # plugin. The literal group name is the only static signal available
        # when TOML parsing itself fails.
        if HERMES_ENTRY_POINT_GROUP not in text:
            return None
        findings.append(
            _finding(
                "HPG002",
                f"pyproject.toml contains invalid TOML: {exc}",
                relative,
            )
        )
        return metadata, findings

    project = data.get("project")
    entry_point_groups = project.get("entry-points") if isinstance(project, dict) else None
    if (
        not isinstance(entry_point_groups, dict)
        or HERMES_ENTRY_POINT_GROUP not in entry_point_groups
    ):
        return None
    raw_entries = entry_point_groups.get(HERMES_ENTRY_POINT_GROUP)
    metadata.entry_point_count = len(raw_entries) if isinstance(raw_entries, dict) else 0
    entries = _hermes_entry_points(data)
    entries_are_valid = (
        isinstance(raw_entries, dict) and bool(raw_entries) and len(entries) == len(raw_entries)
    )
    if not isinstance(project, dict) or not entries_are_valid:
        findings.append(
            _finding(
                "HPG002",
                (
                    f"[project.entry-points.{HERMES_ENTRY_POINT_GROUP!r}] must contain "
                    "at least one non-empty plugin name and import target."
                ),
                relative,
                _line_for_toml_table(text, HERMES_ENTRY_POINT_GROUP),
            )
        )
        return metadata, findings

    dynamic = _string_set(project.get("dynamic"))
    for key in ("name", "version", "description"):
        value = project.get(key)
        if (not isinstance(value, str) or not value.strip()) and key not in dynamic:
            findings.append(
                _finding(
                    "HPG003",
                    f"Required package metadata field {key!r} is missing or empty.",
                    relative,
                    _line_for_toml_key(text, key),
                )
            )

    metadata.name = str(project.get("name") or next(iter(entries))).strip()
    metadata.version = str(project.get("version") or "").strip()

    metadata.valid = not any(finding.rule_id == "HPG002" for finding in findings)
    return metadata, findings


def inspect_dashboard_manifest(
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
    metadata = PluginMetadata(
        root=plugin_root,
        kind="dashboard",
        declaration_source="dashboard/manifest.json",
        has_hook_declarations=False,
    )
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

    for key in ("name", "label", "entry"):
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
    tab = data.get("tab")
    tab_path = tab.get("path") if isinstance(tab, dict) else None
    if not isinstance(tab_path, str) or not tab_path.strip():
        findings.append(
            _finding(
                "HPG003",
                "Required dashboard manifest field 'tab.path' is missing or empty.",
                relative,
                _line_for_json_key(text, "tab"),
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

    raw_entry = data.get("entry")
    if isinstance(raw_entry, str) and raw_entry.strip():
        entry = raw_entry.strip()
        dashboard_root = plugin_root / "dashboard"
        entry_path = Path(entry)
        entry_is_safe = (
            not entry_path.is_absolute()
            and not entry.startswith(("/", "\\"))
            and not re.match(r"^[A-Za-z]:[\\/]", entry)
        )
        candidate = dashboard_root / entry_path
        if entry_is_safe:
            try:
                candidate.resolve().relative_to(dashboard_root.resolve())
            except (OSError, RuntimeError, ValueError):
                entry_is_safe = False
        if not entry_is_safe:
            findings.append(
                _finding(
                    "HPG002",
                    "Dashboard entry must stay inside the dashboard directory.",
                    relative,
                    _line_for_json_key(text, "entry"),
                )
            )
        elif candidate.suffix.casefold() not in {".js", ".mjs"}:
            findings.append(
                _finding(
                    "HPG005",
                    "Dashboard entry must point to a JavaScript .js or .mjs bundle.",
                    relative,
                    _line_for_json_key(text, "entry"),
                )
            )
        elif not candidate.is_file():
            findings.append(
                _finding(
                    "HPG005",
                    f"Dashboard entry bundle {entry!r} was not found.",
                    _relative(candidate, repository_root),
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
