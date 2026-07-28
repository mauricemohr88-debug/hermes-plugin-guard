"""Supply-chain checks for Python dependency declarations."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Iterable

import yaml

from .catalog import get_rule
from .manifest import MAX_MANIFEST_BYTES
from .models import Finding

FULL_SHA_RE = re.compile(r"(?i)(?:@|/)[0-9a-f]{40}(?:[#?]|$)")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+")
REMOTE_FETCH_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n]*(?:https?://)")
PIPE_TO_SHELL_RE = re.compile(
    r"(?i)\|\s*(?:(?:/usr/bin/env|env)\s+)?(?:ba|da|fi|z)?sh\b"
    r"|\|\s*(?:iex|invoke-expression)\b"
)


def inspect_dependencies(root: Path, repository_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[Path] = set()
    candidates = sorted(root.glob("requirements*.txt"))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        candidates.append(pyproject)
    manifest = root / "plugin.yaml"
    if manifest.is_file():
        candidates.append(manifest)

    for path in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.name == "pyproject.toml":
            findings.extend(_inspect_pyproject(path, repository_root))
        elif path.name == "plugin.yaml":
            findings.extend(_inspect_plugin_manifest(path, repository_root))
        else:
            findings.extend(_inspect_requirements(path, repository_root))
    return findings


def _inspect_requirements(path: Path, root: Path) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    entries = (
        (line_number, line.strip())
        for line_number, line in enumerate(lines, start=1)
        if line.strip() and not line.lstrip().startswith(("#", "-r", "--requirement"))
    )
    return _inspect_entries(entries, _relative(path, root))


def _inspect_pyproject(path: Path, root: Path) -> list[Finding]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return []

    dependencies: list[str] = []
    project = data.get("project")
    project_name = ""
    if isinstance(project, dict):
        raw_name = project.get("name")
        if isinstance(raw_name, str):
            project_name = raw_name
        raw = project.get("dependencies")
        if isinstance(raw, list):
            dependencies.extend(item for item in raw if isinstance(item, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    dependencies.extend(item for item in group if isinstance(item, str))

    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        raw = build_system.get("requires")
        if isinstance(raw, list):
            dependencies.extend(item for item in raw if isinstance(item, str))

    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[int, str]] = []
    search_from = 0
    for dependency in dependencies:
        line_number = 1
        for index in range(search_from, len(lines)):
            if dependency in lines[index]:
                line_number = index + 1
                search_from = index + 1
                break
        entries.append((line_number, dependency))
    ignored_names = {project_name} if project_name else set()
    return _inspect_entries(entries, _relative(path, root), ignored_names=ignored_names)


def _inspect_plugin_manifest(path: Path, root: Path) -> list[Finding]:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            # The structural manifest pass reports HPG002. Do not parse the
            # same oversized untrusted YAML again during dependency analysis.
            return []
        with path.open(encoding="utf-8") as stream:
            text = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(text) > MAX_MANIFEST_BYTES:
            return []
        data = yaml.safe_load(text) or {}
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []

    lines = text.splitlines()
    pip_dependencies = data.get("pip_dependencies")
    entries: list[tuple[int, str]] = []
    if isinstance(pip_dependencies, list):
        search_from = 0
        for dependency in pip_dependencies:
            if not isinstance(dependency, str):
                continue
            line_number, search_from = _line_for_yaml_value(
                lines,
                dependency,
                search_from,
                key=None,
            )
            entries.append((line_number, dependency))

    relative = _relative(path, root)
    findings = _inspect_entries(entries, relative)
    external_dependencies = data.get("external_dependencies")
    if not isinstance(external_dependencies, list):
        return findings

    search_from = 0
    for dependency in external_dependencies:
        if not isinstance(dependency, dict):
            continue
        install = dependency.get("install")
        if not isinstance(install, str) or not _pipes_remote_script_to_shell(install):
            continue
        line_number, search_from = _line_for_yaml_value(
            lines,
            install,
            search_from,
            key="install",
        )
        rule = get_rule("HPG204")
        findings.append(
            Finding(
                rule_id="HPG204",
                severity=rule.default_severity,
                message="External dependency downloads a remote script and pipes it to a shell.",
                path=relative,
                line=line_number,
                evidence="remote download | shell",
            )
        )
    return findings


def _line_for_yaml_value(
    lines: list[str],
    value: str,
    search_from: int,
    *,
    key: str | None,
) -> tuple[int, int]:
    def is_candidate(line: str) -> bool:
        stripped = line.lstrip()
        marker = f"{key}:" if key else "-"
        return stripped.startswith(marker) and value in line

    for index in range(search_from, len(lines)):
        if is_candidate(lines[index]):
            return index + 1, index + 1
    for index, line in enumerate(lines):
        if is_candidate(line):
            return index + 1, index + 1
    return 1, search_from


def _pipes_remote_script_to_shell(command: str) -> bool:
    return bool(REMOTE_FETCH_RE.search(command) and PIPE_TO_SHELL_RE.search(command))


def _inspect_entries(
    entries: Iterable[tuple[int, str]],
    relative_path: str,
    *,
    ignored_names: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    normalized_ignored = {_normalize_name(name) for name in ignored_names or set()}
    for line, raw_entry in entries:
        entry = raw_entry.split(";", 1)[0].strip()
        if not entry or entry.startswith(("-e ", "--editable ")):
            entry = entry.split(maxsplit=1)[-1] if " " in entry else entry

        is_remote = (
            "git+" in entry
            or " @ http://" in entry
            or " @ https://" in entry
            or entry.startswith(("http://", "https://"))
        )
        if is_remote and not FULL_SHA_RE.search(entry):
            rule = get_rule("HPG202")
            findings.append(
                Finding(
                    rule_id="HPG202",
                    severity=rule.default_severity,
                    message=f"Remote dependency is not pinned to a full commit SHA: {entry!r}.",
                    path=relative_path,
                    line=line,
                    evidence=entry,
                )
            )
            continue

        if is_remote or entry.startswith((".", "/", "file:")):
            continue
        if not NAME_RE.match(entry):
            continue

        match = NAME_RE.match(entry)
        if match is None:
            continue
        if _normalize_name(match.group(0)) in normalized_ignored:
            continue
        spec = entry[match.end() :]
        bounded = "==" in spec or "~=" in spec or "<" in spec
        if not bounded:
            rule = get_rule("HPG203")
            findings.append(
                Finding(
                    rule_id="HPG203",
                    severity=rule.default_severity,
                    message=f"Dependency has no compatible upper bound: {entry!r}.",
                    path=relative_path,
                    line=line,
                    evidence=entry,
                )
            )
    return findings


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
