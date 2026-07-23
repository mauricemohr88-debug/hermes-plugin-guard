"""Supply-chain checks for Python dependency declarations."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Iterable

from .catalog import get_rule
from .models import Finding

FULL_SHA_RE = re.compile(r"(?i)(?:@|/)[0-9a-f]{40}(?:[#?]|$)")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+")


def inspect_dependencies(root: Path, repository_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[Path] = set()
    candidates = sorted(root.glob("requirements*.txt"))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        candidates.append(pyproject)

    for path in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.name == "pyproject.toml":
            findings.extend(_inspect_pyproject(path, repository_root))
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
    if isinstance(project, dict):
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
    return _inspect_entries(entries, _relative(path, root))


def _inspect_entries(entries: Iterable[tuple[int, str]], relative_path: str) -> list[Finding]:
    findings: list[Finding] = []
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

        spec = entry[NAME_RE.match(entry).end() :]  # type: ignore[union-attr]
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


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
