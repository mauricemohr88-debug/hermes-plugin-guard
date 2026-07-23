"""Credential-file and secret-literal checks that do not execute target code."""

from __future__ import annotations

import re
from pathlib import Path

from .catalog import get_rule
from .models import Finding

IGNORED_SECRET_FILES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}
SENSITIVE_FILENAMES = {
    ".env",
    ".npmrc",
    ".netrc",
    "auth.json",
    "credentials.json",
    "id_dsa",
    "id_ed25519",
    "id_rsa",
}
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    ),
    (
        "AWS access key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "OpenAI-style API key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
)
MAX_TEXT_BYTES = 1_000_000


def inspect_file(path: Path, repository_root: Path) -> list[Finding]:
    relative = _relative(path, repository_root)
    findings: list[Finding] = []
    lowered = path.name.lower()

    if lowered not in IGNORED_SECRET_FILES and (
        lowered in SENSITIVE_FILENAMES or path.suffix.lower() in {".key", ".p12", ".pem"}
    ):
        findings.append(
            _finding(
                f"Credential-like file {path.name!r} is present in the plugin tree.",
                relative,
            )
        )

    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return findings
        raw = path.read_bytes()
        if b"\0" in raw:
            return findings
        text = raw.decode("utf-8")
    except (OSError, UnicodeError):
        return findings

    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        line = text.count("\n", 0, match.start()) + 1
        findings.append(
            _finding(
                f"Possible {label} literal is committed; revoke and remove it from history.",
                relative,
                line,
                evidence=label,
            )
        )
    return findings


def _finding(
    message: str,
    path: str,
    line: int = 1,
    evidence: str | None = None,
) -> Finding:
    rule = get_rule("HPG201")
    return Finding(
        rule_id="HPG201",
        severity=rule.default_severity,
        message=message,
        path=path,
        line=line,
        evidence=evidence,
    )


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
