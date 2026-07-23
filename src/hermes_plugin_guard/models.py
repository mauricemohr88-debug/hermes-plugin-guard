"""Shared result types used by scanners and reporters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    """Finding severity ordered from informational to critical."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"unknown severity {value!r}; choose one of: {choices}") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    description: str
    remediation: str
    default_severity: Severity
    category: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int = 1
    column: int = 1
    evidence: str | None = None

    @property
    def fingerprint(self) -> str:
        """Return a stable identity that survives harmless line movement."""
        raw = "\0".join(
            [
                self.rule_id,
                self.path,
                self.message,
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "fingerprint": self.fingerprint,
        }
        if self.evidence is not None:
            data["evidence"] = self.evidence
        return data


@dataclass(slots=True)
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    plugin_count: int = 0
    skipped_files: int = 0

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (
                -int(item.severity),
                item.path,
                item.line,
                item.column,
                item.rule_id,
                item.message,
            ),
        )

    def counts(self) -> dict[str, int]:
        return {
            severity.label: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in reversed(Severity)
        }

    def fails_at(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(finding.severity >= threshold for finding in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "tool": "hermes-plugin-guard",
            "root": ".",
            "summary": {
                "plugins": self.plugin_count,
                "scanned_files": self.scanned_files,
                "skipped_files": self.skipped_files,
                "findings": len(self.findings),
                "counts": self.counts(),
            },
            "findings": [finding.as_dict() for finding in self.sorted_findings()],
        }
