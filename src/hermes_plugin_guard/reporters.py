"""Deterministic human and machine-readable scan reports."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .catalog import RULES, get_rule
from .models import Finding, ScanResult, Severity

INFORMATION_URI = "https://github.com/mauricemohr88-debug/hermes-plugin-guard"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"
)
SECURITY_SCORES = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def render_text(result: ScanResult, threshold: Severity | None = Severity.HIGH) -> str:
    """Render a compact terminal report without exposing absolute local paths."""
    counts = result.counts()
    lines = [
        f"hermes-plugin-guard {__version__}",
        (
            f"Scanned {result.plugin_count} plugin(s), {result.scanned_files} file(s)"
            f" — {len(result.findings)} finding(s)"
        ),
    ]
    if result.skipped_files:
        lines.append(f"Skipped {result.skipped_files} file(s) above the size limit.")

    for finding in result.sorted_findings():
        rule = get_rule(finding.rule_id)
        location = f"{finding.path}:{finding.line}:{finding.column}"
        lines.append(
            f"{finding.severity.label.upper():8} {finding.rule_id} {rule.title}  {location}"
        )
        lines.append(f"         {finding.message}")
        lines.append(f"         Fix: {rule.remediation}")

    summary = "  ".join(
        f"{name}={counts[name]}"
        for name in ("critical", "high", "medium", "low", "info")
        if counts[name]
    )
    if not summary:
        summary = "no findings"
    lines.append(f"Summary: {summary}")
    if threshold is None:
        lines.append("Result: informational (failure threshold disabled)")
    elif result.fails_at(threshold):
        lines.append(f"Result: FAIL (finding at or above {threshold.label})")
    else:
        lines.append(f"Result: PASS (no finding at or above {threshold.label})")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    """Render the stable JSON interchange format."""
    return json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n"


def render_sarif(result: ScanResult) -> str:
    """Render SARIF 2.1.0 suitable for GitHub code scanning upload."""
    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hermes-plugin-guard",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_sarif_rule(RULES[rule_id]) for rule_id in sorted(RULES)],
                    }
                },
                "results": [_sarif_result(finding) for finding in result.sorted_findings()],
                "properties": {
                    "pluginsScanned": result.plugin_count,
                    "filesScanned": result.scanned_files,
                    "filesSkipped": result.skipped_files,
                },
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def render_github(result: ScanResult) -> str:
    """Render GitHub Actions workflow annotations."""
    lines: list[str] = []
    for finding in result.sorted_findings():
        level = _github_level(finding.severity)
        rule = get_rule(finding.rule_id)
        properties = ",".join(
            [
                f"file={_escape_property(finding.path)}",
                f"line={max(finding.line, 1)}",
                f"col={max(finding.column, 1)}",
                f"title={_escape_property(f'{finding.rule_id} {rule.title}')}",
            ]
        )
        lines.append(f"::{level} {properties}::{_escape_message(finding.message)}")
    return ("\n".join(lines) + "\n") if lines else ""


def render(
    result: ScanResult,
    report_format: str,
    threshold: Severity | None = Severity.HIGH,
) -> str:
    """Dispatch to a named reporter."""
    reporters = {
        "text": lambda: render_text(result, threshold),
        "json": lambda: render_json(result),
        "sarif": lambda: render_sarif(result),
        "github": lambda: render_github(result),
    }
    try:
        return reporters[report_format]()
    except KeyError as exc:
        raise ValueError(f"unknown report format: {report_format}") from exc


def _sarif_rule(rule: Any) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.title.replace(" ", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": f"{rule.description} {rule.remediation}",
            "markdown": f"{rule.description}\n\n**Remediation:** {rule.remediation}",
        },
        "helpUri": f"{INFORMATION_URI}#rules",
        "defaultConfiguration": {"level": _sarif_level(rule.default_severity)},
        "properties": {
            "category": rule.category,
            "security-severity": SECURITY_SCORES[rule.default_severity],
            "tags": ["security", "hermes-agent", rule.category],
        },
    }


def _sarif_result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(finding.line, 1),
                        "startColumn": max(finding.column, 1),
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint,
        },
        "properties": {
            "security-severity": SECURITY_SCORES[finding.severity],
        },
    }


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _github_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "notice"


def _escape_property(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escape_message(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
