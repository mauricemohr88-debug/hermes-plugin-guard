from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_plugin_guard.catalog import RULES
from hermes_plugin_guard.models import Finding, ScanResult, Severity
from hermes_plugin_guard.python_scan import inspect_python
from hermes_plugin_guard.reporters import (
    render,
    render_github,
    render_json,
    render_sarif,
    render_text,
)
from hermes_plugin_guard.secret_scan import inspect_file


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(
        root=Path("/private/users/alice/plugin"),
        findings=list(findings),
        scanned_files=4,
        plugin_count=1,
        skipped_files=1,
    )


def _finding(
    rule_id: str = "HPG109",
    severity: Severity = Severity.HIGH,
    *,
    path: str = "plugin.py",
    line: int = 7,
    column: int = 3,
    message: str = "TLS verification is disabled.",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        path=path,
        line=line,
        column=column,
    )


def test_text_report_is_relative_human_readable_and_threshold_aware() -> None:
    result = _result(_finding())

    report = render_text(result, Severity.HIGH)

    assert "HIGH     HPG109" in report
    assert "plugin.py:7:3" in report
    assert "Fix:" in report
    assert "Skipped 1 file(s)" in report
    assert "Result: FAIL" in report
    assert str(result.root) not in report
    assert "Result: informational" in render_text(result, None)


def test_json_report_is_stable_and_matches_public_schema() -> None:
    result = _result(
        _finding(rule_id="HPG203", severity=Severity.LOW, path="requirements.txt"),
        _finding(),
    )

    first = render_json(result)
    second = render_json(result)
    payload = json.loads(first)

    assert first == second
    assert first.endswith("\n")
    assert payload["schema_version"] == "1.0"
    assert payload["tool"] == "hermes-plugin-guard"
    assert payload["summary"]["findings"] == 2
    assert payload["summary"]["counts"]["high"] == 1
    assert [item["rule_id"] for item in payload["findings"]] == [
        "HPG109",
        "HPG203",
    ]


def test_sarif_is_deterministic_complete_and_uses_relative_locations() -> None:
    result = _result(
        _finding(),
        _finding(
            rule_id="HPG107",
            severity=Severity.MEDIUM,
            path="nested/config.py",
            line=11,
        ),
    )

    first = render_sarif(result)
    second = render_sarif(result)
    payload = json.loads(first)
    run = payload["runs"][0]

    assert first == second
    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "hermes-plugin-guard"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == sorted(RULES)
    assert [item["level"] for item in run["results"]] == ["error", "warning"]
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {
        "uri": "plugin.py",
        "uriBaseId": "%SRCROOT%",
    }
    assert location["region"] == {"startLine": 7, "startColumn": 3}
    assert run["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert str(result.root) not in first


def test_github_annotations_escape_properties_and_messages() -> None:
    result = _result(
        _finding(
            path="dir/a:b,c%.py",
            message="line one%\nline two",
        ),
        _finding(
            rule_id="HPG107",
            severity=Severity.MEDIUM,
            message="medium",
        ),
        _finding(
            rule_id="HPG203",
            severity=Severity.LOW,
            message="low",
        ),
    )

    report = render_github(result)
    lines = report.splitlines()

    assert lines[0].startswith("::error ")
    assert "file=dir/a%3Ab%2Cc%25.py" in lines[0]
    assert "::line one%25%0Aline two" in lines[0]
    assert lines[1].startswith("::warning ")
    assert lines[2].startswith("::notice ")
    assert render_github(_result()) == ""


@pytest.mark.parametrize("report_format", ["text", "json", "sarif", "github"])
def test_no_reporter_reveals_a_complete_secret(
    tmp_path: Path,
    report_format: str,
) -> None:
    secret = "sk-" + ("C" * 32)
    path = tmp_path / "plugin.py"
    path.write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")
    result = ScanResult(root=tmp_path, findings=inspect_file(path, tmp_path))

    report = render(result, report_format)

    assert secret not in report


@pytest.mark.parametrize("report_format", ["text", "json", "sarif", "github"])
def test_no_reporter_reveals_url_credentials_paths_or_queries(
    tmp_path: Path,
    report_format: str,
) -> None:
    secret = "synthetic-url-secret"
    path = tmp_path / "plugin.py"
    path.write_text(
        "\n".join(
            [
                "import requests",
                (f"requests.post('https://alice:{secret}@example.invalid/private?token={secret}')"),
                (f"requests.get('https://example.invalid\\\\{secret}')"),
                (f"requests.get('https://example.invalid%2F{secret}')"),
                (f"requests.get('https://[fe80::1%25{secret}]/upload')"),
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = ScanResult(
        root=tmp_path,
        findings=inspect_python(path, tmp_path, set()).findings,
    )

    report = render(result, report_format)

    assert secret not in report
    assert "alice" not in report
    assert "/private" not in report
    assert "token=" not in report
    assert "example.invalid" in report


def test_unknown_report_format_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown report format"):
        render(_result(), "xml")
