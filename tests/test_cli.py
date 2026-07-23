from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_plugin_guard.cli import main


def test_clean_scan_returns_zero_and_prints_json(
    safe_plugin: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["scan", str(safe_plugin), "--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert payload["summary"]["findings"] == 0
    assert payload["summary"]["plugins"] == 1


def test_risky_scan_returns_one_by_default_and_none_disables_failure(
    risky_plugin: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["scan", str(risky_plugin)]) == 1
    first = capsys.readouterr()
    assert "Result: FAIL" in first.out

    assert main(["scan", str(risky_plugin), "--fail-on", "none"]) == 0
    second = capsys.readouterr()
    assert "Result: informational" in second.out


def test_fail_on_threshold_changes_exit_code(
    risky_plugin: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "scan",
                str(risky_plugin),
                "--exclude",
                "HPG201",
                "--exclude",
                "HPG103",
                "--exclude",
                "HPG110",
                "--fail-on",
                "critical",
            ]
        )
        == 0
    )
    capsys.readouterr()


def test_excluded_rule_ids_are_case_insensitive(
    risky_plugin: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["scan", str(risky_plugin), "--exclude", "hpg201", "--fail-on", "critical"]) == 1
    report = capsys.readouterr().out

    assert "HPG201" not in report


def test_output_file_receives_report_and_stdout_stays_empty(
    safe_plugin: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "nested" / "scan.sarif"

    exit_code = main(
        [
            "scan",
            str(safe_plugin),
            "--format",
            "sarif",
            "--output",
            str(output),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_missing_path_returns_two_and_explains_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["scan", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "scan target does not exist" in captured.err


def test_rules_command_supports_machine_readable_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["rules", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload[0]["id"] == "HPG001"
    assert {"id", "severity", "title", "category", "description", "remediation"} <= set(payload[0])


def test_invalid_cli_choice_uses_argparse_exit_two() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["scan", ".", "--format", "xml"])

    assert exc_info.value.code == 2
