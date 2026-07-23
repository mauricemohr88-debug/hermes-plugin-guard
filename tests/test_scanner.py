from __future__ import annotations

from pathlib import Path

from conftest import make_clean_plugin

from hermes_plugin_guard import scan


def test_safe_fixture_has_no_findings(safe_plugin: Path) -> None:
    result = scan(safe_plugin)

    assert result.plugin_count == 1
    assert result.scanned_files >= 5
    assert result.skipped_files == 0
    assert result.findings == []


def test_risky_fixture_exercises_critical_and_high_rules(risky_plugin: Path) -> None:
    result = scan(risky_plugin)
    ids = {finding.rule_id for finding in result.findings}

    assert {
        "HPG006",
        "HPG101",
        "HPG102",
        "HPG103",
        "HPG104",
        "HPG106",
        "HPG107",
        "HPG109",
        "HPG110",
        "HPG111",
        "HPG201",
        "HPG202",
        "HPG203",
    } <= ids
    assert result.counts()["critical"] >= 2
    assert result.fails_at(None) is False


def test_scan_is_deterministic(risky_plugin: Path) -> None:
    first = scan(risky_plugin).as_dict()
    second = scan(risky_plugin).as_dict()

    assert first == second
    fingerprints = [item["fingerprint"] for item in first["findings"]]
    assert len(fingerprints) == len(set(fingerprints))


def test_scan_never_imports_or_executes_target_code(risky_plugin: Path) -> None:
    marker = risky_plugin / "EXECUTED"
    marker.unlink(missing_ok=True)

    scan(risky_plugin)

    assert not marker.exists()


def test_scanner_does_not_follow_file_symlinks_outside_root(tmp_path: Path) -> None:
    external = tmp_path / "external.py"
    external.write_text('KEY = "sk-' + ("B" * 32) + '"\n', encoding="utf-8")
    plugin = make_clean_plugin(tmp_path / "plugin")
    (plugin / "outside.py").symlink_to(external)

    result = scan(plugin)

    assert [(finding.rule_id, finding.path) for finding in result.findings] == [
        ("HPG002", "outside.py")
    ]
    assert "HPG201" not in {finding.rule_id for finding in result.findings}


def test_excluded_rules_are_removed_after_analysis(risky_plugin: Path) -> None:
    result = scan(risky_plugin, excluded_rules=["hpg201", "HPG103"])

    assert {"HPG201", "HPG103"}.isdisjoint(finding.rule_id for finding in result.findings)


def test_missing_target_and_file_target_fail_cleanly(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    regular_file = tmp_path / "file.py"
    regular_file.write_text("", encoding="utf-8")

    try:
        scan(missing)
    except FileNotFoundError as exc:
        assert str(missing) in str(exc)
    else:
        raise AssertionError("missing path must fail")

    try:
        scan(regular_file)
    except NotADirectoryError as exc:
        assert str(regular_file) in str(exc)
    else:
        raise AssertionError("file target must fail")


def test_plugin_yml_compatibility_trap_is_reported(tmp_path: Path) -> None:
    plugin = make_clean_plugin(tmp_path / "plugin-yml")
    (plugin / "plugin.yaml").rename(plugin / "plugin.yml")

    result = scan(plugin)

    manifest_findings = [finding for finding in result.findings if finding.rule_id == "HPG001"]
    assert result.plugin_count == 1
    assert len(manifest_findings) == 1
    assert "plugin.yml exists" in manifest_findings[0].message
