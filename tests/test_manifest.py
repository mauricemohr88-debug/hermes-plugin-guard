from __future__ import annotations

from pathlib import Path

import pytest

from hermes_plugin_guard.manifest import VALID_KINDS, inspect_manifest


def _write_manifest(root: Path, text: str, *, entry_point: bool = True) -> Path:
    root.mkdir()
    (root / "plugin.yaml").write_text(text, encoding="utf-8")
    if entry_point:
        (root / "__init__.py").write_text("", encoding="utf-8")
    return root


def test_safe_manifest_supports_rich_env_and_hook_aliases(safe_plugin: Path) -> None:
    metadata, findings = inspect_manifest(safe_plugin, safe_plugin)

    assert findings == []
    assert metadata.valid is True
    assert metadata.name == "safe-example"
    assert metadata.declared_hooks == {"on_session_start"}
    assert metadata.declared_tools == {"safe_echo"}
    assert metadata.declared_env == {"SAFE_PLUGIN_TOKEN"}


@pytest.mark.parametrize("kind", sorted(VALID_KINDS))
def test_all_documented_plugin_kinds_are_accepted(tmp_path: Path, kind: str) -> None:
    root = _write_manifest(
        tmp_path / kind,
        f"name: example\nversion: 1.0.0\ndescription: Example\nkind: {kind}\n",
    )

    _, findings = inspect_manifest(root, root)

    assert "HPG004" not in {finding.rule_id for finding in findings}


def test_manifest_reports_invalid_yaml_with_source_location(tmp_path: Path) -> None:
    root = _write_manifest(
        tmp_path / "bad-yaml",
        "name: [unterminated\nversion: 1.0.0\n",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert len(findings) == 1
    assert findings[0].rule_id == "HPG002"
    assert findings[0].path == "plugin.yaml"
    assert findings[0].line >= 1


def test_duplicate_manifest_keys_are_rejected(tmp_path: Path) -> None:
    root = _write_manifest(
        tmp_path / "duplicate-key",
        "name: first\nname: second\nversion: 1.0.0\ndescription: Example\n",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert len(findings) == 1
    assert findings[0].rule_id == "HPG002"
    assert "duplicate key" in findings[0].message


def test_manifest_reports_metadata_kind_version_hook_and_entry_point(
    tmp_path: Path,
) -> None:
    root = _write_manifest(
        tmp_path / "bad-contract",
        "\n".join(
            [
                "name: ''",
                "version: latest",
                "description: ''",
                "kind: mystery",
                "hooks:",
                "  - invented_hook",
                "",
            ]
        ),
        entry_point=False,
    )

    metadata, findings = inspect_manifest(root, root)
    ids = [finding.rule_id for finding in findings]

    assert metadata.valid is True
    assert ids.count("HPG003") == 3
    assert "HPG004" in ids
    assert "HPG005" in ids
    assert "HPG006" in ids
    assert {finding.path for finding in findings} <= {"plugin.yaml", "__init__.py"}


def test_missing_manifest_is_high_severity(tmp_path: Path) -> None:
    root = tmp_path / "missing"
    root.mkdir()

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert [(item.rule_id, item.severity.label) for item in findings] == [("HPG001", "high")]


def test_dashboard_manifest_is_a_valid_manifest_without_python_entry_point(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        (
            '{"name":"sample","version":"1.2.3",'
            '"description":"A dashboard extension","entry":"dist/index.js"}\n'
        ),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert findings == []
    assert metadata.valid is True
    assert metadata.kind == "dashboard"
    assert metadata.name == "sample"
    assert metadata.version == "1.2.3"


def test_invalid_dashboard_manifest_is_reported_as_structural_error(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        '{"name":"first","name":"duplicate"}\n',
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert len(findings) == 1
    assert findings[0].rule_id == "HPG002"
    assert findings[0].path == "dashboard/manifest.json"
    assert "duplicate key" in findings[0].message
