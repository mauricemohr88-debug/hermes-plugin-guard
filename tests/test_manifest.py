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


def test_optional_environment_and_memory_provider_lifecycle_are_supported(
    tmp_path: Path,
) -> None:
    root = _write_manifest(
        tmp_path / "memory-provider",
        "\n".join(
            [
                "name: memory-example",
                "version: 1.0.0",
                "description: Example memory provider",
                "optional_env:",
                "  - name: MEMORY_OPTIONAL_TOKEN",
                "hooks:",
                "  - on_pre_compress",
                "  - on_session_end",
                "",
            ]
        ),
    )
    (root / "__init__.py").write_text(
        "\n".join(
            [
                "class MemoryProvider:",
                "    pass",
                "",
                "def register_memory_provider():",
                "    return MemoryProvider()",
                "",
            ]
        ),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert findings == []
    assert metadata.kind == "exclusive"
    assert metadata.declared_env == {"MEMORY_OPTIONAL_TOKEN"}
    assert metadata.has_hook_declarations is False


@pytest.mark.parametrize("kind", sorted(VALID_KINDS))
def test_all_documented_plugin_kinds_are_accepted(tmp_path: Path, kind: str) -> None:
    root = _write_manifest(
        tmp_path / kind,
        f"name: example\nversion: 1.0.0\ndescription: Example\nkind: {kind}\n",
    )

    _, findings = inspect_manifest(root, root)

    assert "HPG004" not in {finding.rule_id for finding in findings}


@pytest.mark.parametrize(
    "hook",
    [
        "pre_verify",
        "kanban_task_claimed",
        "kanban_task_completed",
        "kanban_task_blocked",
    ],
)
def test_current_hermes_hooks_are_accepted(tmp_path: Path, hook: str) -> None:
    root = _write_manifest(
        tmp_path / hook,
        "\n".join(
            [
                "name: example",
                "version: 1.0.0",
                "description: Example",
                "hooks:",
                f"  - {hook}",
                "",
            ]
        ),
    )

    _, findings = inspect_manifest(root, root)

    assert "HPG006" not in {finding.rule_id for finding in findings}


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


def test_pip_entry_point_package_uses_pyproject_metadata(tmp_path: Path) -> None:
    root = tmp_path / "entrypoint-plugin"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "example-hermes-plugin"',
                'version = "1.2.3rc1"',
                'description = "Example pip-distributed Hermes plugin"',
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'example = "example_plugin"',
                'second-example = "example_plugin"',
                "",
            ]
        ),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert findings == []
    assert metadata.valid is True
    assert metadata.name == "example-hermes-plugin"
    assert metadata.version == "1.2.3rc1"
    assert metadata.kind == "entrypoint"
    assert metadata.has_hook_declarations is False
    assert metadata.entry_point_count == 2


def test_dynamic_pip_package_metadata_is_accepted(tmp_path: Path) -> None:
    root = tmp_path / "entrypoint-plugin"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "example-hermes-plugin"',
                'dynamic = ["version", "description"]',
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'example = "example_plugin"',
                "",
            ]
        ),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert findings == []
    assert metadata.valid is True
    assert metadata.name == "example-hermes-plugin"
    assert metadata.version == ""


def test_empty_pip_entry_point_group_is_invalid(tmp_path: Path) -> None:
    root = tmp_path / "entrypoint-plugin"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "example-hermes-plugin"',
                'version = "1.2.3"',
                'description = "Example pip-distributed Hermes plugin"',
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'example = ""',
                "",
            ]
        ),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert [(finding.rule_id, finding.path) for finding in findings] == [
        ("HPG002", "pyproject.toml")
    ]
    assert findings[0].line == 6


def test_mixed_valid_and_invalid_pip_entry_points_are_rejected(
    tmp_path: Path,
) -> None:
    root = tmp_path / "entrypoint-plugin"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "example-hermes-plugin"',
                'version = "1.2.3"',
                'description = "Example pip-distributed Hermes plugin"',
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'valid = "example_plugin"',
                "broken = 42",
                "",
            ]
        ),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert metadata.entry_point_count == 2
    assert [(finding.rule_id, finding.path) for finding in findings] == [
        ("HPG002", "pyproject.toml")
    ]


def test_ordinary_pyproject_is_not_a_hermes_entry_point_manifest(tmp_path: Path) -> None:
    root = tmp_path / "ordinary-package"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "ordinary-package"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert [(finding.rule_id, finding.path) for finding in findings] == [("HPG001", "plugin.yaml")]


def test_invalid_entry_point_pyproject_is_reported_as_structural_error(
    tmp_path: Path,
) -> None:
    root = tmp_path / "entrypoint-plugin"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project.entry-points."hermes_agent.plugins"]\nexample = [unterminated\n',
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert [(finding.rule_id, finding.path) for finding in findings] == [
        ("HPG002", "pyproject.toml")
    ]


def test_dashboard_manifest_is_a_valid_manifest_without_python_entry_point(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        ('{"name":"sample","label":"Sample","tab":{"path":"/sample"},"entry":"dist/index.js"}\n'),
        encoding="utf-8",
    )
    bundle = dashboard / "dist" / "index.js"
    bundle.parent.mkdir()
    bundle.write_text("export default {};\n", encoding="utf-8")

    metadata, findings = inspect_manifest(root, root)

    assert findings == []
    assert metadata.valid is True
    assert metadata.kind == "dashboard"
    assert metadata.name == "sample"
    assert metadata.version == ""


def test_dashboard_manifest_reports_missing_runtime_fields(tmp_path: Path) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        '{"name":"sample","description":"Optional description","version":"1.2.3"}\n',
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is True
    assert [finding.message for finding in findings] == [
        "Required dashboard manifest field 'label' is missing or empty.",
        "Required dashboard manifest field 'entry' is missing or empty.",
        "Required dashboard manifest field 'tab.path' is missing or empty.",
    ]


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


def test_dashboard_manifest_reports_missing_entry_bundle(tmp_path: Path) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        '{"name":"sample","label":"Sample","tab":{"path":"/sample"},"entry":"dist/index.js"}\n',
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is True
    assert [(finding.rule_id, finding.path) for finding in findings] == [
        ("HPG005", "dashboard/dist/index.js")
    ]


def test_dashboard_manifest_requires_a_javascript_entry_bundle(tmp_path: Path) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        '{"name":"sample","label":"Sample","tab":{"path":"/sample"},"entry":"index.txt"}\n',
        encoding="utf-8",
    )
    (dashboard / "index.txt").write_text("not JavaScript\n", encoding="utf-8")

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is True
    assert [(finding.rule_id, finding.path) for finding in findings] == [
        ("HPG005", "dashboard/manifest.json")
    ]


@pytest.mark.parametrize(
    "entry",
    [
        "../../outside.js",
        "/tmp/outside.js",
        "C:\\outside.js",
        "\\\\server\\share\\index.js",
    ],
)
def test_dashboard_manifest_rejects_entries_outside_dashboard(
    tmp_path: Path,
    entry: str,
) -> None:
    root = tmp_path / "dashboard-plugin"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    escaped = entry.replace("\\", "\\\\")
    (dashboard / "manifest.json").write_text(
        (f'{{"name":"sample","label":"Sample","tab":{{"path":"/sample"}},"entry":"{escaped}"}}\n'),
        encoding="utf-8",
    )

    metadata, findings = inspect_manifest(root, root)

    assert metadata.valid is False
    assert [(finding.rule_id, finding.path) for finding in findings] == [
        ("HPG002", "dashboard/manifest.json")
    ]
