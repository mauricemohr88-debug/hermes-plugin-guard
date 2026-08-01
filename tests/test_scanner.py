from __future__ import annotations

import socket
from pathlib import Path

import pytest
from conftest import make_clean_plugin

from hermes_plugin_guard import scan


def test_safe_fixture_has_no_findings(safe_plugin: Path) -> None:
    result = scan(safe_plugin)

    assert result.plugin_count == 1
    assert result.scanned_files >= 4
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
        "HPG112",
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


def test_scan_never_uses_network(
    risky_plugin: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def network_forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("scanner attempted network access")

    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", network_forbidden)
    monkeypatch.setattr(socket, "socket", network_forbidden)

    result = scan(risky_plugin)

    assert "HPG112" in {finding.rule_id for finding in result.findings}


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


def test_symlinks_in_ignored_directories_are_not_reported(tmp_path: Path) -> None:
    external = tmp_path / "external-python"
    external.write_text("#!/usr/bin/env python\n", encoding="utf-8")
    plugin = make_clean_plugin(tmp_path / "plugin")
    ignored_bin = plugin / ".venv" / "bin"
    ignored_bin.mkdir(parents=True)
    (ignored_bin / "python").symlink_to(external)
    (ignored_bin / "broken-python").symlink_to(tmp_path / "missing-python")

    result = scan(plugin)

    assert result.findings == []


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


@pytest.mark.parametrize(
    "directory",
    [
        "tests",
        "test",
        "fixtures",
        "fixture",
        "testdata",
        "test_data",
        "cache",
        ".cache",
        "venv",
        ".venv",
        "generated",
    ],
)
def test_non_production_directories_are_not_behavior_or_secret_scanned(
    tmp_path: Path,
    directory: str,
) -> None:
    plugin = make_clean_plugin(tmp_path / "plugin")
    risky_source = "\n".join(
        [
            "import subprocess",
            'TOKEN = "sk-' + ("A" * 32) + '"',
            "subprocess.run(['echo', 'review-me'])",
            "",
        ]
    )
    (plugin / "runtime.py").write_text(risky_source, encoding="utf-8")
    ignored = plugin / directory
    ignored.mkdir(exist_ok=True)
    (ignored / "fixture.py").write_text(risky_source, encoding="utf-8")

    result = scan(plugin)
    security_findings = [
        finding for finding in result.findings if finding.rule_id in {"HPG103", "HPG201"}
    ]

    assert {(finding.rule_id, finding.path) for finding in security_findings} == {
        ("HPG103", "runtime.py"),
        ("HPG201", "runtime.py"),
    }


def test_nested_src_layout_is_discovered_without_root_manifest(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    make_clean_plugin(repository / "src" / "example_plugin")
    (repository / "LICENSE").write_text("Example license\n", encoding="utf-8")
    (repository / "SECURITY.md").write_text("Example policy\n", encoding="utf-8")

    result = scan(repository)

    assert result.plugin_count == 1
    assert "HPG001" not in {finding.rule_id for finding in result.findings}
    assert result.findings == []


def test_pip_entry_point_plugin_is_discovered_without_plugin_yaml(tmp_path: Path) -> None:
    repository = tmp_path / "entrypoint-plugin"
    package = repository / "src" / "example_plugin"
    package.mkdir(parents=True)
    (repository / "pyproject.toml").write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=77,<81"]',
                'build-backend = "setuptools.build_meta"',
                "",
                "[project]",
                'name = "example-hermes-plugin"',
                'version = "1.2.3"',
                'description = "Example pip-distributed Hermes plugin"',
                "dependencies = []",
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'example = "example_plugin"',
                'second-example = "example_plugin"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (package / "__init__.py").write_text(
        "\n".join(
            [
                "def register(ctx):",
                '    ctx.register_hook("pre_tool_call", lambda **kwargs: None)',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (repository / "LICENSE").write_text("Example license\n", encoding="utf-8")
    (repository / "SECURITY.md").write_text("Example policy\n", encoding="utf-8")
    (repository / "tests").mkdir()

    result = scan(repository)
    ids = {finding.rule_id for finding in result.findings}

    assert result.plugin_count == 2
    assert result.scanned_files >= 2
    assert {"HPG001", "HPG005", "HPG006"}.isdisjoint(ids)
    assert result.findings == []

    (package / "__init__.py").write_text(
        "\n".join(
            [
                "def register(ctx):",
                '    ctx.register_hook("invented_hook", lambda **kwargs: None)',
                "",
            ]
        ),
        encoding="utf-8",
    )
    unknown_hook_result = scan(repository)

    assert "HPG006" in {finding.rule_id for finding in unknown_hook_result.findings}


def test_invalid_pip_entry_point_candidate_is_discovered_in_monorepo(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    plugin = repository / "packages" / "broken-plugin"
    plugin.mkdir(parents=True)
    (plugin / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "broken-hermes-plugin"',
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'valid = "example_plugin"',
                'broken = ""',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (repository / "LICENSE").write_text("Example license\n", encoding="utf-8")
    (repository / "SECURITY.md").write_text("Example policy\n", encoding="utf-8")
    (repository / "tests").mkdir()

    result = scan(repository)
    structural_findings = [finding for finding in result.findings if finding.rule_id == "HPG002"]

    assert result.plugin_count == 2
    assert [(finding.path, finding.line) for finding in structural_findings] == [
        ("packages/broken-plugin/pyproject.toml", 4)
    ]


def test_known_category_layouts_and_fixture_manifests_are_bounded(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    make_clean_plugin(repository / "plugins" / "model-providers" / "provider")
    make_clean_plugin(repository / ".hermes" / "plugins" / "platforms" / "channel")
    make_clean_plugin(repository / "fixtures" / "not-a-production-plugin")
    make_clean_plugin(repository / "one" / "two" / "three" / "four" / "too-deep")
    (repository / "LICENSE").write_text("Example license\n", encoding="utf-8")
    (repository / "SECURITY.md").write_text("Example policy\n", encoding="utf-8")

    result = scan(repository)

    assert result.plugin_count == 2
    assert not any(
        finding.path.startswith(("fixtures/", "one/two/three/four/")) for finding in result.findings
    )


def test_dashboard_only_plugin_uses_its_official_manifest(tmp_path: Path) -> None:
    plugin = tmp_path / "example-dashboard"
    dashboard = plugin / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "manifest.json").write_text(
        "\n".join(
            [
                "{",
                '  "name": "example",',
                '  "label": "Example",',
                '  "version": "1.0.0",',
                '  "description": "Example dashboard plugin",',
                '  "tab": {"path": "/example"},',
                '  "entry": "dist/index.js",',
                '  "api": "plugin_api.py"',
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (dashboard / "plugin_api.py").write_text(
        "def build_router():\n    return None\n",
        encoding="utf-8",
    )
    bundle = dashboard / "dist" / "index.js"
    bundle.parent.mkdir()
    bundle.write_text("export default {};\n", encoding="utf-8")
    (plugin / "LICENSE").write_text("Example license\n", encoding="utf-8")
    (plugin / "SECURITY.md").write_text("Example policy\n", encoding="utf-8")
    (plugin / "tests").mkdir()
    (plugin / "tests" / "test_dashboard.py").write_text(
        "def test_dashboard():\n    pass\n",
        encoding="utf-8",
    )

    result = scan(plugin)

    assert result.plugin_count == 1
    assert {"HPG001", "HPG005"}.isdisjoint(finding.rule_id for finding in result.findings)
    assert result.findings == []


def test_directory_plugin_also_validates_its_dashboard_manifest(tmp_path: Path) -> None:
    plugin = make_clean_plugin(tmp_path / "combined-plugin")
    dashboard = plugin / "dashboard"
    dashboard.mkdir()
    (dashboard / "manifest.json").write_text(
        '{"name":"combined","tab":{"path":"/combined"},"entry":"dist/index.js"}\n',
        encoding="utf-8",
    )
    bundle = dashboard / "dist" / "index.js"
    bundle.parent.mkdir()
    bundle.write_text("export default {};\n", encoding="utf-8")

    result = scan(plugin)

    dashboard_findings = [
        finding for finding in result.findings if finding.path == "dashboard/manifest.json"
    ]
    assert [(finding.rule_id, finding.message) for finding in dashboard_findings] == [
        ("HPG003", "Required dashboard manifest field 'label' is missing or empty.")
    ]


def test_unrecognized_dashboard_kind_cannot_skip_dashboard_validation(
    tmp_path: Path,
) -> None:
    plugin = make_clean_plugin(tmp_path / "combined-plugin")
    manifest = plugin / "plugin.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "kind: standalone",
            "kind: dashboard",
        ),
        encoding="utf-8",
    )
    dashboard = plugin / "dashboard"
    dashboard.mkdir()
    (dashboard / "manifest.json").write_text(
        (
            '{"name":"combined","label":"Combined","tab":{"path":"/combined"},'
            '"entry":"../../outside.js"}\n'
        ),
        encoding="utf-8",
    )

    result = scan(plugin)

    assert {"HPG002", "HPG004"} <= {finding.rule_id for finding in result.findings}
    assert any(
        finding.rule_id == "HPG002" and finding.path == "dashboard/manifest.json"
        for finding in result.findings
    )


def test_directory_plugin_also_validates_pip_entry_points(tmp_path: Path) -> None:
    plugin = make_clean_plugin(tmp_path / "combined-plugin")
    (plugin / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "combined-plugin"',
                'version = "1.0.0"',
                'description = "Combined plugin"',
                "",
                '[project.entry-points."hermes_agent.plugins"]',
                'valid = "combined_plugin"',
                "broken = 42",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = scan(plugin)

    assert result.plugin_count == 2
    assert any(
        finding.rule_id == "HPG002" and finding.path == "pyproject.toml"
        for finding in result.findings
    )
