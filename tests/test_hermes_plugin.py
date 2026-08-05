"""Contract tests for the deliberately narrow Hermes review adapter."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPOSITORY = Path(__file__).parents[1]


class RecordingContext:
    """Small Hermes-shaped registry which also records the capability contract."""

    def __init__(self) -> None:
        self.tools: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []

    def register_tool(self, **kwargs: Any) -> None:
        self.tools.append(kwargs)

    def register_cli_command(self, **kwargs: Any) -> None:
        self.commands.append(kwargs)


@pytest.fixture
def adapter() -> ModuleType:
    return importlib.import_module("hermes_plugin_guard.hermes_plugin")


@pytest.fixture
def hermes_plugins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "hermes-home"
    plugins = home / "plugins"
    plugins.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return plugins


def install_fixture(
    plugins: Path,
    key: str,
    fixture: str,
    *,
    manifest_name: str | None = None,
) -> Path:
    destination = plugins / key
    shutil.copytree(
        REPOSITORY / "tests" / "fixtures" / fixture,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    manifest_path = destination / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["name"] = manifest_name or key.rsplit("/", 1)[-1]
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return destination


def invoke(adapter: ModuleType, candidate: object) -> dict[str, Any]:
    raw = adapter.review_candidate({"candidate": candidate})
    assert isinstance(raw, str)
    assert len(raw.encode("utf-8")) <= 16_384
    return json.loads(raw)


def assert_bounded_error(response: dict[str, Any], forbidden: str = "") -> None:
    assert response["ok"] is False
    assert response["status"] == "error"
    assert isinstance(response["error"], dict)
    assert set(response["error"]).issubset({"code", "message"})
    assert len(response["error"].get("message", "")) <= 240
    if forbidden:
        assert forbidden not in json.dumps(response)


def test_registers_one_read_only_tool_and_plugin_guard_command(adapter: ModuleType) -> None:
    context = RecordingContext()

    adapter.register(context)

    assert len(context.tools) == 1
    tool = context.tools[0]
    assert tool["name"] == adapter.TOOL_NAME == "plugin_guard_review_candidate"
    assert tool.get("handler", tool.get("fn")) is adapter.review_candidate
    assert tool["toolset"] == "hermes_plugin_guard"
    assert tool["schema"] is adapter.TOOL_SCHEMA
    assert tool["schema"]["name"] == adapter.TOOL_NAME
    parameters = tool["schema"]["parameters"]
    assert parameters["type"] == "object"
    assert parameters["required"] == ["candidate"]
    assert parameters.get("additionalProperties") is False
    assert set(parameters["properties"]) == {"candidate"}
    assert len(context.commands) == 1
    assert context.commands[0]["name"] == "plugin-guard"
    assert callable(context.commands[0]["setup_fn"])
    assert callable(context.commands[0]["handler_fn"])

    serialized = json.dumps({"tool": tool, "command": context.commands[0]}, default=str).lower()
    for forbidden in ("write", "network", "shell", "subprocess", "override"):
        assert forbidden not in serialized


def test_review_is_inert_and_reports_only_a_safe_projection(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "risky", "risky_plugin")
    sentinel = candidate / "EXECUTED"

    response = invoke(adapter, "risky")

    assert not sentinel.exists(), "reviewing a candidate must never import its code"
    assert response["ok"] is True
    assert response["status"] == "review_required"
    assert response["candidate"] == "risky"
    assert response["summary"]["counts"]["critical"] >= 1
    assert "tree_sha256" not in response
    assert len(response["findings"]) <= 20
    assert all(
        set(item) == {"rule_id", "severity", "location_id", "line"} for item in response["findings"]
    )

    rendered = json.dumps(response)
    for forbidden in (
        str(candidate),
        "EXECUTED",
        "ADMIN_API_TOKEN",
        "PRIVATE_KEY_PATH",
        "synthetic injected message",
        "evidence",
        "message",
    ):
        assert forbidden not in rendered
    assert all(item["location_id"].startswith("loc-") for item in response["findings"])


def test_safe_candidate_passes_and_output_is_deterministic(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    install_fixture(hermes_plugins, "safe", "safe_plugin")

    first = adapter.review_candidate({"candidate": "safe"})
    second = adapter.review_candidate({"candidate": "safe"})
    response = json.loads(first)

    assert first == second
    assert response["ok"] is True
    assert response["status"] == "pass"
    assert response["summary"]["counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_review_does_not_bypass_importable_code_under_tests(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "safe", "safe_plugin")
    test_module = candidate / "tests" / "test_loadable_payload.py"
    test_module.write_text("eval('1 + 1')\n", encoding="utf-8")

    response = invoke(adapter, "safe")

    assert response["ok"] is True
    assert response["status"] == "review_required"
    assert response["summary"]["counts"]["high"] >= 1


@pytest.mark.parametrize("enabled_alias", ["category/plugin", "display-plugin"])
def test_nested_category_candidate_rejects_all_enabled_aliases(
    adapter: ModuleType, hermes_plugins: Path, enabled_alias: str
) -> None:
    install_fixture(
        hermes_plugins,
        "category/plugin",
        "safe_plugin",
        manifest_name="display-plugin",
    )
    (hermes_plugins.parent / "config.yaml").write_text(
        f"plugins:\n  enabled:\n    - {enabled_alias}\n", encoding="utf-8"
    )

    response = invoke(adapter, "category/plugin")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "candidate_enabled"


def test_nested_category_candidate_resolves_exact_plugin_root(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    install_fixture(
        hermes_plugins,
        "category/plugin",
        "safe_plugin",
        manifest_name="display-plugin",
    )

    response = invoke(adapter, "category/plugin")

    assert response["ok"] is True
    assert response["status"] == "pass"
    assert response["candidate"] == "category/plugin"


@pytest.mark.parametrize("candidate", ["safe/tests", "safe/tests/deeper"])
def test_rejects_subdirectories_instead_of_reviewing_a_non_plugin_root(
    adapter: ModuleType,
    hermes_plugins: Path,
    candidate: str,
) -> None:
    install_fixture(hermes_plugins, "safe", "safe_plugin")

    response = invoke(adapter, candidate)

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] in {"candidate_not_found", "invalid_candidate"}


def test_rejects_category_namespace_without_a_direct_manifest(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    install_fixture(hermes_plugins, "category/plugin", "safe_plugin")

    response = invoke(adapter, "category")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "candidate_not_found"


def test_flat_candidate_requires_the_manifest_identity(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    install_fixture(hermes_plugins, "directory-name", "safe_plugin", manifest_name="other-name")

    response = invoke(adapter, "directory-name")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "manifest_invalid"


def test_review_output_uses_opaque_locations_for_unicode_secret_filenames(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "safe", "safe_plugin")
    filename = "\N{PILE OF POO}-TOP_SECRET-sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.py"
    (candidate / filename).write_text("eval('1 + 1')\n", encoding="utf-8")

    raw = adapter.review_candidate({"candidate": "safe"})
    response = json.loads(raw)

    assert len(raw.encode("utf-8")) <= 16_384
    assert response["status"] == "review_required"
    assert filename not in raw
    assert "TOP_SECRET" not in raw
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in raw
    assert all(item["location_id"].startswith("loc-") for item in response["findings"])
    predictable = "loc-" + hashlib.sha256(filename.encode()).hexdigest()[:16]
    assert predictable not in {item["location_id"] for item in response["findings"]}


def test_rejects_unsupported_binary_in_an_otherwise_ignored_directory(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "safe", "safe_plugin")
    ignored = candidate / ".venv"
    ignored.mkdir()
    (ignored / "unreviewable.so").write_bytes(b"\x7fELF")

    response = invoke(adapter, "safe")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "unsupported_tree"


@pytest.mark.parametrize(
    "payload",
    [
        b"\x7fELF\x02\x01\x01\x00",
        b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01",
        b"MZ" + (b"\x00" * 62),
        b"\x00asm\x01\x00\x00\x00",
    ],
)
def test_rejects_extensionless_executable_binary_magic(
    adapter: ModuleType,
    hermes_plugins: Path,
    payload: bytes,
) -> None:
    candidate = install_fixture(hermes_plugins, "safe", "safe_plugin")
    (candidate / "helper.bin").write_bytes(payload)

    response = invoke(adapter, "safe")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "unsupported_tree"


def test_rejects_plugin_kinds_with_separate_activation_paths(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "provider", "safe_plugin")
    manifest_path = candidate / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["kind"] = "model-provider"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    response = invoke(adapter, "provider")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "unsupported_plugin_kind"


@pytest.mark.parametrize(
    ("legacy_marker", "declare_standalone"),
    [
        ("class MemoryProvider:\n    pass\n", False),
        ("class MemoryProvider:\n    pass\n", True),
        ("def register_provider(value):\n    return ProviderProfile(value)\n", False),
        ("def register_provider(value):\n    return ProviderProfile(value)\n", True),
        ("class CronScheduler:\n    pass\n", True),
    ],
)
def test_rejects_legacy_plugins_hermes_routes_outside_enabled_allowlist(
    adapter: ModuleType,
    hermes_plugins: Path,
    legacy_marker: str,
    declare_standalone: bool,
) -> None:
    candidate = install_fixture(hermes_plugins, "legacy", "safe_plugin")
    manifest_path = candidate / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if declare_standalone:
        manifest["kind"] = "standalone"
    else:
        manifest.pop("kind")
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    (candidate / "__init__.py").write_text(legacy_marker, encoding="utf-8")

    response = invoke(adapter, "legacy")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "unsupported_plugin_kind"


def test_rejects_reserved_model_provider_category_regardless_of_declared_kind(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    install_fixture(
        hermes_plugins,
        "model-providers/modx",
        "safe_plugin",
        manifest_name="modx",
    )

    response = invoke(adapter, "model-providers/modx")

    assert_bounded_error(response, str(hermes_plugins))
    assert response["error"]["code"] == "unsupported_plugin_kind"


def test_concurrent_model_review_fails_closed_without_waiting(adapter: ModuleType) -> None:
    assert adapter._REVIEW_SLOT.acquire(blocking=False)
    try:
        response = invoke(adapter, "safe")
    finally:
        adapter._REVIEW_SLOT.release()

    assert_bounded_error(response)
    assert response["error"]["code"] == "review_busy"


@pytest.mark.parametrize(
    "candidate", [None, 7, "", "../risky", "risky/../safe", "/tmp/risky", "safe\\.."]
)
def test_rejects_non_key_and_traversal_inputs(
    adapter: ModuleType, hermes_plugins: Path, candidate: object
) -> None:
    install_fixture(hermes_plugins, "safe", "safe_plugin")

    assert_bounded_error(invoke(adapter, candidate), str(hermes_plugins))


def test_rejects_active_candidate(adapter: ModuleType, hermes_plugins: Path) -> None:
    install_fixture(hermes_plugins, "safe", "safe_plugin")
    (hermes_plugins.parent / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - safe\n", encoding="utf-8"
    )

    assert_bounded_error(invoke(adapter, "safe"), str(hermes_plugins))


@pytest.mark.parametrize("kind", ["candidate-link", "inside-link"])
def test_rejects_symlinked_candidates(adapter: ModuleType, hermes_plugins: Path, kind: str) -> None:
    target = install_fixture(hermes_plugins, "real", "safe_plugin")
    if kind == "candidate-link":
        (hermes_plugins / "linked").symlink_to(target, target_is_directory=True)
        key = "linked"
    else:
        (target / "linked-source.py").symlink_to(target / "__init__.py")
        key = "real"

    assert_bounded_error(invoke(adapter, key), str(hermes_plugins))


def test_rejects_oversize_and_broken_configuration(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "safe", "safe_plugin")
    (candidate / "large.txt").write_bytes(b"x" * (1_048_577))
    assert_bounded_error(invoke(adapter, "safe"), str(hermes_plugins))

    (candidate / "large.txt").unlink()
    (hermes_plugins.parent / "config.yaml").write_text("plugins: [", encoding="utf-8")
    assert_bounded_error(invoke(adapter, "safe"), str(hermes_plugins))


def test_result_is_limited_even_with_many_findings(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "many", "risky_plugin")
    (candidate / "many.py").write_text(
        "\n".join("eval(payload)" for _ in range(80)), encoding="utf-8"
    )

    response = invoke(adapter, "many")

    assert response["ok"] is True
    assert response["status"] == "review_required"
    assert response["summary"]["findings"] > len(response["findings"])
    assert len(response["findings"]) == 20
    assert len(json.dumps(response)) <= 16_384


def test_incomplete_worker_analysis_is_explicit_and_fails_closed(
    adapter: ModuleType, hermes_plugins: Path
) -> None:
    candidate = install_fixture(hermes_plugins, "many", "safe_plugin")
    (candidate / "many.py").write_text(
        "\n".join("eval(payload)" for _ in range(300)), encoding="utf-8"
    )

    response = invoke(adapter, "many")

    assert response["ok"] is True
    assert response["status"] == "review_required"
    assert response["summary"]["finding_limit_reached"] is True
    assert response["summary"]["findings"] == adapter.MAX_WORKER_FINDINGS
    assert response["truncated"] is True


def test_native_operator_cli_scans_an_installed_plugin(
    adapter: ModuleType,
    hermes_plugins: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    install_fixture(hermes_plugins, "safe", "safe_plugin")
    parser = argparse.ArgumentParser()
    adapter._setup_cli(parser)
    args = parser.parse_args(["installed", "safe", "--format", "json", "--fail-on", "none"])

    assert adapter._handle_cli(args) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["root"] == "."
    assert report["summary"]["plugins"] == 1
    assert report["summary"]["counts"]["high"] == 0


def test_root_shim_loads_with_hermes_style_spec_and_manifest_is_consistent(
    adapter: ModuleType,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "isolated_hermes_plugin",
        REPOSITORY / "__init__.py",
        submodule_search_locations=[str(REPOSITORY)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        assert module.register
        manifest = yaml.safe_load((REPOSITORY / "plugin.yaml").read_text(encoding="utf-8"))
    finally:
        sys.modules.pop(spec.name, None)

    package = importlib.import_module("hermes_plugin_guard")
    assert manifest["provides_tools"] == [adapter.TOOL_NAME]
    assert manifest["version"] == package.__version__
    assert manifest["name"] == "hermes-plugin-guard"
