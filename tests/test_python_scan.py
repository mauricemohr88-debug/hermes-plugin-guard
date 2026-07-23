from __future__ import annotations

from pathlib import Path

from hermes_plugin_guard.python_scan import inspect_python


def _inspect(tmp_path: Path, source: str, declared_env: set[str] | None = None):
    path = tmp_path / "plugin.py"
    path.write_text(source, encoding="utf-8")
    return inspect_python(path, tmp_path, declared_env or set())


def test_alias_resolution_finds_process_deserialization_and_unsafe_yaml(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import subprocess as sp",
                "from os import system as invoke",
                "from pickle import loads as restore",
                "import yaml as y",
                "def handler(blob):",
                "    sp.run(['echo', 'x'])",
                "    invoke('echo x')",
                "    restore(blob)",
                "    return y.load(blob)",
                "",
            ]
        ),
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG103") == 2
    assert ids.count("HPG102") == 2


def test_dynamic_execution_shell_true_and_sensitive_path_are_high_risk(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import subprocess",
                "KEY = '~/.ssh/id_ed25519'",
                "def register(ctx):",
                "    exec('pass')",
                "    subprocess.run('echo unsafe', shell=True)",
                "",
            ]
        ),
    )
    by_rule = {finding.rule_id: finding for finding in inspection.findings}

    assert by_rule["HPG101"].severity.label == "high"
    assert by_rule["HPG103"].severity.label == "critical"
    assert by_rule["HPG104"].path == "plugin.py"
    assert by_rule["HPG111"].severity.label == "high"


def test_network_alias_tls_listener_and_declared_environment_handling(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "from requests import get as fetch",
                "from os import getenv as read_env",
                "import socket as sock",
                "def handler():",
                "    read_env('DECLARED_API_TOKEN')",
                "    read_env('MISSING_API_TOKEN')",
                "    fetch('https://example.invalid', verify=False)",
                "    server = sock.socket()",
                "    server.bind(('0.0.0.0', 8080))",
                "",
            ]
        ),
        {"DECLARED_API_TOKEN"},
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG106") == 2
    assert ids.count("HPG107") == 1
    assert "MISSING_API_TOKEN" in next(
        finding.message for finding in inspection.findings if finding.rule_id == "HPG107"
    )
    assert "HPG109" in ids
    assert "HPG105" in ids


def test_safe_yaml_loader_and_regular_subprocess_definition_do_not_overreport(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import yaml",
                "def parse(blob):",
                "    return yaml.load(blob, Loader=yaml.SafeLoader)",
                "",
            ]
        ),
    )

    assert "HPG102" not in {finding.rule_id for finding in inspection.findings}


def test_privileged_surfaces_and_literal_hooks_are_recorded(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "def register(ctx):",
                "    ctx.register_tool(name='terminal', fn=lambda: None, override=True)",
                "    ctx.register_hook('pre_gateway_dispatch', lambda event: event)",
                "    ctx.inject_message('hello')",
                "",
            ]
        ),
    )

    privileged = [finding for finding in inspection.findings if finding.rule_id == "HPG110"]
    assert len(privileged) == 2
    assert any(finding.severity.label == "critical" for finding in privileged)
    assert inspection.literal_hooks == {
        "pre_gateway_dispatch": ("plugin.py", 3),
    }


def test_positional_override_and_keyword_hook_name_are_detected(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "def register(ctx):",
                "    ctx.register_tool(",
                "        'terminal', 'fixture', {}, lambda: None,",
                "        None, None, False, '', '', True,",
                "    )",
                "    ctx.register_hook(",
                "        hook_name='pre_gateway_dispatch', callback=lambda event: event",
                "    )",
                "",
            ]
        ),
    )

    override = next(
        finding
        for finding in inspection.findings
        if finding.rule_id == "HPG110" and "overrides registered tool" in finding.message
    )
    assert override.severity.label == "critical"
    assert inspection.literal_hooks == {
        "pre_gateway_dispatch": ("plugin.py", 6),
    }


def test_definition_time_calls_are_distinguished_from_lazy_lambda_body(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import subprocess",
                "def eager(value=subprocess.run(['echo', 'default'])):",
                "    return value",
                "lazy = lambda: subprocess.run(['echo', 'later'])",
                "",
            ]
        ),
    )

    load_time = [finding for finding in inspection.findings if finding.rule_id == "HPG111"]
    assert len(load_time) == 1
    assert load_time[0].line == 2


def test_additional_dynamic_and_pickle_backed_loaders_are_detected(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import numpy",
                "import runpy",
                "import torch",
                "runpy.run_path('generated.py')",
                "torch.load('model.pt')",
                "numpy.load('array.npy', allow_pickle=True)",
                "torch.load('weights.pt', weights_only=True)",
                "",
            ]
        ),
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG101") == 1
    assert ids.count("HPG102") == 2


def test_syntax_errors_become_findings_instead_of_exceptions(tmp_path: Path) -> None:
    inspection = _inspect(tmp_path, "def broken(:\n")

    assert len(inspection.findings) == 1
    assert inspection.findings[0].rule_id == "HPG002"
    assert inspection.findings[0].line == 1
