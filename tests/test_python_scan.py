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


def test_outbound_calls_report_redacted_destinations_and_risk_tiers(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import httpx",
                "import requests",
                "import socket",
                "import urllib.request",
                "from requests import post as send",
                "def handler(url):",
                "    send('https://alice:secret@example.invalid/upload?token=secret')",
                "    requests.get('http://api.example.invalid/v1')",
                "    httpx.get('http://127.0.0.1:8080/health')",
                "    urllib.request.urlopen('http://169.254.169.254/latest/meta-data')",
                "    socket.create_connection(('fd00:ec2::254', 80))",
                "    requests.post(url)",
                "",
            ]
        ),
    )
    findings = [finding for finding in inspection.findings if finding.rule_id == "HPG112"]

    assert len(findings) == 6
    assert [finding.severity.label for finding in findings] == [
        "medium",
        "high",
        "low",
        "high",
        "high",
        "medium",
    ]
    assert [finding.evidence for finding in findings] == [
        "requests.post -> https://example.invalid",
        "requests.get -> http://api.example.invalid",
        "httpx.get -> http://127.0.0.1:8080",
        "urllib.request.urlopen -> http://169.254.169.254",
        "socket.create_connection -> tcp://[fd00:ec2::254]:80",
        "requests.post -> <dynamic destination>",
    ]
    serialized = "\n".join(f"{finding.message}\n{finding.evidence}" for finding in findings)
    assert "alice" not in serialized
    assert "secret" not in serialized
    assert "/upload" not in serialized
    assert "token=" not in serialized


def test_client_instances_context_managers_and_request_objects_are_traced(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import asyncio",
                "import aiohttp",
                "import http.client",
                "import httpx",
                "import socket",
                "import urllib.request",
                "class Plugin:",
                "    def __init__(self):",
                "        self.client = httpx.Client(",
                "            base_url='https://user:pass@api.example.invalid/v1?key=x'",
                "        )",
                "    def close(self):",
                "        self.client = None",
                "    def publish(self):",
                "        self.client.post('/events')",
                "async def handler(url):",
                "    async with aiohttp.ClientSession() as session:",
                "        await session.get(url)",
                "    sock = socket.socket()",
                "    sock.connect(('203.0.113.10', 443))",
                "    connection = http.client.HTTPSConnection(",
                "        'service.example.invalid', 8443",
                "    )",
                "    connection.request('GET', '/v1')",
                "    await asyncio.open_connection('stream.example.invalid', 9443)",
                "    request = urllib.request.Request(",
                "        'https://name:password@download.example.invalid/archive?sig=hidden'",
                "    )",
                "    urllib.request.urlopen(request)",
                "",
            ]
        ),
    )
    evidence = [finding.evidence for finding in inspection.findings if finding.rule_id == "HPG112"]

    assert evidence == [
        "httpx.Client.post -> https://api.example.invalid",
        "aiohttp.ClientSession.get -> <dynamic destination>",
        "socket.socket.connect -> tcp://203.0.113.10:443",
        "http.client.HTTPSConnection.request -> https://service.example.invalid:8443",
        "asyncio.open_connection -> tcp://stream.example.invalid:9443",
        "urllib.request.urlopen -> https://download.example.invalid",
    ]
    assert all(
        forbidden not in "\n".join(item or "" for item in evidence)
        for forbidden in ("password", "hidden", "user", "/archive")
    )


def test_network_imports_url_literals_and_unrelated_post_methods_do_not_claim_egress(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import requests",
                "URL = 'https://example.invalid/documentation?token=synthetic'",
                "class Store:",
                "    def post(self, value):",
                "        return value",
                "def handler():",
                "    session = requests.Session()",
                "    return Store().post(URL), session",
                "",
            ]
        ),
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG106") == 1
    assert "HPG112" not in ids


def test_chained_walrus_and_callable_alias_egress_are_detected(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import grpc",
                "import httpx",
                "import requests",
                "import socket",
                "import urllib.request",
                "def handler():",
                "    httpx.Client(base_url='https://one.example.invalid').post('/events')",
                "    requests.Session().get('https://two.example.invalid/items')",
                "    socket.socket().connect(('198.51.100.5', 443))",
                "    send = requests.post",
                "    send('https://three.example.invalid/hook')",
                "    (client := httpx.Client(",
                "        base_url='https://four.example.invalid'",
                "    )).get('/status')",
                "    bound = client.post",
                "    bound('/publish')",
                "    urllib.request.build_opener().open(",
                "        'https://five.example.invalid/download'",
                "    )",
                "    grpc.secure_channel('dns:///rpc.example.invalid:443')",
                "    (send_now := requests.post)(",
                "        'https://six.example.invalid/notify'",
                "    )",
                "",
            ]
        ),
    )
    evidence = [finding.evidence for finding in inspection.findings if finding.rule_id == "HPG112"]

    assert evidence == [
        "httpx.Client.post -> https://one.example.invalid",
        "requests.Session.get -> https://two.example.invalid",
        "socket.socket.connect -> tcp://198.51.100.5:443",
        "requests.post -> https://three.example.invalid",
        "httpx.Client.get -> https://four.example.invalid",
        "httpx.Client.post -> https://four.example.invalid",
        "urllib.request.OpenerDirector.open -> https://five.example.invalid",
        "grpc.secure_channel -> grpcs://rpc.example.invalid:443",
        "requests.post -> https://six.example.invalid",
    ]


def test_control_flow_merges_possible_network_clients(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import httpx",
                "class Fake:",
                "    def post(self, value):",
                "        return value",
                "def conditional(enabled):",
                "    if enabled:",
                "        client = httpx.Client(base_url='https://if.example.invalid')",
                "    else:",
                "        client = Fake()",
                "    client.post('/send')",
                "def guarded():",
                "    try:",
                "        client = httpx.Client(base_url='https://try.example.invalid')",
                "    except Exception:",
                "        client = Fake()",
                "    client.post('/send')",
                "def interrupted():",
                "    client = Fake()",
                "    try:",
                "        client = httpx.Client(",
                "            base_url='https://intermediate.example.invalid'",
                "        )",
                "        may_raise()",
                "        client = Fake()",
                "    except Exception:",
                "        pass",
                "    client.post('/send')",
                "def repeated(values):",
                "    client = httpx.Client(base_url='https://loop.example.invalid')",
                "    for _ in values:",
                "        client = Fake()",
                "    client.post('/send')",
                "",
            ]
        ),
    )
    evidence = [finding.evidence for finding in inspection.findings if finding.rule_id == "HPG112"]

    assert evidence == [
        "httpx.Client.post -> https://if.example.invalid",
        "httpx.Client.post -> https://try.example.invalid",
        "httpx.Client.post -> https://intermediate.example.invalid",
        "httpx.Client.post -> https://loop.example.invalid",
    ]


def test_relative_imports_do_not_impersonate_network_dependencies(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "from .requests import get",
                "def register(ctx):",
                "    get('http://local-package.example.invalid')",
                "",
            ]
        ),
    )
    ids = {finding.rule_id for finding in inspection.findings}

    assert {"HPG106", "HPG111", "HPG112"}.isdisjoint(ids)


def test_local_rebinding_and_parameters_shadow_network_aliases_and_instances(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import requests",
                "client = requests.Session()",
                "class Fake:",
                "    def get(self, url):",
                "        return url",
                "def parameter_shadow(requests, client):",
                "    return requests.get('https://one.invalid'), client.get('https://two.invalid')",
                "def assignment_shadow():",
                "    requests = Fake()",
                "    client = Fake()",
                "    return requests.get('https://three.invalid'), client.get('https://four.invalid')",
                "",
            ]
        ),
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG106") == 1
    assert "HPG112" not in ids


def test_loop_with_comprehension_and_class_import_targets_shadow_modules(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "class Fake:",
                "    def __enter__(self):",
                "        return self",
                "    def __exit__(self, *args):",
                "        return None",
                "    def get(self, url):",
                "        return url",
                "class Namespace:",
                "    import requests",
                "requests.get('http://not-a-module.example')",
                "def handler(values):",
                "    import requests",
                "    with Fake() as requests:",
                "        requests.get('http://one.example')",
                "    for requests in values:",
                "        requests.get('http://two.example')",
                "    return [requests.get('http://three.example') for requests in values]",
                "def exception_shadow():",
                "    import requests",
                "    try:",
                "        return None",
                "    except Exception as requests:",
                "        return requests.get('http://four.example')",
                "",
            ]
        ),
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG106") == 1
    assert "HPG112" not in ids


def test_class_client_provenance_is_independent_of_method_source_order(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import httpx",
                "class Plugin:",
                "    def publish(self):",
                "        self.client.post('/events')",
                "    def __init__(self):",
                "        self.client = httpx.Client(",
                "            base_url='https://ordered.example.invalid'",
                "        )",
                "",
            ]
        ),
    )
    egress = [finding for finding in inspection.findings if finding.rule_id == "HPG112"]

    assert [finding.evidence for finding in egress] == [
        "httpx.Client.post -> https://ordered.example.invalid"
    ]


def test_class_prepass_resolves_method_local_imports(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "class Plugin:",
                "    def publish(self):",
                "        self.client.post('/events')",
                "    def __init__(self):",
                "        import httpx",
                "        self.client = httpx.Client(",
                "            base_url='https://local-import.example.invalid'",
                "        )",
                "",
            ]
        ),
    )
    egress = [finding for finding in inspection.findings if finding.rule_id == "HPG112"]

    assert [finding.evidence for finding in egress] == [
        "httpx.Client.post -> https://local-import.example.invalid"
    ]


def test_ipv6_zone_identifiers_are_not_copied_into_evidence(tmp_path: Path) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import requests",
                "requests.get(",
                "    'https://[fe80::1%25synthetic-secret]/upload?token=hidden'",
                ")",
                "",
            ]
        ),
    )
    egress = [finding for finding in inspection.findings if finding.rule_id == "HPG112"]
    serialized = "\n".join(f"{finding.message}\n{finding.evidence or ''}" for finding in egress)

    assert len(egress) == 1
    assert egress[0].evidence == "requests.get -> <dynamic destination>"
    assert "synthetic-secret" not in serialized
    assert "token=hidden" not in serialized


def test_register_time_egress_is_both_inventory_and_load_time_risk(
    tmp_path: Path,
) -> None:
    inspection = _inspect(
        tmp_path,
        "\n".join(
            [
                "import requests",
                "def register(ctx):",
                "    requests.post('https://events.example.invalid/hook')",
                "",
            ]
        ),
    )
    ids = [finding.rule_id for finding in inspection.findings]

    assert ids.count("HPG112") == 1
    assert ids.count("HPG111") == 1


def test_syntax_errors_become_findings_instead_of_exceptions(tmp_path: Path) -> None:
    inspection = _inspect(tmp_path, "def broken(:\n")

    assert len(inspection.findings) == 1
    assert inspection.findings[0].rule_id == "HPG002"
    assert inspection.findings[0].line == 1
