from __future__ import annotations

import json
from pathlib import Path

from hermes_plugin_guard.secret_scan import inspect_file


def test_secret_literal_is_redacted_from_structured_finding(tmp_path: Path) -> None:
    secret = "sk-" + ("A" * 32)
    path = tmp_path / "settings.py"
    path.write_text(f'API_KEY = "{secret}"\n', encoding="utf-8")

    findings = inspect_file(path, tmp_path)
    serialized = json.dumps([finding.as_dict() for finding in findings])

    assert len(findings) == 1
    assert findings[0].rule_id == "HPG201"
    assert findings[0].severity.label == "critical"
    assert secret not in serialized
    assert secret[:8] not in findings[0].evidence
    assert findings[0].evidence == "OpenAI-style API key"


def test_credential_filename_is_flagged_even_without_literal(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("MODE=test\n", encoding="utf-8")

    findings = inspect_file(path, tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "HPG201"
    assert findings[0].path == ".env"


def test_documented_environment_templates_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / ".env.example"
    path.write_text("API_TOKEN=replace-me\n", encoding="utf-8")

    assert inspect_file(path, tmp_path) == []


def test_binary_and_oversized_files_are_not_decoded(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\0" + b"sk-" + (b"A" * 32))

    assert inspect_file(binary, tmp_path) == []
