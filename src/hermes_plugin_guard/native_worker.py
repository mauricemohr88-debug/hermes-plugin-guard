"""Resource-bounded worker for the native Hermes model tool.

This module is launched as a fresh interpreter.  It emits only a compact,
privacy-preserving projection; candidate-controlled paths and scanner messages
never cross the worker boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any

from hermes_plugin_guard.models import Severity
from hermes_plugin_guard.scanner import scan

MAX_FINDINGS = 20
MAX_INTERNAL_FINDINGS = 256
MAX_OUTPUT_BYTES = 16_384
SCAN_IGNORES = frozenset({".git", ".hg", ".svn"})


def _apply_resource_limits() -> None:
    if os.name != "posix":
        return
    try:
        import resource
    except ImportError:
        return

    limits = (
        ("RLIMIT_CPU", 10),
        ("RLIMIT_AS", 512 * 1024 * 1024),
        ("RLIMIT_DATA", 512 * 1024 * 1024),
        ("RLIMIT_FSIZE", 1024 * 1024),
        ("RLIMIT_NOFILE", 64),
    )
    for name, requested in limits:
        resource_id = getattr(resource, name, None)
        if resource_id is None:
            continue
        try:
            soft, hard = resource.getrlimit(resource_id)
            candidates = [requested]
            if soft != resource.RLIM_INFINITY:
                candidates.append(soft)
            if hard != resource.RLIM_INFINITY:
                candidates.append(hard)
            target = min(candidates)
            resource.setrlimit(resource_id, (target, target))
        except (OSError, ValueError):
            continue


def _location_id(path: str, key: bytes) -> str:
    digest = hmac.new(key, os.fsencode(path), hashlib.sha256).hexdigest()[:16]
    return f"loc-{digest}"


def _success_payload(root: Path, location_key: bytes) -> dict[str, Any]:
    result = scan(
        root,
        ignored_directories=SCAN_IGNORES,
        use_default_ignores=False,
        max_findings=MAX_INTERNAL_FINDINGS,
    )
    sorted_findings = result.sorted_findings()
    projected = [
        {
            "rule_id": finding.rule_id,
            "severity": finding.severity.label,
            "location_id": _location_id(finding.path, location_key),
            "line": max(1, min(int(finding.line), 10_000_000)),
        }
        for finding in sorted_findings[:MAX_FINDINGS]
    ]
    blocking = sum(1 for finding in sorted_findings if finding.severity >= Severity.HIGH)
    incomplete = result.finding_limit_reached
    return {
        "ok": True,
        "status": "review_required" if blocking or incomplete else "pass",
        "blocking_findings": blocking,
        "summary": {
            "plugins": result.plugin_count,
            "scanned_files": result.scanned_files,
            "skipped_files": result.skipped_files,
            "findings": len(sorted_findings),
            "finding_limit_reached": incomplete,
            "counts": result.counts(),
        },
        "findings": projected,
        "truncated": incomplete or len(sorted_findings) > len(projected),
    }


def _emit(payload: dict[str, Any]) -> int:
    rendered = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(rendered) > MAX_OUTPUT_BYTES:
        rendered = b'{"error":{"code":"scan_failed"},"ok":false}'
    sys.stdout.buffer.write(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        return _emit({"ok": False, "error": {"code": "scan_failed"}})
    try:
        location_key = bytes.fromhex(os.environ.pop("HPG_LOCATION_KEY"))
    except (KeyError, ValueError):
        return _emit({"ok": False, "error": {"code": "scan_failed"}})
    if len(location_key) != 32:
        return _emit({"ok": False, "error": {"code": "scan_failed"}})
    _apply_resource_limits()
    try:
        return _emit(_success_payload(Path(arguments[0]), location_key))
    except Exception:
        return _emit({"ok": False, "error": {"code": "scan_failed"}})


if __name__ == "__main__":
    raise SystemExit(main())
