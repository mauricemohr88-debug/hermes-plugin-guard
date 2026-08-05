"""Native Hermes v0.20 integration for review-only plugin scans.

The model-facing tool is intentionally narrower than the operator CLI.  It can
only review an installed, currently disabled plugin below ``HERMES_HOME`` and
returns a bounded projection that cannot disclose source, evidence, secrets,
or absolute paths to the active model provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .cli import FORMATS, THRESHOLDS

TOOL_NAME = "plugin_guard_review_candidate"
TOOLSET = "hermes_plugin_guard"
CLI_NAME = "plugin-guard"

MAX_FINDINGS = 20
MAX_RESPONSE_BYTES = 16_384
MAX_WORKER_FINDINGS = 256
MAX_FILES = 1_000
MAX_ENTRIES = 1_500
MAX_DEPTH = 16
MAX_FILE_BYTES = 262_144
MAX_TOTAL_BYTES = 16_000_000
MAX_PYTHON_BYTES = 2_000_000
MAX_PYTHON_LINES = 40_000
MAX_CONFIG_BYTES = 1_000_000
MAX_SCAN_SECONDS = 10.0

_NATIVE_IGNORED_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_UNSUPPORTED_EXECUTABLE_SUFFIXES = frozenset(
    {
        ".class",
        ".dll",
        ".dylib",
        ".egg",
        ".exe",
        ".jar",
        ".node",
        ".pyd",
        ".pyc",
        ".pyo",
        ".so",
        ".wasm",
        ".whl",
        ".zip",
    }
)
_UNSUPPORTED_CONTENT_MAGICS = (
    b"\x00asm",  # WebAssembly
    b"\x7fELF",
    b"MZ",  # DOS/PE executables
    b"PK\x03\x04",  # ZIP/JAR/wheel/egg
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"!<arch>\n",  # Unix static library
    b"dex\n",  # Android DEX
    b"\xca\xfe\xba\xbe",  # Java class or Mach-O universal binary
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
    b"\xce\xfa\xed\xfe",  # Mach-O, little-endian 32-bit
    b"\xcf\xfa\xed\xfe",  # Mach-O, little-endian 64-bit
    b"\xfe\xed\xfa\xce",  # Mach-O, big-endian 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O, big-endian 64-bit
)
_REVIEW_SLOT = threading.BoundedSemaphore(1)

_KEY_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[/\\]")

TOOL_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Review one installed, disabled Hermes plugin with local static checks. "
        "Target code is never imported or executed. This is a review aid, not "
        "a safety verdict or activation gate."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "candidate": {
                "type": "string",
                "description": (
                    "Installed plugin key below HERMES_HOME/plugins, for example "
                    "my-plugin or image_gen/provider. Arbitrary paths are rejected."
                ),
                "minLength": 1,
                "maxLength": 255,
            }
        },
        "required": ["candidate"],
        "additionalProperties": False,
    },
}

_ERROR_MESSAGES = {
    "invalid_arguments": "Provide exactly one installed plugin key in 'candidate'.",
    "invalid_candidate": "The candidate must be a valid installed plugin key, not a path.",
    "candidate_not_found": "The requested installed plugin was not found.",
    "candidate_enabled": "Review is limited to plugins that are currently disabled.",
    "config_unreadable": "Hermes plugin activation state could not be verified.",
    "unsafe_tree": "The candidate contains an unsupported link or special filesystem entry.",
    "tree_too_large": "The candidate exceeds the bounded review limits.",
    "tree_too_deep": "The candidate exceeds the bounded directory-depth limit.",
    "tree_unreadable": "The candidate tree could not be read safely.",
    "unsupported_tree": "The candidate contains executable binary content that is not statically reviewed.",
    "manifest_invalid": "The candidate manifest could not be validated.",
    "unsupported_plugin_kind": "This plugin kind has a separate Hermes activation path and cannot be proven disabled here.",
    "tree_changed": "The candidate changed during review; retry with a stable checkout.",
    "review_busy": "Another bounded plugin review is already running; retry shortly.",
    "scan_timeout": "The bounded review time was exceeded.",
    "scan_failed": "The static review could not be completed.",
}


@dataclass(frozen=True, slots=True)
class _TreeSnapshot:
    digest: str
    files: int
    entries: int
    total_bytes: int


class _ReviewError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate manifest keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def register(ctx: Any) -> None:
    """Register one read-only model tool and one operator CLI command."""
    ctx.register_tool(
        name=TOOL_NAME,
        toolset=TOOLSET,
        schema=TOOL_SCHEMA,
        handler=review_candidate,
        description=(
            "Bounded static review of an installed, disabled Hermes plugin; "
            "does not enable, block, or execute it."
        ),
        emoji="🛡️",
    )
    ctx.register_cli_command(
        name=CLI_NAME,
        help="Statically review Hermes plugins without executing target code",
        setup_fn=_setup_cli,
        handler_fn=_handle_cli,
        description=(
            "Run Hermes Plugin Guard against a local path or an installed plugin. "
            "This command reports findings but does not change activation state."
        ),
    )


def review_candidate(args: dict[str, Any], **_: Any) -> str:
    """Return a bounded static-review result for one disabled installed plugin."""
    candidate: str | None = None
    if not _REVIEW_SLOT.acquire(blocking=False):
        return _error_payload("review_busy", candidate)
    try:
        if not isinstance(args, dict) or set(args) != {"candidate"}:
            raise _ReviewError("invalid_arguments")
        raw_candidate = args.get("candidate")
        if not isinstance(raw_candidate, str):
            raise _ReviewError("invalid_arguments")
        candidate = _normalize_candidate(raw_candidate)

        home = _hermes_home()
        target = _resolve_installed_candidate(home, candidate)
        with tempfile.TemporaryDirectory(prefix="hpg-review-") as temporary:
            snapshot_root = Path(temporary) / "candidate"
            snapshot_root.mkdir(mode=0o700)
            first = _snapshot_tree(target, copy_to=snapshot_root)

            manifest_name, manifest_kind = _read_manifest_identity(snapshot_root)
            if "/" not in candidate and candidate != manifest_name:
                raise _ReviewError("manifest_invalid")
            if candidate.split("/", 1)[0].casefold() == "model-providers" or manifest_kind not in {
                "backend",
                "platform",
                "standalone",
            }:
                raise _ReviewError("unsupported_plugin_kind")
            aliases = {candidate, manifest_name}
            if _read_enabled_plugins(home).intersection(aliases):
                raise _ReviewError("candidate_enabled")

            worker_result = _run_worker(snapshot_root, Path(temporary))
        second = _snapshot_tree(target)
        if first != second:
            raise _ReviewError("tree_changed")
        if _read_enabled_plugins(home).intersection(aliases):
            raise _ReviewError("candidate_enabled")

        summary = dict(worker_result["summary"])
        summary["tree_files"] = second.files
        payload = {
            "schema_version": "1.0",
            "ok": True,
            "status": worker_result["status"],
            "candidate": candidate,
            "scanner_version": __version__,
            "policy": {
                "threshold": "high",
                "blocking_findings": worker_result["blocking_findings"],
                "meaning": (
                    "Static review only; absence of blocking findings is not a safety verdict."
                ),
            },
            "summary": summary,
            "findings": worker_result["findings"],
            "truncated": worker_result["truncated"],
        }
        return _json(payload)
    except _ReviewError as exc:
        return _error_payload(exc.code, candidate)
    except Exception:
        return _error_payload("scan_failed", candidate)
    finally:
        _REVIEW_SLOT.release()


def _normalize_candidate(value: str) -> str:
    candidate = value.strip()
    if not candidate or len(candidate) > 255 or "\\" in candidate:
        raise _ReviewError("invalid_candidate")
    if candidate.startswith("/") or _WINDOWS_ABSOLUTE.match(candidate):
        raise _ReviewError("invalid_candidate")
    parts = candidate.split("/")
    if len(parts) > 2 or any(not _KEY_PART.fullmatch(part) for part in parts):
        raise _ReviewError("invalid_candidate")
    if any(part in {".", ".."} or part.startswith(".") for part in parts):
        raise _ReviewError("invalid_candidate")
    return "/".join(parts)


def _hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home()).expanduser()
    except ImportError:
        configured = os.environ.get("HERMES_HOME", "").strip()
        return Path(configured).expanduser() if configured else Path.home() / ".hermes"


def _resolve_installed_candidate(home: Path, candidate: str) -> Path:
    plugins = home / "plugins"
    try:
        if plugins.is_symlink():
            raise _ReviewError("unsafe_tree")
        plugins_root = plugins.resolve(strict=True)
    except _ReviewError:
        raise
    except (FileNotFoundError, NotADirectoryError):
        raise _ReviewError("candidate_not_found") from None
    except OSError:
        raise _ReviewError("tree_unreadable") from None

    parts = candidate.split("/")
    current = plugins
    for index, part in enumerate(parts):
        current = current / part
        try:
            if current.is_symlink():
                raise _ReviewError("unsafe_tree")
            if index == 0 and len(parts) == 2 and _direct_manifest(current) is not None:
                raise _ReviewError("candidate_not_found")
        except OSError:
            raise _ReviewError("tree_unreadable") from None
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(plugins_root)
        if not resolved.is_dir():
            raise _ReviewError("candidate_not_found")
        if _direct_manifest(resolved) is None:
            raise _ReviewError("candidate_not_found")
    except _ReviewError:
        raise
    except (FileNotFoundError, NotADirectoryError, ValueError):
        raise _ReviewError("candidate_not_found") from None
    except OSError:
        raise _ReviewError("tree_unreadable") from None
    return resolved


def _direct_manifest(root: Path) -> Path | None:
    primary = root / "plugin.yaml"
    alternate = root / "plugin.yml"
    try:
        if primary.is_symlink() or alternate.is_symlink():
            raise _ReviewError("unsafe_tree")
        if primary.is_file():
            return primary
        if alternate.is_file():
            return alternate
    except _ReviewError:
        raise
    except OSError:
        raise _ReviewError("tree_unreadable") from None
    return None


def _read_manifest_identity(root: Path) -> tuple[str, str]:
    manifest = _direct_manifest(root)
    if manifest is None:
        raise _ReviewError("manifest_invalid")
    try:
        size = manifest.stat().st_size
        if size > MAX_FILE_BYTES:
            raise _ReviewError("manifest_invalid")
        text = manifest.read_text(encoding="utf-8")
        data = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except _ReviewError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError, yaml.YAMLError, RecursionError):
        raise _ReviewError("manifest_invalid") from None
    if not isinstance(data, dict):
        raise _ReviewError("manifest_invalid")
    name = data.get("name")
    if not isinstance(name, str):
        raise _ReviewError("manifest_invalid")
    name = name.strip()
    if not _KEY_PART.fullmatch(name) or name.startswith("."):
        raise _ReviewError("manifest_invalid")
    kind = data.get("kind", "standalone")
    if not isinstance(kind, str) or not kind.strip():
        raise _ReviewError("manifest_invalid")
    normalized_kind = kind.strip().casefold()
    separately_loaded_kind = _separate_activation_kind(root)
    if separately_loaded_kind is not None:
        normalized_kind = separately_loaded_kind
    return name, normalized_kind


def _separate_activation_kind(root: Path) -> str | None:
    """Detect v0.20 plugin families that bypass ``plugins.enabled``."""
    init_path = root / "__init__.py"
    try:
        source = init_path.read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        return None
    if "register_memory_provider" in source or "MemoryProvider" in source:
        return "exclusive"
    if "register_provider" in source and "ProviderProfile" in source:
        return "model-provider"
    if "register_cron_scheduler" in source or "CronScheduler" in source:
        return "cron-provider"
    return None


def _read_enabled_plugins(home: Path) -> set[str]:
    config_path = home / "config.yaml"
    try:
        if config_path.is_symlink():
            raise _ReviewError("config_unreadable")
        if not config_path.exists():
            return set()
        size = config_path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise _ReviewError("config_unreadable")
        with config_path.open(encoding="utf-8") as stream:
            text = stream.read(MAX_CONFIG_BYTES + 1)
        if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise _ReviewError("config_unreadable")
        data = yaml.safe_load(text) or {}
    except _ReviewError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError):
        raise _ReviewError("config_unreadable") from None
    if not isinstance(data, dict):
        raise _ReviewError("config_unreadable")
    plugins = data.get("plugins", {})
    if plugins is None:
        return set()
    if not isinstance(plugins, dict):
        raise _ReviewError("config_unreadable")
    enabled = plugins.get("enabled", [])
    if enabled is None:
        return set()
    if not isinstance(enabled, list) or any(not isinstance(item, str) for item in enabled):
        raise _ReviewError("config_unreadable")
    return {item.strip() for item in enabled if item.strip()}


def _snapshot_tree(root: Path, *, copy_to: Path | None = None) -> _TreeSnapshot:
    try:
        if root.is_symlink() or not root.is_dir():
            raise _ReviewError("unsafe_tree")
    except _ReviewError:
        raise
    except OSError:
        raise _ReviewError("tree_unreadable") from None

    digest = hashlib.sha256()
    files = 0
    entries = 0
    total_bytes = 0
    python_bytes = 0
    python_lines = 0
    deadline = time.monotonic() + MAX_SCAN_SECONDS

    def walk(
        directory: Path,
        relative_parts: tuple[str, ...],
        depth: int,
        destination: Path | None,
    ) -> None:
        nonlocal entries, files, python_bytes, python_lines, total_bytes
        if time.monotonic() > deadline:
            raise _ReviewError("scan_timeout")
        try:
            with os.scandir(directory) as iterator:
                children = []
                for entry in iterator:
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise _ReviewError("tree_too_large")
                    if time.monotonic() > deadline:
                        raise _ReviewError("scan_timeout")
                    children.append(entry)
                children.sort(key=lambda item: os.fsencode(item.name))
        except _ReviewError:
            raise
        except OSError:
            raise _ReviewError("tree_unreadable") from None

        destination_names: set[str] = set()
        for entry in children:
            name = entry.name
            folded = name.casefold()
            collision_key = unicodedata.normalize("NFC", name).casefold()
            if collision_key in destination_names:
                raise _ReviewError("unsafe_tree")
            destination_names.add(collision_key)
            rel_parts = (*relative_parts, name)
            rel_bytes = b"/".join(os.fsencode(part) for part in rel_parts)
            try:
                if entry.is_symlink():
                    raise _ReviewError("unsafe_tree")
                is_directory = entry.is_dir(follow_symlinks=False)
                if is_directory:
                    ignored = folded in _NATIVE_IGNORED_DIRECTORIES
                    digest.update(b"I" if ignored else b"D")
                    digest.update(len(rel_bytes).to_bytes(4, "big"))
                    digest.update(rel_bytes)
                    if ignored:
                        continue
                    if depth + 1 > MAX_DEPTH:
                        raise _ReviewError("tree_too_deep")
                    child_destination = destination / name if destination is not None else None
                    if child_destination is not None:
                        try:
                            child_destination.mkdir(mode=0o700)
                        except OSError:
                            raise _ReviewError("tree_unreadable") from None
                    walk(Path(entry.path), rel_parts, depth + 1, child_destination)
                    continue
                info = entry.stat(follow_symlinks=False)
            except _ReviewError:
                raise
            except OSError:
                raise _ReviewError("tree_unreadable") from None
            if not stat.S_ISREG(info.st_mode):
                raise _ReviewError("unsafe_tree")
            if Path(name).suffix.casefold() in _UNSUPPORTED_EXECUTABLE_SUFFIXES:
                raise _ReviewError("unsupported_tree")
            if info.st_size > MAX_FILE_BYTES:
                raise _ReviewError("tree_too_large")
            files += 1
            total_bytes += info.st_size
            if files > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise _ReviewError("tree_too_large")
            content = _read_regular_file(Path(entry.path), info.st_size)
            if any(content.startswith(magic) for magic in _UNSUPPORTED_CONTENT_MAGICS):
                raise _ReviewError("unsupported_tree")
            if Path(name).suffix.casefold() == ".py":
                python_bytes += len(content)
                python_lines += content.count(b"\n") + bool(content)
                if python_bytes > MAX_PYTHON_BYTES or python_lines > MAX_PYTHON_LINES:
                    raise _ReviewError("tree_too_large")
            digest.update(b"F")
            digest.update(len(rel_bytes).to_bytes(4, "big"))
            digest.update(rel_bytes)
            digest.update(info.st_size.to_bytes(8, "big"))
            digest.update(content)
            if destination is not None:
                _write_private_file(destination / name, content)

    walk(root, (), 0, copy_to)

    return _TreeSnapshot(
        digest=digest.hexdigest(),
        files=files,
        entries=entries,
        total_bytes=total_bytes,
    )


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise _ReviewError("tree_unreadable")
                view = view[written:]
        finally:
            os.close(descriptor)
    except _ReviewError:
        raise
    except OSError:
        raise _ReviewError("tree_unreadable") from None


def _read_regular_file(path: Path, expected_size: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
                raise _ReviewError("tree_changed")
            chunks: list[bytes] = []
            remaining = expected_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 131_072))
                if not chunk:
                    raise _ReviewError("tree_changed")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise _ReviewError("tree_changed")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except _ReviewError:
        raise
    except OSError:
        raise _ReviewError("tree_unreadable") from None


def _run_worker(snapshot_root: Path, working_directory: Path) -> dict[str, Any]:
    script = Path(__file__).with_name("native_worker.py")
    package_root = Path(__file__).parents[1]
    environment = {
        "HPG_LOCATION_KEY": secrets.token_hex(32),
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(package_root),
        "PYTHONUTF8": "1",
    }
    for name in ("LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value

    try:
        completed = subprocess.run(
            [sys.executable, str(script), str(snapshot_root)],
            cwd=working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=MAX_SCAN_SECONDS,
            check=False,
            start_new_session=os.name == "posix",
        )
    except subprocess.TimeoutExpired:
        raise _ReviewError("scan_timeout") from None
    except OSError:
        raise _ReviewError("scan_failed") from None

    if completed.returncode != 0 or len(completed.stdout) > MAX_RESPONSE_BYTES:
        raise _ReviewError("scan_failed")
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise _ReviewError("scan_failed") from None
    return _validate_worker_result(payload)


def _validate_worker_result(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise _ReviewError("scan_failed")
    if payload.get("status") not in {"pass", "review_required"}:
        raise _ReviewError("scan_failed")
    blocking = payload.get("blocking_findings")
    findings = payload.get("findings")
    summary = payload.get("summary")
    truncated = payload.get("truncated")
    if (
        not isinstance(blocking, int)
        or isinstance(blocking, bool)
        or blocking < 0
        or not isinstance(findings, list)
        or len(findings) > MAX_FINDINGS
        or not isinstance(summary, dict)
        or not isinstance(truncated, bool)
    ):
        raise _ReviewError("scan_failed")
    allowed_severities = {"critical", "high", "medium", "low", "info"}
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {
            "line",
            "location_id",
            "rule_id",
            "severity",
        }:
            raise _ReviewError("scan_failed")
        if (
            not isinstance(finding["rule_id"], str)
            or not re.fullmatch(r"HPG\d{3}", finding["rule_id"])
            or finding["severity"] not in allowed_severities
            or not isinstance(finding["location_id"], str)
            or not re.fullmatch(r"loc-[0-9a-f]{16}", finding["location_id"])
            or not isinstance(finding["line"], int)
            or isinstance(finding["line"], bool)
            or not 1 <= finding["line"] <= 10_000_000
        ):
            raise _ReviewError("scan_failed")

    expected_summary = {
        "counts",
        "finding_limit_reached",
        "findings",
        "plugins",
        "scanned_files",
        "skipped_files",
    }
    if set(summary) != expected_summary or not isinstance(summary["finding_limit_reached"], bool):
        raise _ReviewError("scan_failed")
    counts = summary["counts"]
    if not isinstance(counts, dict) or set(counts) != allowed_severities:
        raise _ReviewError("scan_failed")
    numeric_values = [
        summary["findings"],
        summary["plugins"],
        summary["scanned_files"],
        summary["skipped_files"],
        *counts.values(),
    ]
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in numeric_values
    ):
        raise _ReviewError("scan_failed")
    total_findings = summary["findings"]
    incomplete = summary["finding_limit_reached"]
    expected_blocking = counts["critical"] + counts["high"]
    expected_status = "review_required" if expected_blocking or incomplete else "pass"
    if (
        total_findings > MAX_WORKER_FINDINGS
        or sum(counts.values()) != total_findings
        or len(findings) > total_findings
        or blocking != expected_blocking
        or payload["status"] != expected_status
        or truncated != (incomplete or total_findings > len(findings))
    ):
        raise _ReviewError("scan_failed")
    return payload


def _error_payload(code: str, candidate: str | None) -> str:
    safe_code = code if code in _ERROR_MESSAGES else "scan_failed"
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "ok": False,
        "status": "error",
        "error": {"code": safe_code, "message": _ERROR_MESSAGES[safe_code]},
    }
    if candidate is not None:
        payload["candidate"] = candidate
    return _json(payload)


def _json(payload: dict[str, Any]) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(rendered.encode("utf-8")) <= MAX_RESPONSE_BYTES:
        return rendered
    return json.dumps(
        {
            "schema_version": "1.0",
            "ok": False,
            "status": "error",
            "error": {
                "code": "scan_failed",
                "message": _ERROR_MESSAGES["scan_failed"],
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _setup_cli(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(dest="plugin_guard_command", required=True)

    scan_parser = subparsers.add_parser("scan", help="review a local plugin path")
    _add_scan_arguments(scan_parser, path_name="path", path_help="plugin or repository path")

    installed_parser = subparsers.add_parser(
        "installed", help="review a plugin already installed under HERMES_HOME"
    )
    _add_scan_arguments(
        installed_parser,
        path_name="candidate",
        path_help="installed plugin key (for example my-plugin or image_gen/provider)",
    )

    rules_parser = subparsers.add_parser("rules", help="list static review rules")
    rules_parser.add_argument(
        "--format", dest="report_format", choices=("text", "json"), default="text"
    )


def _add_scan_arguments(
    parser: argparse.ArgumentParser,
    *,
    path_name: str,
    path_help: str,
) -> None:
    parser.add_argument(path_name, help=path_help)
    parser.add_argument("--format", dest="report_format", choices=FORMATS, default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=THRESHOLDS, default="high")
    parser.add_argument(
        "--exclude",
        "--exclude-rule",
        dest="excluded_rules",
        action="append",
        default=[],
        metavar="RULE_ID",
    )


def _handle_cli(args: argparse.Namespace) -> int:
    command = getattr(args, "plugin_guard_command", None)
    if command == "rules":
        return _invoke_standalone_cli(["rules", "--format", args.report_format])
    if command not in {"scan", "installed"}:
        return 2

    if command == "installed":
        try:
            candidate = _normalize_candidate(args.candidate)
            target = _resolve_installed_candidate(_hermes_home(), candidate)
        except _ReviewError as exc:
            print(f"hermes plugin-guard: {_ERROR_MESSAGES[exc.code]}", file=sys.stderr)
            return 2
        path = str(target)
    else:
        path = args.path

    argv = ["scan", path, "--format", args.report_format, "--fail-on", args.fail_on]
    if args.output is not None:
        argv.extend(["--output", str(args.output)])
    for rule_id in args.excluded_rules:
        argv.extend(["--exclude", rule_id])
    return _invoke_standalone_cli(argv)


def _invoke_standalone_cli(argv: list[str]) -> int:
    from .cli import main

    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
