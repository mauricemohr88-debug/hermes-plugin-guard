"""Command-line interface for hermes-plugin-guard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .catalog import RULES
from .models import Severity
from .reporters import render
from .scanner import scan

FORMATS = ("text", "json", "sarif", "github")
THRESHOLDS = ("critical", "high", "medium", "low", "info", "none")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermes-plugin-guard",
        description=(
            "Statically inspect Hermes Agent plugins before enabling them. "
            "Target code is never imported or executed."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="scan a plugin directory or repository",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="plugin or repository path (default: current directory)",
    )
    scan_parser.add_argument(
        "--format",
        dest="report_format",
        choices=FORMATS,
        default="text",
        help="output format (default: text)",
    )
    scan_parser.add_argument(
        "--output",
        type=Path,
        help="write the report to this file instead of stdout",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=THRESHOLDS,
        default="high",
        help="minimum severity that returns exit 1 (default: high)",
    )
    scan_parser.add_argument(
        "--exclude",
        "--exclude-rule",
        dest="excluded_rules",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="exclude a rule ID; may be repeated",
    )

    rules_parser = subparsers.add_parser(
        "rules",
        help="list all checks and their default severity",
    )
    rules_parser.add_argument(
        "--format",
        dest="report_format",
        choices=("text", "json"),
        default="text",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        return _print_rules(args.report_format)

    excluded_rules = [value.upper() for value in args.excluded_rules]
    unknown = sorted(set(excluded_rules) - set(RULES))
    if unknown:
        parser.error(f"unknown rule ID(s): {', '.join(unknown)}")

    threshold = None if args.fail_on == "none" else Severity.parse(args.fail_on)
    try:
        result = scan(args.path, excluded_rules=excluded_rules)
        report = render(result, args.report_format, threshold)
        _write_report(report, args.output)
    except (FileNotFoundError, NotADirectoryError, OSError, ValueError) as exc:
        print(f"hermes-plugin-guard: error: {exc}", file=sys.stderr)
        return 2
    return 1 if result.fails_at(threshold) else 0


def _write_report(report: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(report)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")


def _print_rules(report_format: str) -> int:
    if report_format == "json":
        import json

        payload = [
            {
                "id": rule.id,
                "severity": rule.default_severity.label,
                "title": rule.title,
                "category": rule.category,
                "description": rule.description,
                "remediation": rule.remediation,
            }
            for rule in RULES.values()
        ]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    for rule in RULES.values():
        print(f"{rule.id}  {rule.default_severity.label.upper():8}  {rule.title}")
        print(f"         {rule.description}")
        print(f"         Fix: {rule.remediation}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
