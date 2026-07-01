"""Command-line interface for tracewarden.

    tracewarden scan <path> [--fail-on SEV] [--html F] [--sarif F] [--json F]
    tracewarden rules [--json]

The ``scan`` command loads one trace or a directory of traces, runs the
deterministic rule engine, prints a colored report, optionally writes
HTML / SARIF / JSON artifacts, and returns a CI-friendly non-zero exit code
when findings at or above ``--fail-on`` are present.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from . import __version__, engine, rules
from .reporters import render_terminal, write_html, write_sarif
from .schema import Finding, SEVERITIES, severity_rank

# Exit codes
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def _findings_to_json(results: Dict[str, List[Finding]]) -> dict:
    return {
        "tool": "tracewarden",
        "version": __version__,
        "files": {
            path: [f.to_dict() for f in findings]
            for path, findings in results.items()
        },
        "summary": _summary(results),
    }


def _summary(results: Dict[str, List[Finding]]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    total = 0
    for findings in results.values():
        for f in findings:
            counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1
            total += 1
    return {"total": total, "files": len(results), "by_severity": counts}


def _worst_rank(results: Dict[str, List[Finding]]) -> int:
    worst = -1
    for findings in results.values():
        worst = max(worst, engine.max_severity_rank(findings))
    return worst


def cmd_scan(args: argparse.Namespace) -> int:
    path = args.path
    if not os.path.exists(path):
        print(f"tracewarden: path not found: {path}", file=sys.stderr)
        return EXIT_ERROR

    results = engine.scan_path(path)

    if args.json == "-":
        json.dump(_findings_to_json(results), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        report = render_terminal(results, use_color=not args.no_color)
        print(report)

    # Write artifacts
    if args.html:
        write_html(results, args.html)
        print(f"tracewarden: HTML report written to {args.html}", file=sys.stderr)
    if args.sarif:
        write_sarif(results, args.sarif, version=__version__)
        print(f"tracewarden: SARIF written to {args.sarif}", file=sys.stderr)
    if args.json and args.json != "-":
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(_findings_to_json(results), fh, indent=2)
        print(f"tracewarden: JSON written to {args.json}", file=sys.stderr)

    # CI exit policy
    if args.fail_on:
        threshold = severity_rank(args.fail_on)
        if _worst_rank(results) >= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #
def cmd_rules(args: argparse.Namespace) -> int:
    catalog = rules.catalog()
    if args.json:
        json.dump(
            [
                {
                    "id": m.id,
                    "title": m.title,
                    "severity": m.severity,
                    "owasp": m.owasp,
                    "description": m.description,
                }
                for m in catalog
            ],
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return EXIT_OK

    print(f"tracewarden rule catalog ({len(catalog)} rules)\n")
    print(f"{'ID':<7} {'SEVERITY':<9} {'OWASP CATEGORY':<40} TITLE")
    print("-" * 100)
    for m in catalog:
        print(f"{m.id:<7} {m.severity:<9} {m.owasp:<40} {m.title}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracewarden",
        description="Deterministic, offline static security linter for recorded "
        "AI-agent tool-call traces (indirect prompt injection, lethal trifecta, "
        "secret exfiltration, RCE, over-broad tool use).",
    )
    parser.add_argument("--version", action="version", version=f"tracewarden {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a trace file or directory of traces")
    p_scan.add_argument("path", help="trace .json file or directory")
    p_scan.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        choices=[s for s in SEVERITIES] + [s.lower() for s in SEVERITIES],
        help="exit non-zero if any finding is at or above this severity "
        "(CRITICAL, HIGH, MEDIUM, LOW, INFO)",
    )
    p_scan.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    p_scan.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 output")
    p_scan.add_argument(
        "--json",
        metavar="FILE",
        help="write JSON findings to FILE (use '-' for stdout)",
    )
    p_scan.add_argument("--no-color", action="store_true", help="disable colored output")
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser("rules", help="list the rule catalog")
    p_rules.add_argument("--json", action="store_true", help="emit the catalog as JSON")
    p_rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR
    if getattr(args, "fail_on", None):
        args.fail_on = args.fail_on.upper()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
