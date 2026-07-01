"""Scan orchestration: load -> taint -> rules -> deduped, sorted findings."""

from __future__ import annotations

import glob
import os
from typing import Dict, List

from . import loaders, rules
from .schema import Finding, Trace, severity_rank
from .taint import build_context, propagate_flow_markers


def scan_trace(trace: Trace) -> List[Finding]:
    """Run the full rule engine over an already-loaded trace."""
    ctx = build_context(trace)
    propagate_flow_markers(ctx)

    findings: List[Finding] = []
    for meta, fn in rules.RULES:
        for hit in fn(trace, ctx):
            findings.append(
                Finding(
                    rule_id=meta.id,
                    title=meta.title,
                    severity=meta.severity,
                    owasp=meta.owasp,
                    message=hit.message,
                    event_index=hit.event_index,
                    tool_name=hit.tool_name,
                    evidence=hit.evidence,
                    related_indices=list(hit.related_indices),
                    source_path=trace.source_path,
                )
            )

    return _sort_and_dedupe(findings)


def _sort_and_dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.event_index, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (-severity_rank(f.severity), f.event_index, f.rule_id))
    return unique


def scan_file(path: str) -> List[Finding]:
    trace = loaders.load(path)
    return scan_trace(trace)


def _iter_json_files(path: str) -> List[str]:
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "*.json"), recursive=True))
        # ignore sidecar label files
        return [f for f in files if os.path.basename(f) != "labels.json"]
    return [path]


def scan_path(path: str) -> Dict[str, List[Finding]]:
    """Scan a file or a directory of traces. Returns {path: findings}."""
    results: Dict[str, List[Finding]] = {}
    for f in _iter_json_files(path):
        try:
            results[f] = scan_file(f)
        except Exception as exc:  # noqa: BLE001 - surface load errors per-file
            results[f] = [
                Finding(
                    rule_id="TW000",
                    title="Trace failed to load",
                    severity="INFO",
                    owasp="-",
                    message=f"Could not parse trace: {exc}",
                    event_index=-1,
                    source_path=f,
                )
            ]
    return results


def max_severity_rank(findings: List[Finding]) -> int:
    return max((severity_rank(f.severity) for f in findings), default=-1)
