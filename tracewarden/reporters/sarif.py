"""SARIF 2.1.0 output so findings can be consumed by CI / code-scanning UIs."""

from __future__ import annotations

import json
import os
from typing import Dict, List

from .. import rules
from ..schema import Finding

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "1.0",
}


def _rule_descriptors() -> List[dict]:
    out = []
    for meta in rules.catalog():
        out.append(
            {
                "id": meta.id,
                "name": meta.title.replace(" ", ""),
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.description or meta.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(meta.severity, "warning")},
                "properties": {
                    "tags": ["security", "ai-agent", meta.owasp],
                    "security-severity": _SECURITY_SEVERITY.get(meta.severity, "5.0"),
                    "owasp": meta.owasp,
                },
            }
        )
    return out


def _result(f: Finding) -> dict:
    uri = os.path.basename(f.source_path) if f.source_path else "trace.json"
    return {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL.get(f.severity.upper(), "warning"),
        "message": {"text": f"{f.title}: {f.message}"},
        "properties": {
            "severity": f.severity,
            "owasp": f.owasp,
            "evidence": f.evidence,
            "eventIndex": f.event_index,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(f.event_index + 1, 1)},
                },
                "logicalLocations": [
                    {"name": f.tool_name or "trace", "kind": "function"}
                ],
            }
        ],
    }


def build_sarif(results: Dict[str, List[Finding]], version: str = "0.1.0") -> dict:
    all_results = [_result(f) for fs in results.values() for f in fs if f.event_index >= 0]
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tracewarden",
                        "informationUri": "https://github.com/Danush-Aries/tracewarden",
                        "version": version,
                        "rules": _rule_descriptors(),
                    }
                },
                "results": all_results,
            }
        ],
    }


def write_sarif(results: Dict[str, List[Finding]], out_path: str, version: str = "0.1.0") -> str:
    doc = build_sarif(results, version=version)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    return out_path
