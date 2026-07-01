"""Colored terminal reporter. Uses `rich` when available, plain text otherwise."""

from __future__ import annotations

import os
from typing import Dict, List

from ..schema import Finding, severity_rank

_SEV_COLORS = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}
_SEV_PLAIN = {
    "CRITICAL": "[CRIT]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MED ]",
    "LOW": "[LOW ]",
    "INFO": "[INFO]",
}


def _counts(findings: List[Finding]) -> Dict[str, int]:
    out = {s: 0 for s in _SEV_PLAIN}
    for f in findings:
        out[f.severity.upper()] = out.get(f.severity.upper(), 0) + 1
    return out


def render_terminal(results: Dict[str, List[Finding]], use_color: bool = True) -> str:
    try:
        if use_color and not os.environ.get("TW_NO_RICH"):
            return _render_rich(results)
    except Exception:  # noqa: BLE001 - never let rendering crash a scan
        pass
    return _render_plain(results)


# --------------------------------------------------------------------------- #
# rich renderer
# --------------------------------------------------------------------------- #
def _render_rich(results: Dict[str, List[Finding]]) -> str:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console(record=True, width=100)
    console.print()
    console.print(
        Panel.fit(
            Text("tracewarden", style="bold cyan")
            + Text("  ·  post-execution trace forensics for AI agents", style="dim"),
            border_style="cyan",
        )
    )

    total: List[Finding] = []
    for path, findings in results.items():
        total.extend(findings)
        header = Text(_short(path), style="bold")
        if not findings:
            console.print(header, Text("  clean - no findings", style="green"))
            continue
        console.print()
        console.print(header)
        table = Table(show_header=True, header_style="bold", expand=True, box=None, pad_edge=False)
        table.add_column("SEV", width=9)
        table.add_column("RULE", width=7)
        table.add_column("EVT", width=4, justify="right")
        table.add_column("OWASP", width=20)
        table.add_column("FINDING", overflow="fold")
        for f in findings:
            table.add_row(
                Text(f.severity, style=_SEV_COLORS.get(f.severity.upper(), "white")),
                f.rule_id,
                str(f.event_index),
                Text(f.owasp, style="dim"),
                _finding_text(f),
            )
        console.print(table)

    console.print()
    console.print(_summary_line_rich(total))
    return console.export_text(styles=False)


def _finding_text(f: Finding):
    from rich.text import Text

    t = Text(f.title, style="bold")
    t.append("\n" + f.message, style="")
    if f.evidence:
        t.append(f"\n  evidence: {f.evidence}", style="dim italic")
    if f.related_indices:
        t.append(f"  (related events: {f.related_indices})", style="dim")
    return t


def _summary_line_rich(total: List[Finding]):
    from rich.text import Text

    c = _counts(total)
    t = Text("Summary: ", style="bold")
    t.append(f"{len(total)} findings  ")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if c.get(sev):
            t.append(f" {sev.title()}={c[sev]}", style=_SEV_COLORS.get(sev, "white"))
    if not total:
        t.append("no issues detected", style="green")
    return t


# --------------------------------------------------------------------------- #
# plain renderer (fallback / --no-color)
# --------------------------------------------------------------------------- #
def _render_plain(results: Dict[str, List[Finding]]) -> str:
    lines = ["", "=== tracewarden - post-execution trace forensics ===", ""]
    total: List[Finding] = []
    for path, findings in results.items():
        total.extend(findings)
        if not findings:
            lines.append(f"{_short(path)}: clean - no findings")
            continue
        lines.append(f"{_short(path)}:")
        for f in findings:
            tag = _SEV_PLAIN.get(f.severity.upper(), "[????]")
            lines.append(f"  {tag} {f.rule_id} (evt {f.event_index}) {f.title}  [{f.owasp}]")
            lines.append(f"        {f.message}")
            if f.evidence:
                lines.append(f"        evidence: {f.evidence}")
        lines.append("")

    c = _counts(total)
    lines.append(
        "Summary: {n} findings  Critical={CRITICAL} High={HIGH} "
        "Medium={MEDIUM} Low={LOW} Info={INFO}".format(n=len(total), **c)
    )
    return "\n".join(lines)


def _short(path: str) -> str:
    return os.path.basename(path) or path
