"""Self-contained HTML reporter (no external assets, no JS dependencies)."""

from __future__ import annotations

import datetime
import html
from typing import Dict, List

from ..schema import Finding

_SEV_BG = {
    "CRITICAL": "#b3001b",
    "HIGH": "#e4572e",
    "MEDIUM": "#e6a800",
    "LOW": "#2a9d8f",
    "INFO": "#6c757d",
}


def _esc(text) -> str:
    return html.escape(str(text if text is not None else ""))


def _badge(sev: str) -> str:
    color = _SEV_BG.get(sev.upper(), "#6c757d")
    return f'<span class="badge" style="background:{color}">{_esc(sev)}</span>'


def render_html(results: Dict[str, List[Finding]], title: str = "tracewarden report") -> str:
    all_findings = [f for fs in results.values() for f in fs]
    counts = {s: 0 for s in _SEV_BG}
    for f in all_findings:
        counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards = "".join(
        f'<div class="stat"><div class="num" style="color:{_SEV_BG[s]}">{counts.get(s,0)}</div>'
        f'<div class="lbl">{s.title()}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    sections = []
    for path, findings in results.items():
        rows = []
        if not findings:
            rows.append('<tr><td colspan="4" class="clean">No findings - clean trace</td></tr>')
        for f in findings:
            related = f" · related events {f.related_indices}" if f.related_indices else ""
            evidence = (
                f'<div class="evidence">evidence: <code>{_esc(f.evidence)}</code>{_esc(related)}</div>'
                if f.evidence else ""
            )
            rows.append(
                "<tr>"
                f"<td>{_badge(f.severity)}</td>"
                f'<td><code>{_esc(f.rule_id)}</code></td>'
                f'<td class="owasp">{_esc(f.owasp)}</td>'
                f'<td><div class="ftitle">{_esc(f.title)} '
                f'<span class="evt">event #{_esc(f.event_index)}'
                f'{" · " + _esc(f.tool_name) if f.tool_name else ""}</span></div>'
                f'<div class="fmsg">{_esc(f.message)}</div>{evidence}</td>'
                "</tr>"
            )
        sections.append(
            f'<section><h2>{_esc(_short(path))} '
            f'<span class="count">{len(findings)} finding(s)</span></h2>'
            f'<table><thead><tr><th>Severity</th><th>Rule</th><th>OWASP</th>'
            f'<th>Detail</th></tr></thead><tbody>{"".join(rows)}</tbody></table></section>'
        )

    return _TEMPLATE.format(
        title=_esc(title),
        generated=_esc(generated),
        total=len(all_findings),
        files=len(results),
        cards=cards,
        sections="".join(sections),
    )


def write_html(results: Dict[str, List[Finding]], out_path: str, title: str = "tracewarden report") -> str:
    doc = render_html(results, title=title)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out_path


def _short(path: str) -> str:
    import os
    return os.path.basename(path) or path


_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ --bg:#0f1420; --card:#1a2130; --ink:#e8edf5; --muted:#94a3b8; --line:#2a3446; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  header {{ padding:32px 28px 20px; border-bottom:1px solid var(--line); }}
  h1 {{ margin:0; font-size:26px; letter-spacing:-.5px; }}
  h1 span {{ color:#4cc3ff; }}
  .sub {{ color:var(--muted); margin-top:6px; font-size:13px; }}
  .stats {{ display:flex; gap:14px; flex-wrap:wrap; padding:22px 28px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:14px 20px; min-width:96px; text-align:center; }}
  .stat .num {{ font-size:30px; font-weight:700; }}
  .stat .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }}
  section {{ padding:8px 28px 26px; }}
  h2 {{ font-size:16px; border-bottom:1px solid var(--line); padding-bottom:8px; }}
  h2 .count {{ color:var(--muted); font-weight:400; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; color:var(--muted); font-size:11px; text-transform:uppercase;
    letter-spacing:.6px; padding:8px 10px; border-bottom:1px solid var(--line); }}
  td {{ padding:12px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  .badge {{ color:#fff; padding:3px 9px; border-radius:20px; font-size:11px; font-weight:700;
    text-transform:uppercase; letter-spacing:.4px; white-space:nowrap; }}
  code {{ background:#0b0f18; padding:2px 6px; border-radius:5px; font-size:12.5px; color:#9fe0ff; }}
  .owasp {{ color:var(--muted); font-size:12.5px; white-space:nowrap; }}
  .ftitle {{ font-weight:600; }}
  .evt {{ color:var(--muted); font-weight:400; font-size:12px; }}
  .fmsg {{ color:#cdd6e4; margin-top:4px; font-size:13.5px; }}
  .evidence {{ margin-top:6px; font-size:12.5px; color:var(--muted); }}
  .clean {{ color:#2a9d8f; text-align:center; padding:18px; }}
  footer {{ color:var(--muted); font-size:12px; padding:18px 28px 40px; border-top:1px solid var(--line); }}
</style></head>
<body>
<header>
  <h1>trace<span>warden</span></h1>
  <div class="sub">Static security linter for what an AI agent actually did · fully offline, no LLM ·
  {total} findings across {files} trace(s) · generated {generated}</div>
</header>
<div class="stats">{cards}</div>
{sections}
<footer>tracewarden · deterministic post-execution trace forensics · OWASP Agentic Top 10 mapping ·
maps indirect prompt injection &amp; the lethal trifecta</footer>
</body></html>
"""
