"""Normalised internal trace schema shared by every loader and rule.

Every adapter (OpenAI / MCP / LangChain) maps its native shape onto this small,
stable data model so the rule engine and taint pass never need to know which
framework produced the trace.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Optional

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), 0)


# --------------------------------------------------------------------------- #
# Core events
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    """A single step in a normalised agent trace.

    An event is either a ``tool_call`` (the agent invoked a tool, with
    ``arguments`` and an optional tool ``result``) or a ``message``
    (free-form text with a ``role`` such as user/assistant/system).
    """

    index: int
    kind: str  # "tool_call" | "message"
    tool_name: Optional[str] = None
    arguments: dict = field(default_factory=dict)
    result: Optional[str] = None
    role: Optional[str] = None
    content: Optional[str] = None
    call_id: Optional[str] = None
    origin: Optional[str] = None  # e.g. MCP server name, used for shadowing checks

    # populated by the taint pass
    tainted: bool = False
    taint_reason: Optional[str] = None
    taint_source: Optional[int] = None  # index of the ingest event responsible

    raw: dict = field(default_factory=dict)

    # -- convenience text accessors ---------------------------------------- #
    def args_blob(self) -> str:
        """All argument values flattened into one searchable string."""
        if not self.arguments:
            return ""
        try:
            return json.dumps(self.arguments, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(self.arguments)

    def result_blob(self) -> str:
        return self.result or ""

    def text_blob(self) -> str:
        """Everything searchable about this event: args + result + content."""
        parts = [self.args_blob(), self.result_blob()]
        if self.content:
            parts.append(self.content)
        return "\n".join(p for p in parts if p)

    def label(self) -> str:
        if self.kind == "tool_call":
            return self.tool_name or "tool"
        return self.role or "message"


@dataclass
class Trace:
    """A normalised trace: an ordered list of events plus metadata."""

    source_format: str
    events: List[Event] = field(default_factory=list)
    source_path: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def tool_calls(self) -> List[Event]:
        return [e for e in self.events if e.kind == "tool_call"]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """One rule hit against a trace."""

    rule_id: str
    title: str
    severity: str
    owasp: str
    message: str
    event_index: int
    tool_name: Optional[str] = None
    evidence: Optional[str] = None
    related_indices: List[int] = field(default_factory=list)
    source_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "owasp": self.owasp,
            "message": self.message,
            "event_index": self.event_index,
            "tool_name": self.tool_name,
            "evidence": self.evidence,
            "related_indices": list(self.related_indices),
            "source_path": self.source_path,
        }


@dataclass
class Hit:
    """Lightweight rule output; the engine enriches it into a Finding.

    Rules only need to describe *where* and *why*; the rule id / title /
    severity / OWASP category come from the rule metadata so they can never
    drift out of sync with the catalog.
    """

    event_index: int
    message: str
    evidence: Optional[str] = None
    tool_name: Optional[str] = None
    related_indices: List[int] = field(default_factory=list)


def truncate(text: Any, limit: int = 160) -> str:
    """Collapse whitespace and clip a string for compact evidence display."""
    s = " ".join(str(text).split())
    if len(s) > limit:
        return s[: limit - 1] + "…"
    return s
