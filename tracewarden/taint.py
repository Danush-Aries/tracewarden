"""Taint pass - the flagship detector.

Content returned by *external / untrusted* tools (web fetch, email read, issue
fetch, file read) is marked tainted. We then track when that tainted text flows
verbatim into a *sensitive sink* (shell exec, network egress, file write). A
verbatim flow from untrusted content into a dangerous action is the signature of
indirect prompt injection.

The analysis is intentionally simple and deterministic: mark sources, index
their distinctive tokens, and look for those tokens re-appearing downstream in a
sink's arguments. No model, no heuristic guessing beyond substring dataflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import patterns as P
from .schema import Event, Trace


@dataclass
class TaintFlow:
    """A verbatim flow of tainted content into a downstream sink."""

    source_index: int
    sink_index: int
    token: str  # the shared substring that proves the flow


@dataclass
class ScanContext:
    """Pre-computed analysis shared across all rules for one trace."""

    trace: Trace
    ingest_events: List[Event] = field(default_factory=list)
    external_ingest_events: List[Event] = field(default_factory=list)
    shell_sinks: List[Event] = field(default_factory=list)
    network_sinks: List[Event] = field(default_factory=list)
    filewrite_sinks: List[Event] = field(default_factory=list)
    secret_event_indices: set = field(default_factory=set)

    # -- capability predicates (used by the lethal-trifecta rule) ----------- #
    def has_untrusted_input(self) -> bool:
        return bool(self.external_ingest_events)

    def has_secret_access(self) -> bool:
        return bool(self.secret_event_indices)

    def has_exfil_channel(self) -> bool:
        for ev in self.network_sinks:
            if P.external_hosts(ev.text_blob()):
                return True
        return False

    def taint_flows_into(self, sink: Event) -> Optional[TaintFlow]:
        """Return the flow if any tainted source's token appears in ``sink`` args."""
        blob = sink.args_blob()
        if not blob:
            return None
        for src in self.ingest_events:
            if src.index >= sink.index:
                continue
            for token in P.significant_tokens(src.result_blob()):
                if token in blob:
                    return TaintFlow(source_index=src.index, sink_index=sink.index, token=token)
        return None


def _is_ingest(ev: Event) -> bool:
    return (
        ev.kind == "tool_call"
        and ev.tool_name is not None
        and bool(P.RE_EXTERNAL_INGEST.search(ev.tool_name))
        and bool(ev.result)
    )


def _is_external_ingest(ev: Event) -> bool:
    """Ingest from a genuinely external channel (web/email/issue/remote doc).

    A plain local ``read_file`` is still tainted (it could read attacker-planted
    content) but only *web-facing* ingestion counts towards the "untrusted
    input" leg of the lethal trifecta, to keep that critical rule precise.
    """
    if not _is_ingest(ev):
        return False
    name = ev.tool_name.lower()
    web_markers = (
        "fetch", "http", "web", "browse", "scrape", "crawl", "url",
        "issue", "pull_request", "comment", "email", "gmail", "imap",
        "inbox", "rss", "download", "retriev",
    )
    if any(m in name for m in web_markers):
        return True
    # A file read is external if it pulls in a URL or reads a non-local path.
    return bool(P.external_hosts(ev.result_blob()))


def build_context(trace: Trace) -> ScanContext:
    ctx = ScanContext(trace=trace)

    for ev in trace.events:
        if ev.kind != "tool_call" or not ev.tool_name:
            continue
        name = ev.tool_name

        if _is_ingest(ev):
            ev.tainted = True
            ev.taint_reason = f"content returned by untrusted tool '{name}'"
            ev.taint_source = ev.index
            ctx.ingest_events.append(ev)
            if _is_external_ingest(ev):
                ctx.external_ingest_events.append(ev)

        if P.RE_SHELL_SINK.search(name):
            ctx.shell_sinks.append(ev)
        if P.RE_NETWORK_SINK.search(name):
            ctx.network_sinks.append(ev)
        if P.RE_FILE_WRITE_SINK.search(name):
            ctx.filewrite_sinks.append(ev)

    # Record which events carry secret material in their arguments so the
    # trifecta rule and reporters can cross-reference cheaply.
    for ev in trace.tool_calls():
        blob = ev.args_blob()
        for _id, _title, _sev, _owasp, rx in P.SECRET_PATTERNS:
            if rx.search(blob):
                ctx.secret_event_indices.add(ev.index)
                break
        # reading a secret-bearing file also counts as secret access
        if any(m in ev.text_blob().lower() for m in (".env", "credentials", "id_rsa", "/.ssh")):
            if ev.result:  # actually returned secret-ish content
                ctx.secret_event_indices.add(ev.index)

    return ctx


def propagate_flow_markers(ctx: ScanContext) -> List[TaintFlow]:
    """Annotate sink events that received tainted data; return all flows."""
    flows: List[TaintFlow] = []
    sinks = {e.index: e for e in (ctx.shell_sinks + ctx.network_sinks + ctx.filewrite_sinks)}
    for sink in sinks.values():
        flow = ctx.taint_flows_into(sink)
        if flow:
            sink.tainted = True
            sink.taint_source = flow.source_index
            sink.taint_reason = (
                f"argument contains data from untrusted event #{flow.source_index}"
            )
            flows.append(flow)
    return flows
