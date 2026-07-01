"""The deterministic rule engine: 28 rules mapped to the OWASP taxonomy.

Each rule is a small generator ``fn(trace, ctx) -> Iterable[Hit]``. The rule's
id / title / severity / OWASP category live in ``RuleMeta`` so the catalog can
never drift from the detection logic. The engine (``engine.py``) enriches each
``Hit`` into a full ``Finding`` using the rule metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Tuple

from . import patterns as P
from .schema import Event, Hit, Trace, truncate
from .taint import ScanContext


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    severity: str
    owasp: str
    description: str


RuleFn = Callable[[Trace, ScanContext], Iterable[Hit]]
RULES: List[Tuple[RuleMeta, RuleFn]] = []


def rule(id, title, severity, owasp, description=""):
    def deco(fn: RuleFn) -> RuleFn:
        RULES.append((RuleMeta(id, title, severity, owasp, description), fn))
        return fn
    return deco


# --------------------------------------------------------------------------- #
# Secret patterns TW001-TW009 (generated from the shared catalog in patterns)
# --------------------------------------------------------------------------- #
def _make_secret_rule(rx):
    def detect(trace: Trace, ctx: ScanContext) -> Iterable[Hit]:
        for ev in trace.tool_calls():
            blob = ev.args_blob()
            m = rx.search(blob)
            if m:
                yield Hit(
                    event_index=ev.index,
                    tool_name=ev.tool_name,
                    message=(
                        f"Secret-looking value passed as an argument to "
                        f"'{ev.tool_name}'. Credentials must never be placed in "
                        f"tool call arguments."
                    ),
                    evidence=truncate(m.group(0)),
                )
    return detect


for _id, _title, _sev, _owasp, _rx in P.SECRET_PATTERNS:
    RULES.append((RuleMeta(_id, _title, _sev, _owasp,
                           "Regex match of a credential pattern in tool arguments."),
                  _make_secret_rule(_rx)))


# --------------------------------------------------------------------------- #
# Dangerous code / command execution TW010-TW014
# --------------------------------------------------------------------------- #
@rule("TW010", "Python subprocess / os.system execution", "HIGH", P.AGENTIC_TOOL_MISUSE,
      "Invocation of subprocess/os.system/os.popen inside tool arguments.")
def r_subprocess(trace, ctx):
    for ev in trace.tool_calls():
        m = P.RE_PY_SUBPROCESS.search(ev.text_blob())
        if m:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=f"'{ev.tool_name}' spawns an OS subprocess, granting arbitrary command execution.",
                      evidence=truncate(m.group(0)))


@rule("TW011", "Dynamic code eval/exec", "HIGH", P.AGENTIC_RCE,
      "Use of eval()/exec() on dynamic input.")
def r_dynamic_eval(trace, ctx):
    for ev in trace.tool_calls():
        m = P.RE_DYNAMIC_EVAL.search(ev.text_blob())
        if m:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=f"'{ev.tool_name}' evaluates dynamic code (eval/exec), enabling code injection.",
                      evidence=truncate(m.group(0)))


@rule("TW012", "Remote script piped to shell (curl | bash)", "CRITICAL", P.AGENTIC_RCE,
      "Downloading and executing a remote script in a single command.")
def r_curl_pipe_shell(trace, ctx):
    for ev in trace.tool_calls():
        m = P.RE_CURL_PIPE_SHELL.search(ev.text_blob())
        if m:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=("Remote script downloaded and piped straight into a shell "
                               "(curl|bash). Executes attacker-controlled code with no review."),
                      evidence=truncate(m.group(0)))


@rule("TW013", "Reverse / bind shell", "CRITICAL", P.AGENTIC_RCE,
      "Reverse-shell or bind-shell command pattern.")
def r_reverse_shell(trace, ctx):
    for ev in trace.tool_calls():
        m = P.RE_REVERSE_SHELL.search(ev.text_blob())
        if m:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=("Reverse/bind shell pattern detected - hands interactive control "
                               "of the host to a remote endpoint."),
                      evidence=truncate(m.group(0)))


@rule("TW014", "Destructive filesystem command", "HIGH", P.AGENTIC_TOOL_MISUSE,
      "Recursive force-delete against a broad path.")
def r_destructive_rm(trace, ctx):
    for ev in trace.tool_calls():
        m = P.RE_DESTRUCTIVE_RM.search(ev.text_blob())
        if m:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message="Recursive force-delete targeting a broad path; risks irreversible data loss.",
                      evidence=truncate(m.group(0)))


# --------------------------------------------------------------------------- #
# Exfiltration / egress TW015-TW018
# --------------------------------------------------------------------------- #
@rule("TW015", "Network egress to external host", "HIGH", P.OWASP_SENSITIVE_INFO,
      "A network sink sends data to a public (non-internal) host.")
def r_network_egress(trace, ctx):
    for ev in ctx.network_sinks:
        hosts = P.external_hosts(ev.text_blob())
        if hosts:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=(f"'{ev.tool_name}' sends data to external host(s): "
                               f"{', '.join(hosts)}. Potential data exfiltration channel."),
                      evidence=truncate(", ".join(hosts)))


@rule("TW016", "Staged exfiltration (file write then upload)", "MEDIUM", P.OWASP_SENSITIVE_INFO,
      "A local file write is followed later by a network upload.")
def r_staged_exfil(trace, ctx):
    if not ctx.filewrite_sinks or not ctx.network_sinks:
        return
    first_write = min(e.index for e in ctx.filewrite_sinks)
    for net in ctx.network_sinks:
        if net.index > first_write and P.external_hosts(net.text_blob()):
            writer = next(e for e in ctx.filewrite_sinks if e.index == first_write)
            yield Hit(net.index, tool_name=net.tool_name,
                      message=("Data staged to a local file and later uploaded externally - "
                               "a classic two-step exfiltration pattern."),
                      evidence=f"write #{first_write} -> upload #{net.index}",
                      related_indices=[first_write])


@rule("TW017", "Outbound message to external recipient", "HIGH", P.OWASP_SENSITIVE_INFO,
      "Email / message send addressed to an external domain.")
def r_outbound_message(trace, ctx):
    for ev in trace.tool_calls():
        name = (ev.tool_name or "").lower()
        if not any(k in name for k in ("email", "send_message", "smtp", "mail", "message")):
            continue
        for m in P.RE_EMAIL_ADDR.finditer(ev.args_blob()):
            domain = m.group(1).lower()
            if not P.is_internal_host(domain):
                yield Hit(ev.index, tool_name=ev.tool_name,
                          message=(f"'{ev.tool_name}' sends a message to external recipient "
                                   f"@{domain}; verify this is not data exfiltration."),
                          evidence=truncate(m.group(0)))
                break


@rule("TW018", "Obfuscated payload before egress", "MEDIUM", P.OWASP_SENSITIVE_INFO,
      "base64/hex/gzip encoding applied immediately before a network egress.")
def r_obfuscated_egress(trace, ctx):
    if not ctx.network_sinks:
        return
    enc_markers = ("base64", "b64encode", "gzip", "zlib", ".hex(", "btoa(")
    for net in ctx.network_sinks:
        if not P.external_hosts(net.text_blob()):
            continue
        for ev in trace.tool_calls():
            if ev.index > net.index:
                continue
            low = ev.text_blob().lower()
            if any(mk in low for mk in enc_markers):
                yield Hit(net.index, tool_name=net.tool_name,
                          message=("Payload is encoded/obfuscated (base64/gzip/hex) shortly "
                                   "before being sent to an external host - typical of stealthy exfiltration."),
                          evidence=truncate(next(mk for mk in enc_markers if mk in low)),
                          related_indices=[ev.index])
                break


# --------------------------------------------------------------------------- #
# Taint flow (flagship) TW019-TW021
# --------------------------------------------------------------------------- #
@rule("TW019", "Untrusted content flows into shell sink", "CRITICAL", P.OWASP_PROMPT_INJECTION,
      "Text from an untrusted tool re-appears verbatim in a shell command.")
def r_taint_to_shell(trace, ctx):
    for sink in ctx.shell_sinks:
        flow = ctx.taint_flows_into(sink)
        if flow:
            yield Hit(sink.index, tool_name=sink.tool_name,
                      message=(f"Content ingested from untrusted event #{flow.source_index} is "
                               f"executed by shell tool '{sink.tool_name}'. Indirect prompt "
                               f"injection -> remote code execution."),
                      evidence=truncate(flow.token),
                      related_indices=[flow.source_index])


@rule("TW020", "Untrusted content flows into network egress", "CRITICAL", P.OWASP_PROMPT_INJECTION,
      "Text from an untrusted tool (URL/secret) re-appears in an outbound request.")
def r_taint_to_network(trace, ctx):
    for sink in ctx.network_sinks:
        flow = ctx.taint_flows_into(sink)
        if flow and P.external_hosts(sink.text_blob()):
            yield Hit(sink.index, tool_name=sink.tool_name,
                      message=(f"Data from untrusted event #{flow.source_index} is sent outbound by "
                               f"'{sink.tool_name}'. The untrusted source is steering an exfiltration "
                               f"request - indirect prompt injection."),
                      evidence=truncate(flow.token),
                      related_indices=[flow.source_index])


@rule("TW021", "Untrusted content flows into file write", "HIGH", P.OWASP_PROMPT_INJECTION,
      "Text from an untrusted tool is written to the filesystem.")
def r_taint_to_filewrite(trace, ctx):
    for sink in ctx.filewrite_sinks:
        flow = ctx.taint_flows_into(sink)
        if flow:
            yield Hit(sink.index, tool_name=sink.tool_name,
                      message=(f"Untrusted content from event #{flow.source_index} is persisted to disk "
                               f"by '{sink.tool_name}'; may poison later runs or overwrite trusted files."),
                      evidence=truncate(flow.token),
                      related_indices=[flow.source_index])


# --------------------------------------------------------------------------- #
# Injection markers + lethal trifecta TW022-TW023
# --------------------------------------------------------------------------- #
@rule("TW022", "Injected instructions in untrusted content", "HIGH", P.OWASP_PROMPT_INJECTION,
      "Untrusted tool output contains prompt-override / imperative attack text.")
def r_injection_markers(trace, ctx):
    for ev in ctx.ingest_events:
        text = ev.result_blob()
        for rx in P.INJECTION_MARKERS:
            m = rx.search(text)
            if m:
                yield Hit(ev.index, tool_name=ev.tool_name,
                          message=(f"Output of untrusted tool '{ev.tool_name}' contains embedded "
                                   f"instructions attempting to hijack the agent (indirect prompt injection)."),
                          evidence=truncate(m.group(0)))
                break


@rule("TW023", "Lethal trifecta: untrusted input + secrets + exfiltration", "CRITICAL",
      P.OWASP_PROMPT_INJECTION,
      "All three legs of the lethal trifecta co-occur in one trace.")
def r_lethal_trifecta(trace, ctx):
    if ctx.has_untrusted_input() and ctx.has_secret_access() and ctx.has_exfil_channel():
        src = ctx.external_ingest_events[0].index
        secret_idx = sorted(ctx.secret_event_indices)[0]
        exfil = next(e for e in ctx.network_sinks if P.external_hosts(e.text_blob()))
        yield Hit(
            exfil.index,
            tool_name=exfil.tool_name,
            message=(
                "LETHAL TRIFECTA: this run combines untrusted input (event "
                f"#{src}), access to secrets (event #{secret_idx}), and an external "
                f"exfiltration channel (event #{exfil.index}). Any prompt injection "
                "in the untrusted input can now steal the secrets."
            ),
            evidence="untrusted-input + secret-access + external-egress",
            related_indices=sorted({src, secret_idx, exfil.index}),
        )


# --------------------------------------------------------------------------- #
# Over-broad scope / sensitive access / PII TW024-TW026
# --------------------------------------------------------------------------- #
@rule("TW024", "Over-broad file glob / wildcard scope", "MEDIUM", P.OWASP_EXCESSIVE_AGENCY,
      "Tool operates over an unbounded wildcard path.")
def r_broad_glob(trace, ctx):
    for ev in trace.tool_calls():
        m = P.RE_BROAD_GLOB.search(ev.args_blob())
        if m:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=(f"'{ev.tool_name}' uses an over-broad wildcard scope. Excessive agency: "
                               f"the tool can touch far more than the task requires."),
                      evidence=truncate(m.group(0)))


@rule("TW025", "Sensitive file access", "HIGH", P.AGENTIC_PRIV_COMPROMISE,
      "Access to credential / key / system files (.env, id_rsa, /etc/passwd...).")
def r_sensitive_file(trace, ctx):
    for ev in trace.tool_calls():
        blob = ev.args_blob().lower() + " " + (ev.result_blob().lower()[:200])
        for marker in P.SENSITIVE_PATH_MARKERS:
            if marker in blob:
                yield Hit(ev.index, tool_name=ev.tool_name,
                          message=(f"'{ev.tool_name}' touches sensitive path '{marker}'. "
                                   f"Reading credentials/keys is a privilege-compromise vector."),
                          evidence=marker)
                break


@rule("TW026", "PII in agent output", "MEDIUM", P.OWASP_SENSITIVE_INFO,
      "Personally identifiable information present in tool output / final answer.")
def r_pii_output(trace, ctx):
    for ev in trace.events:
        text = (ev.result_blob() if ev.kind == "tool_call" else (ev.content or ""))
        if not text:
            continue
        # skip obvious credential files; those are covered by secret rules
        for label, rx in P.PII_PATTERNS:
            m = rx.search(text)
            if m and _looks_like_real_pii(label, m.group(0)):
                yield Hit(ev.index, tool_name=ev.tool_name,
                          message=f"Output appears to contain {label} - review before logging/returning.",
                          evidence=truncate(m.group(0)))
                break


def _looks_like_real_pii(label: str, value: str) -> bool:
    if label == "credit card number":
        digits = [c for c in value if c.isdigit()]
        return len(digits) in (13, 14, 15, 16)
    if label == "phone number":
        digits = [c for c in value if c.isdigit()]
        return len(digits) >= 10
    return True


# --------------------------------------------------------------------------- #
# Multi-agent / resource TW027-TW028
# --------------------------------------------------------------------------- #
@rule("TW027", "Tool-name shadowing / duplicate tool identity", "MEDIUM", P.AGENTIC_IDENTITY_SPOOF,
      "The same tool name is served by two different origins/servers.")
def r_tool_shadowing(trace, ctx):
    seen: dict[str, str] = {}
    for ev in trace.tool_calls():
        if not ev.tool_name or ev.origin is None:
            continue
        prev = seen.get(ev.tool_name)
        if prev is not None and prev != ev.origin:
            yield Hit(ev.index, tool_name=ev.tool_name,
                      message=(f"Tool '{ev.tool_name}' is provided by two different origins "
                               f"('{prev}' and '{ev.origin}'). A shadow tool can impersonate a trusted one."),
                      evidence=f"{prev} vs {ev.origin}")
        else:
            seen.setdefault(ev.tool_name, ev.origin)


@rule("TW028", "Tool-call flooding / resource overload", "LOW", P.AGENTIC_RESOURCE_OVERLOAD,
      "A single tool is called an anomalously high number of times.")
def r_flooding(trace, ctx):
    counts: dict[str, list] = {}
    for ev in trace.tool_calls():
        counts.setdefault(ev.tool_name or "?", []).append(ev.index)
    for name, idxs in counts.items():
        if len(idxs) >= 10:
            yield Hit(idxs[0], tool_name=name,
                      message=(f"Tool '{name}' invoked {len(idxs)} times in one run - possible "
                               f"runaway loop or resource-exhaustion behaviour."),
                      evidence=f"{len(idxs)} calls",
                      related_indices=idxs[1:6])


def catalog() -> List[RuleMeta]:
    """All rule metadata, sorted by id, for docs / --list-rules / SARIF."""
    return sorted((meta for meta, _ in RULES), key=lambda m: m.id)
