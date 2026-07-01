"""Deterministic detection primitives: regexes, tool taxonomy, host helpers.

Everything here is pure pattern matching. No model, no network, no state.
"""

from __future__ import annotations

import re
from typing import List

# --------------------------------------------------------------------------- #
# OWASP category constants (LLM Top 10 2025 + Agentic AI threat taxonomy T1-T15)
# --------------------------------------------------------------------------- #
OWASP_PROMPT_INJECTION = "LLM01: Prompt Injection"
OWASP_SENSITIVE_INFO = "LLM02: Sensitive Information Disclosure"
OWASP_EXCESSIVE_AGENCY = "LLM06: Excessive Agency"
AGENTIC_TOOL_MISUSE = "Agentic T2: Tool Misuse"
AGENTIC_PRIV_COMPROMISE = "Agentic T3: Privilege Compromise"
AGENTIC_RESOURCE_OVERLOAD = "Agentic T4: Resource Overload"
AGENTIC_RCE = "Agentic T11: Unexpected Code Execution (RCE)"
AGENTIC_IDENTITY_SPOOF = "Agentic T9: Identity Spoofing & Impersonation"

# --------------------------------------------------------------------------- #
# Secret patterns (id, title, severity, owasp, compiled regex)
# The example traces use OBVIOUSLY FAKE tokens (sk-FAKE..., AWS's documented
# AKIAIOSFODNN7EXAMPLE, etc.) so nothing real is ever committed.
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = [
    (
        "TW001",
        "LLM/OpenAI API key in tool arguments",
        "CRITICAL",
        OWASP_SENSITIVE_INFO,
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "TW002",
        "AWS access key id in tool arguments",
        "CRITICAL",
        OWASP_SENSITIVE_INFO,
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "TW003",
        "Private key material in tool arguments",
        "CRITICAL",
        OWASP_SENSITIVE_INFO,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "TW004",
        "GitHub token in tool arguments",
        "CRITICAL",
        OWASP_SENSITIVE_INFO,
        re.compile(r"\bgh[posur]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "TW005",
        "Slack token in tool arguments",
        "HIGH",
        OWASP_SENSITIVE_INFO,
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "TW006",
        "Authorization bearer token in tool arguments",
        "HIGH",
        OWASP_SENSITIVE_INFO,
        re.compile(r"(?i)authorization\W{0,4}bearer\s+[A-Za-z0-9._\-]{12,}"),
    ),
    (
        "TW007",
        "JSON Web Token (JWT) in tool arguments",
        "MEDIUM",
        OWASP_SENSITIVE_INFO,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b"),
    ),
    (
        "TW008",
        "Google API key in tool arguments",
        "HIGH",
        OWASP_SENSITIVE_INFO,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    (
        "TW009",
        "Generic credential assignment in tool arguments",
        "MEDIUM",
        OWASP_SENSITIVE_INFO,
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|"
            r"client[_-]?secret|password|passwd)\b\W{0,4}[\"']?[A-Za-z0-9/+=_\-]{12,}"
        ),
    ),
]

# --------------------------------------------------------------------------- #
# Dangerous command / code patterns (scanned in tool arguments)
# --------------------------------------------------------------------------- #
RE_PY_SUBPROCESS = re.compile(
    r"\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output|check_call)|"
    r"os\.popen|pty\.spawn)\s*\("
)
RE_DYNAMIC_EVAL = re.compile(r"\b(?:eval|exec)\s*\(")
RE_CURL_PIPE_SHELL = re.compile(
    r"(?i)\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"
)
RE_REVERSE_SHELL = re.compile(
    r"(?i)(?:bash\s+-i|/dev/tcp/|nc(?:at)?\s+-e|mkfifo|"
    r"socket\.socket\([^)]*\)[^\n]*connect|python[0-9]?\s+-c\s+['\"]?import\s+socket)"
)
RE_DESTRUCTIVE_RM = re.compile(r"(?i)\brm\s+-[a-z]*[rf][a-z]*\s+(?:-[a-z]+\s+)*(?:/|~|\*|\.\s|\.$)")

# --------------------------------------------------------------------------- #
# Injection / prompt-override markers (scanned in *untrusted* content)
# --------------------------------------------------------------------------- #
INJECTION_MARKERS = [
    re.compile(r"(?i)ignore (?:all |any )?(?:previous|above|prior|earlier) (?:instructions|prompts?)"),
    re.compile(r"(?i)disregard (?:all |the )?(?:previous|above|prior) (?:instructions|context)"),
    re.compile(r"(?i)you are now (?:a |an )?"),
    re.compile(r"(?i)new (?:system )?(?:instructions?|directive|task)\s*[:\-]"),
    re.compile(r"(?i)\bexfiltrat"),
    re.compile(r"(?i)send (?:the |your |its )?(?:full |entire )?(?:contents?|file|secrets?|keys?)[^\n]{0,40}(?:to|via)\b"),
    re.compile(r"(?i)\bPOST\b[^\n]{0,40}(?:to|https?://)"),
    re.compile(r"(?i)(?:run|execute|paste)\s+(?:the\s+)?(?:following|this)\b"),
    re.compile(r"(?i)bash\s+-i|/dev/tcp/"),
    re.compile(r"(?i)base64\b[^\n]{0,30}(?:encode|the|and)"),
    re.compile(r"(?i)forward this[^\n]{0,30}to\b"),
]

# --------------------------------------------------------------------------- #
# Sensitive files / over-broad scope
# --------------------------------------------------------------------------- #
SENSITIVE_PATH_MARKERS = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "/.ssh",
    ".ssh/",
    ".aws/credentials",
    ".aws/config",
    "/etc/passwd",
    "/etc/shadow",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
    ".npmrc",
    ".git-credentials",
    "kubeconfig",
]

RE_BROAD_GLOB = re.compile(r"(\*\*/?\*?|/\*\*|~/\.?\*?|\*\.(?:pem|key|env|p12|pfx)\b|/\*(?:\s|$)|\bfind\s+/\b)")

# --------------------------------------------------------------------------- #
# PII patterns (scanned in outputs / final answers)
# --------------------------------------------------------------------------- #
PII_PATTERNS = [
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("US SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit card number", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("phone number", re.compile(r"\b(?:\+?\d{1,2}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b")),
]

# --------------------------------------------------------------------------- #
# Tool taxonomy: name-based classification of ingest sources and sinks
# --------------------------------------------------------------------------- #
RE_EXTERNAL_INGEST = re.compile(
    r"(?i)(fetch|http_?get|web_?search|web_?fetch|browse|scrape|crawl|"
    r"read_?file|file_?read|load_?file|cat_?file|get_?url|open_?url|read_?url|"
    r"issue|pull_?request|comment|email_?read|read_?email|get_?email|inbox|"
    r"gmail|imap|rss|download|read_?doc|get_?document|retriev|search_?docs?)"
)

RE_SHELL_SINK = re.compile(
    r"(?i)(shell|bash|sh_exec|terminal|exec|run_?command|run_?shell|command|"
    r"subprocess|system|python_?repl|repl|code_?interpreter|eval|os_?exec)"
)

RE_NETWORK_SINK = re.compile(
    r"(?i)(http_?post|http_?put|http_?request|https?_?request|post|put|upload|"
    r"send_?email|send_?message|email_?send|smtp|webhook|slack_?post|discord|"
    r"publish|sync_?upload|cloud_?sync|exfil|curl|api_?call|outbound)"
)

RE_FILE_WRITE_SINK = re.compile(
    r"(?i)(write_?file|file_?write|save_?file|create_?file|append_?file|"
    r"put_?object|fs_?write|overwrite)"
)

# --------------------------------------------------------------------------- #
# Host / URL helpers
# --------------------------------------------------------------------------- #
RE_URL = re.compile(r"https?://([A-Za-z0-9._~%-]+(?::\d+)?)(/[^\s\"'`<>]*)?")
RE_EMAIL_ADDR = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

_RE_RFC1918 = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


def extract_hosts(text: str) -> List[str]:
    """Return every host referenced in URLs inside ``text``."""
    hosts = []
    for m in RE_URL.finditer(text or ""):
        host = m.group(1).split(":")[0].lower()
        hosts.append(host)
    return hosts


def is_internal_host(host: str) -> bool:
    """True for loopback / private / link-local / .local / .internal hosts."""
    host = (host or "").lower().strip().strip(".")
    if host in {"localhost", "0.0.0.0", "::1", ""}:
        return True
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".svc"):
        return True
    if _RE_RFC1918.match(host):
        return True
    if "." not in host and ":" not in host:  # bare hostname, treat as internal
        return True
    return False


def external_hosts(text: str) -> List[str]:
    """External (public / attacker-reachable) hosts referenced in ``text``."""
    seen, out = set(), []
    for host in extract_hosts(text):
        if not is_internal_host(host) and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def significant_tokens(text: str, min_len: int = 15) -> List[str]:
    """Long, distinctive tokens/lines usable for substring taint tracking.

    We keep whole lines and whitespace/quote-delimited tokens above ``min_len``
    so that URLs, secret values and injected commands become traceable when
    they later re-appear verbatim inside a sink's arguments.
    """
    out, seen = [], set()
    if not text:
        return out
    candidates = re.split(r"[\r\n]+", text) + re.split(r"[\s\"'`]+", text)
    for tok in candidates:
        tok = tok.strip().strip("\"'`,;")
        if len(tok) >= min_len and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out
