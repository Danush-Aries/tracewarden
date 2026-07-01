"""tracewarden - static security linter for AI agent tool-call traces.

Post-execution trace forensics: point it at a recorded agent run and it
deterministically flags dangerous behaviour (indirect prompt injection, the
lethal trifecta, secret exfiltration, over-broad tool use) offline, with no
LLM calls and no API keys.
"""

from .schema import Event, Finding, Trace
from .engine import scan_file, scan_path, scan_trace

__version__ = "0.1.0"
__author__ = "Dhanush Shankar"

__all__ = [
    "Event",
    "Finding",
    "Trace",
    "scan_file",
    "scan_path",
    "scan_trace",
    "__version__",
]
