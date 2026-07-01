"""Trace loaders: adapters from framework-native formats to the normalised schema.

Public API:
    load(path)         -> Trace   (auto-detects format)
    load_data(obj, fmt)-> Trace   (parse an already-decoded object)
    detect_format(obj) -> str     ("openai" | "mcp" | "langchain")
"""

from __future__ import annotations

import json
from typing import Any

from ..schema import Trace
from . import langchain as _langchain
from . import mcp as _mcp
from . import openai as _openai

ADAPTERS = {
    "openai": _openai.parse,
    "mcp": _mcp.parse,
    "langchain": _langchain.parse,
}


def detect_format(obj: Any) -> str:
    """Best-effort deterministic format detection.

    An explicit ``"format"`` key always wins so callers can be unambiguous.
    """
    if isinstance(obj, dict):
        explicit = obj.get("format") or obj.get("_tracewarden_format")
        if isinstance(explicit, str) and explicit.lower() in ADAPTERS:
            return explicit.lower()
        if _langchain.matches(obj):
            return "langchain"
        if _openai.matches(obj):
            return "openai"
        if _mcp.matches(obj):
            return "mcp"
    if isinstance(obj, list):
        # A bare list of {tool, arguments, result} is the MCP call log shape.
        if _openai.matches(obj):
            return "openai"
        return "mcp"
    raise ValueError("Unrecognised trace format: could not detect an adapter")


def load_data(obj: Any, fmt: str | None = None, source_path: str | None = None) -> Trace:
    fmt = (fmt or detect_format(obj)).lower()
    if fmt not in ADAPTERS:
        raise ValueError(f"Unknown trace format {fmt!r}")
    trace = ADAPTERS[fmt](obj)
    trace.source_path = source_path
    return trace


def load(path: str) -> Trace:
    with open(path, "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    return load_data(obj, source_path=path)


__all__ = ["load", "load_data", "detect_format", "ADAPTERS"]
