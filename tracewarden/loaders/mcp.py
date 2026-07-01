"""Adapter for a simple MCP (Model Context Protocol) call log.

Expected shape (either a top-level object or a bare list)::

    {"mcp_version": "1.0", "calls": [
        {"tool": "read_file", "server": "fs",
         "arguments": {...}, "result": "..."},
        ...
    ]}

Field aliases are tolerated: ``name``/``method`` for tool, ``params``/``input``
for arguments, ``response``/``output``/``content`` for result.
"""

from __future__ import annotations

import json
from typing import Any, List

from ..schema import Event, Trace


def _calls(obj: Any) -> List[dict]:
    if isinstance(obj, dict):
        return obj.get("calls") or obj.get("log") or obj.get("entries") or []
    if isinstance(obj, list):
        return obj
    return []


def matches(obj: Any) -> bool:
    if isinstance(obj, dict) and ("mcp_version" in obj or "calls" in obj):
        return True
    for call in _calls(obj):
        if isinstance(call, dict) and ("tool" in call or "method" in call) and (
            "arguments" in call or "params" in call or "input" in call
        ):
            return True
    return False


def _get(call: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in call and call[k] is not None:
            return call[k]
    return default


def parse(obj: Any) -> Trace:
    events: List[Event] = []
    for idx, call in enumerate(_calls(obj)):
        if not isinstance(call, dict):
            continue
        name = _get(call, "tool", "name", "method")
        args = _get(call, "arguments", "params", "input", default={})
        if not isinstance(args, dict):
            args = {"value": args}
        result = _get(call, "result", "response", "output", "content")
        events.append(
            Event(
                index=idx,
                kind="tool_call",
                tool_name=name,
                arguments=args,
                result=_stringify(result),
                origin=_get(call, "server", "origin", "source"),
                raw=call,
            )
        )
    meta = {}
    if isinstance(obj, dict):
        meta = {k: v for k, v in obj.items() if k in ("mcp_version", "client", "session")}
    return Trace(source_format="mcp", events=events, metadata=meta)


def _stringify(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    return json.dumps(result, default=str, ensure_ascii=False)
