"""Adapter for OpenAI-style chat/tool-call transcripts.

Accepts either a top-level object with a ``messages`` array, or a bare list of
message objects. Assistant ``tool_calls`` become ``tool_call`` events and the
matching ``role: "tool"`` messages are stitched back in as their ``result``.
"""

from __future__ import annotations

import json
from typing import Any, List

from ..schema import Event, Trace


def _messages(obj: Any) -> List[dict]:
    if isinstance(obj, dict):
        return obj.get("messages") or []
    if isinstance(obj, list):
        return obj
    return []


def matches(obj: Any) -> bool:
    for msg in _messages(obj):
        if not isinstance(msg, dict):
            continue
        if "tool_calls" in msg and isinstance(msg["tool_calls"], list):
            for tc in msg["tool_calls"]:
                if isinstance(tc, dict) and "function" in tc:
                    return True
        if msg.get("role") == "tool" and "tool_call_id" in msg:
            return True
    return False


def _parse_arguments(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except (ValueError, TypeError):
            return {"_raw": raw}
    return {}


def parse(obj: Any) -> Trace:
    messages = _messages(obj)
    events: List[Event] = []
    call_events: dict[str, Event] = {}
    idx = 0

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")

        if role == "tool":
            call_id = msg.get("tool_call_id") or msg.get("call_id")
            content = _stringify(msg.get("content"))
            target = call_events.get(call_id)
            if target is not None:
                target.result = content
            else:  # orphan tool result -> keep as its own event
                events.append(
                    Event(index=idx, kind="tool_call", tool_name=msg.get("name"),
                          result=content, call_id=call_id, raw=msg)
                )
                idx += 1
            continue

        tool_calls = msg.get("tool_calls") or []
        if tool_calls:
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function", {}) if isinstance(tc.get("function"), dict) else {}
                name = fn.get("name") or tc.get("name")
                args = _parse_arguments(fn.get("arguments", tc.get("arguments")))
                ev = Event(
                    index=idx,
                    kind="tool_call",
                    tool_name=name,
                    arguments=args,
                    call_id=tc.get("id") or tc.get("call_id"),
                    role=role,
                    raw=tc,
                )
                events.append(ev)
                if ev.call_id:
                    call_events[ev.call_id] = ev
                idx += 1

        content = _stringify(msg.get("content"))
        if content:
            events.append(
                Event(index=idx, kind="message", role=role, content=content, raw=msg)
            )
            idx += 1

    meta = {"num_messages": len(messages)}
    if isinstance(obj, dict):
        meta.update({k: v for k, v in obj.items() if k in ("model", "id", "name")})
    return Trace(source_format="openai", events=events, metadata=meta)


def _stringify(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # multimodal content blocks
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(block.get("text") or block.get("content") or "")
            else:
                parts.append(str(block))
        return "\n".join(p for p in parts if p)
    return json.dumps(content, default=str)
