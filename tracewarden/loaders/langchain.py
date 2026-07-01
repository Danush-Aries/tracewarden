"""Adapter for LangChain / LangGraph-style traces.

Two shapes are supported:

1. Classic AgentExecutor ``intermediate_steps``::

    {"intermediate_steps": [
        {"action": {"tool": "search", "tool_input": {...}},
         "observation": "..."}
    ], "output": "final answer"}

2. LangGraph message list with typed messages::

    {"messages": [
        {"type": "ai", "tool_calls": [{"name": "...", "args": {...}, "id": "..."}]},
        {"type": "tool", "tool_call_id": "...", "content": "..."},
        {"type": "human", "content": "..."}
    ]}
"""

from __future__ import annotations

import json
from typing import Any, List

from ..schema import Event, Trace


def matches(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    if "intermediate_steps" in obj:
        return True
    msgs = obj.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            if isinstance(m, dict) and m.get("type") in ("ai", "tool", "human", "system"):
                return True
    return False


def parse(obj: Any) -> Trace:
    if "intermediate_steps" in obj:
        return _parse_steps(obj)
    return _parse_messages(obj)


def _parse_steps(obj: dict) -> Trace:
    events: List[Event] = []
    idx = 0
    user = obj.get("input") or obj.get("query")
    if user:
        events.append(Event(index=idx, kind="message", role="user", content=_stringify(user)))
        idx += 1

    for step in obj.get("intermediate_steps") or []:
        action = observation = None
        if isinstance(step, dict):
            action = step.get("action") or step
            observation = step.get("observation")
        elif isinstance(step, (list, tuple)) and len(step) == 2:
            action, observation = step

        tool = tool_input = None
        if isinstance(action, dict):
            tool = action.get("tool") or action.get("name")
            tool_input = action.get("tool_input", action.get("args"))
        if not isinstance(tool_input, dict):
            tool_input = {} if tool_input is None else {"value": tool_input}

        events.append(
            Event(
                index=idx,
                kind="tool_call",
                tool_name=tool,
                arguments=tool_input,
                result=_stringify(observation),
                raw=step if isinstance(step, dict) else {"action": action},
            )
        )
        idx += 1

    output = obj.get("output") or obj.get("final")
    if output:
        events.append(Event(index=idx, kind="message", role="assistant", content=_stringify(output)))
        idx += 1

    return Trace(source_format="langchain", events=events, metadata={"shape": "intermediate_steps"})


def _parse_messages(obj: dict) -> Trace:
    events: List[Event] = []
    call_events: dict[str, Event] = {}
    idx = 0
    for msg in obj.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        mtype = msg.get("type")
        if mtype == "tool":
            cid = msg.get("tool_call_id") or msg.get("id")
            target = call_events.get(cid)
            if target is not None:
                target.result = _stringify(msg.get("content"))
                continue
            events.append(
                Event(index=idx, kind="tool_call", tool_name=msg.get("name"),
                      result=_stringify(msg.get("content")), call_id=cid, raw=msg)
            )
            idx += 1
            continue

        for tc in msg.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            args = tc.get("args") or tc.get("arguments") or {}
            if not isinstance(args, dict):
                args = {"value": args}
            ev = Event(
                index=idx, kind="tool_call", tool_name=tc.get("name"),
                arguments=args, call_id=tc.get("id"), role="ai", raw=tc,
            )
            events.append(ev)
            if ev.call_id:
                call_events[ev.call_id] = ev
            idx += 1

        content = _stringify(msg.get("content"))
        if content:
            role = {"human": "user", "ai": "assistant"}.get(mtype, mtype or "message")
            events.append(Event(index=idx, kind="message", role=role, content=content, raw=msg))
            idx += 1

    return Trace(source_format="langchain", events=events, metadata={"shape": "messages"})


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str, ensure_ascii=False)
