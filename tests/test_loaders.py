"""Loader adapters + format auto-detection."""

from tracewarden import loaders


def test_detect_openai_messages():
    obj = {
        "messages": [
            {"role": "assistant", "tool_calls": [
                {"id": "1", "function": {"name": "f", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "1", "content": "ok"},
        ]
    }
    assert loaders.detect_format(obj) == "openai"


def test_detect_mcp_calls():
    obj = {"mcp_version": "1.0", "calls": [
        {"tool": "read_file", "arguments": {"path": "a"}, "result": "x"}]}
    assert loaders.detect_format(obj) == "mcp"


def test_detect_langchain_intermediate_steps():
    obj = {"intermediate_steps": [], "output": "done"}
    assert loaders.detect_format(obj) == "langchain"


def test_detect_langchain_messages():
    obj = {"messages": [{"type": "human", "content": "hi"}]}
    assert loaders.detect_format(obj) == "langchain"


def test_explicit_format_key_wins():
    # Shape looks MCP-ish but explicit format forces openai adapter.
    obj = {"format": "openai", "messages": []}
    assert loaders.detect_format(obj) == "openai"


def test_openai_stitches_tool_results():
    obj = {
        "messages": [
            {"role": "assistant", "tool_calls": [
                {"id": "call_1", "function": {"name": "read_file",
                                              "arguments": "{\"path\": \".env\"}"}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "SECRET_CONTENT"},
        ]
    }
    trace = loaders.load_data(obj)
    calls = trace.tool_calls()
    assert len(calls) == 1
    assert calls[0].tool_name == "read_file"
    assert calls[0].arguments == {"path": ".env"}
    assert calls[0].result == "SECRET_CONTENT"


def test_mcp_field_aliases():
    obj = [{"method": "search", "params": {"q": "x"}, "response": "y"}]
    trace = loaders.load_data(obj, fmt="mcp")
    ev = trace.tool_calls()[0]
    assert ev.tool_name == "search"
    assert ev.arguments == {"q": "x"}
    assert ev.result == "y"


def test_langchain_messages_roundtrip():
    obj = {"messages": [
        {"type": "ai", "tool_calls": [{"id": "t1", "name": "web_fetch",
                                       "args": {"url": "http://x"}}]},
        {"type": "tool", "tool_call_id": "t1", "content": "hello"},
    ]}
    trace = loaders.load_data(obj)
    ev = trace.tool_calls()[0]
    assert ev.tool_name == "web_fetch"
    assert ev.result == "hello"


def test_unrecognised_format_raises():
    import pytest
    with pytest.raises(ValueError):
        loaders.detect_format(42)
