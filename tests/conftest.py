"""Shared test fixtures and helpers."""

import os

import pytest

from tracewarden import engine, loaders

EXAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "examples")
)


def make_mcp_trace(calls):
    """Build a normalised trace from a list of MCP-style call dicts."""
    return loaders.load_data({"format": "mcp", "calls": calls}, source_path="synthetic.json")


def fired_ids(calls):
    """Rule ids fired by the engine over a synthetic MCP call list."""
    trace = make_mcp_trace(calls)
    return {f.rule_id for f in engine.scan_trace(trace)}


@pytest.fixture
def examples_dir():
    return EXAMPLES_DIR
