"""Reporters: terminal (rich), self-contained HTML, and SARIF JSON."""

from .html import render_html, write_html
from .sarif import build_sarif, write_sarif
from .terminal import render_terminal

__all__ = [
    "render_terminal",
    "render_html",
    "write_html",
    "build_sarif",
    "write_sarif",
]
