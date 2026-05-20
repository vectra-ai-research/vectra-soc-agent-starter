"""Standalone Vectra reports engine — no MCP, no IDE coupling."""

import sys

if sys.version_info < (3, 11):
    raise RuntimeError(
        "vectra-reports requires Python 3.11+ (got "
        f"{sys.version_info.major}.{sys.version_info.minor}). "
        "Activate the skill venv (`uv sync` in skills/vectra-reports/) "
        "and re-run from `.venv/bin/python`. If a 3.11+ venv is not "
        "available, switch channels: use `vectra-reports-mcp` (same "
        "reports, no Python required) or `vectra-hunt` (for "
        "investigation pivots that aren't canned reports). Do NOT "
        "hand-roll REST calls against the Investigation Query API."
    )

from engine.client import RateLimitError, VectraAPIError, VectraClient, load_credentials
from engine.executor import execute_report
from engine.loader import ReportDefinition, load_report_definitions
from engine.renderer import render_report

__all__ = [
    "RateLimitError",
    "VectraAPIError",
    "VectraClient",
    "ReportDefinition",
    "execute_report",
    "load_credentials",
    "load_report_definitions",
    "render_report",
]
