"""Smoke tests for the report executor.

Focus: the vectra_rest argument path (YAML `arguments` must reach the
client method through its **params signature) and literal coercion —
the exact regression class CI previously could not catch.

Run from skills/vectra-reports/:

    uv run --extra dev pytest -q tests
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.executor import (  # noqa: E402
    _coerce_argument,
    _merge_template_context,
    _run_vectra_rest,
)
from engine.loader import VectraRestDataSource  # noqa: E402


class StubClient:
    """Mimics VectraClient's **params REST helper shape."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def get_detections(self, **params):
        self.calls.append(params)
        return {"results": [{"id": 1, "type": "hidden_dns_tunnel"}]}


def test_rest_arguments_reach_kwargs_method():
    ds = VectraRestDataSource(
        id="open_detections",
        client_method="get_detections",
        arguments={"page": "1", "page_size": "{{ page_size }}"},
    )
    client = StubClient()
    rows, meta = asyncio.run(_run_vectra_rest(ds, {"page_size": 25}, client))
    assert client.calls == [{"page": 1, "page_size": 25}]
    assert rows == [{"id": 1, "type": "hidden_dns_tunnel"}]
    assert meta["request_id"] is None


def test_rest_unknown_method_rejected():
    ds = VectraRestDataSource(
        id="bad",
        client_method="submit_investigation_query",
        arguments={},
    )
    with pytest.raises(ValueError, match="not allowlisted"):
        asyncio.run(_run_vectra_rest(ds, {}, StubClient()))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("25", 25),
        ("-3", -3),
        ("true", True),
        ("False", False),
        ("active", "active"),
        ("1.5", "1.5"),  # floats stay strings — httpx renders them fine
    ],
)
def test_coerce_argument(raw, expected):
    assert _coerce_argument(raw) == expected


def test_merge_template_context_renders_source_parameters():
    ctx = _merge_template_context(
        {"hours": 24}, {"window": "last {{ hours }}h"}
    )
    assert ctx == {"hours": 24, "window": "last 24h"}
