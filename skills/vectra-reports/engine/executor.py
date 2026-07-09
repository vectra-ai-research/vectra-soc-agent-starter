"""Parallel-aware executor for report data sources.

Optimisation vs the MCP server's executor:

The original server enforced a strict ≥ 12 second gap between **all**
Investigation Query API calls (submit + every poll, every page), and ran data
sources sequentially. A 3-source report could spend ~36 s purely in rate-gating
even when the queries themselves were fast.

This executor:

1. Submits all investigation queries **concurrently**. The token bucket inside
   ``VectraClient`` enforces the documented 5 req/min ceiling but allows bursts
   so several submissions can race away in parallel.
2. Polls all in-flight queries **concurrently** using ``asyncio.gather``.
3. Runs ``vectra_rest`` data sources concurrently with the investigation jobs —
   they share the same rate bucket but never block each other in code.

For a typical 3-source report, wall-clock drops from ~36 s of pure gating to
roughly the duration of the slowest single query.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import time
from typing import Any

from jinja2.sandbox import SandboxedEnvironment

from engine.client import VectraAPIError, VectraClient
from engine.loader import (
    InvestigationDataSource,
    ReportDefinition,
    VectraRestDataSource,
)

POLL_INTERVAL_SEC = 5
MAX_POLLS = 24  # 24 * 5s = 2 minutes per query

_jinja_sql = SandboxedEnvironment(autoescape=False)
_jinja_args = SandboxedEnvironment(autoescape=False)


class QueryTimeoutError(Exception):
    """Raised when an investigation query did not complete within the poll window."""

    def __init__(self, request_id: str, elapsed_sec: float) -> None:
        self.request_id = request_id
        self.elapsed_sec = elapsed_sec
        super().__init__(
            f"Investigation query timed out after {elapsed_sec:.0f}s "
            f"(request_id={request_id})"
        )


# REST methods we expose to YAML (read-only).
_REST_BLOCKED: frozenset[str] = frozenset(
    {"submit_investigation_query", "get_investigation_results"}
)


def _rest_allowlist() -> frozenset[str]:
    return frozenset(
        name
        for name in dir(VectraClient)
        if (
            name not in _REST_BLOCKED
            and not name.startswith("_")
            and name.startswith(("get_", "search_"))
            and callable(getattr(VectraClient, name, None))
        )
    )


def _merge_template_context(
    report_params: dict[str, Any], source_parameters: dict[str, str]
) -> dict[str, Any]:
    ctx: dict[str, Any] = dict(report_params)
    for key, tmpl in source_parameters.items():
        try:
            ctx[key] = _jinja_sql.from_string(tmpl).render(**ctx)
        except Exception:  # noqa: BLE001 — fall back to raw template
            ctx[key] = tmpl
    return ctx


def _render_sql(query: str, ctx: dict[str, Any]) -> str:
    return _jinja_sql.from_string(query).render(**ctx)


def _rows_from_investigation_response(resp: dict[str, Any]) -> list[dict[str, Any]]:
    data = resp.get("data")
    if data is None:
        data = resp.get("results")
    if data is None:
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _num_pages(meta: dict[str, Any]) -> int:
    if meta.get("num_pages") is not None:
        try:
            return max(1, int(meta["num_pages"]))
        except (TypeError, ValueError):
            pass
    nrows = int(meta.get("num_rows_available") or 0)
    psize = int(meta.get("page_size") or 1) or 1
    return max(1, (nrows + psize - 1) // psize)


async def _run_investigation_source(
    ds: InvestigationDataSource,
    ctx: dict[str, Any],
    client: VectraClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    t0 = time.perf_counter()
    sql = _render_sql(ds.query, ctx)

    submit = await client.submit_investigation_query(sql, version="1.0")
    request_id = submit.get("request_id")
    if not request_id:
        raise VectraAPIError(
            "No request_id from investigation submit", status_code=None
        )

    poll_response: dict[str, Any] | None = None
    poll_started = time.perf_counter()
    for attempt in range(MAX_POLLS):
        await asyncio.sleep(POLL_INTERVAL_SEC)
        try:
            poll_response = await client.get_investigation_results(
                request_id=request_id,
                page=1,
                page_size=ds.pagination.page_size,
            )
        except VectraAPIError as exc:
            # 400 on early polls means the job is still initializing server-side.
            if exc.status_code == 400 and attempt < MAX_POLLS - 1:
                continue
            raise
        status = (poll_response.get("meta") or {}).get("query_status", "").upper()
        if status == "FAILED":
            err = poll_response.get("error", poll_response)
            raise VectraAPIError(
                f"Investigation query failed: {err!r}", status_code=None
            )
        if status == "SUCCESS":
            break
    else:
        raise QueryTimeoutError(request_id, time.perf_counter() - poll_started)

    assert poll_response is not None
    all_rows = _rows_from_investigation_response(poll_response)
    meta = poll_response.get("meta") or {}

    page_errors: list[str] = []
    if ds.pagination.enabled:
        pages = _num_pages(meta)
        fetch_pages = min(pages, ds.pagination.max_pages)
        # Pages 2..N can be fetched in parallel — they're independent reads.
        if fetch_pages > 1:
            extra_pages = await asyncio.gather(
                *(
                    client.get_investigation_results(
                        request_id=request_id,
                        page=p,
                        page_size=ds.pagination.page_size,
                    )
                    for p in range(2, fetch_pages + 1)
                ),
                return_exceptions=True,
            )
            for page_num, resp in enumerate(extra_pages, start=2):
                if isinstance(resp, BaseException):
                    page_errors.append(f"page {page_num}: {resp}")
                    continue
                chunk = _rows_from_investigation_response(resp)
                if chunk:
                    all_rows.extend(chunk)

    out_meta: dict[str, Any] = {
        "request_id": request_id,
        "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }
    if page_errors:
        out_meta["warning"] = (
            f"partial results — {len(page_errors)} page fetch(es) failed: "
            + "; ".join(page_errors)
        )
    return all_rows, out_meta


_INT_RE = re.compile(r"-?\d+")


def _coerce_argument(raw: str) -> Any:
    """Best-effort literal coercion for a rendered YAML argument.

    The REST helpers all take ``**params`` (and under
    ``from __future__ import annotations`` signature annotations are strings
    anyway), so there is no annotation to coerce against — send integers and
    booleans as their natural types, leave everything else as the rendered
    string.
    """
    s = raw.strip()
    if _INT_RE.fullmatch(s):
        return int(s)
    if s.lower() in ("true", "false"):
        return s.lower() == "true"
    return raw


async def _run_vectra_rest(
    ds: VectraRestDataSource,
    ctx: dict[str, Any],
    client: VectraClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    t0 = time.perf_counter()
    if ds.client_method not in _rest_allowlist():
        raise ValueError(
            f"client_method {ds.client_method!r} is not allowlisted for reports"
        )
    method = getattr(client, ds.client_method)
    sig = inspect.signature(method)
    accepts_var_kwargs = any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    named_params = {
        p.name
        for p in sig.parameters.values()
        if p.kind
        in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        and p.name != "self"
    }
    kwargs: dict[str, Any] = {}
    for aname, tmpl in ds.arguments.items():
        if aname not in named_params and not accepts_var_kwargs:
            raise ValueError(
                f"argument {aname!r} is not accepted by "
                f"client_method {ds.client_method!r}"
            )
        rendered = _jinja_args.from_string(tmpl).render(**ctx)
        kwargs[aname] = _coerce_argument(rendered)
    result = await method(**kwargs)
    meta_out = {
        "request_id": None,
        "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)], meta_out
    if isinstance(result, dict):
        if isinstance(result.get("results"), list):
            return [r for r in result["results"] if isinstance(r, dict)], meta_out
        return [result], meta_out
    return [{"value": result}], meta_out


async def _run_one_source(
    ds: Any, ctx: dict[str, Any], client: VectraClient
) -> tuple[str, list[dict[str, Any]] | dict[str, Any], dict[str, Any]]:
    sm: dict[str, Any] = {
        "id": ds.id,
        "row_count": 0,
        "duration_ms": 0.0,
        "error": None,
        "warning": None,
        "request_id": None,
    }
    try:
        if isinstance(ds, InvestigationDataSource):
            rows, m = await _run_investigation_source(ds, ctx, client)
        elif isinstance(ds, VectraRestDataSource):
            rows, m = await _run_vectra_rest(ds, ctx, client)
        else:
            raise ValueError(f"unknown data source type: {type(ds).__name__}")
    except QueryTimeoutError as exc:
        sm["error"] = str(exc)
        return ds.id, {"error": str(exc)}, sm
    except (VectraAPIError, ValueError, TypeError, KeyError) as exc:
        sm["error"] = str(exc)
        return ds.id, {"error": str(exc)}, sm
    sm["row_count"] = len(rows)
    sm["duration_ms"] = m.get("duration_ms", 0.0)
    sm["request_id"] = m.get("request_id")
    sm["warning"] = m.get("warning")
    return ds.id, rows, sm


async def execute_report(
    definition: ReportDefinition,
    params: dict[str, Any],
    client: VectraClient,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run all data sources in parallel.

    Returns:
        ``(results_by_source_id, execution_metadata)``.

        ``results`` values are ``list[dict]`` on success or
        ``{"error": str}`` on per-source failure.
    """
    t_all = time.perf_counter()
    contexts = {ds.id: _merge_template_context(params, ds.parameters) for ds in definition.data_sources}

    completed = await asyncio.gather(
        *(
            _run_one_source(ds, contexts[ds.id], client)
            for ds in definition.data_sources
        ),
        return_exceptions=False,
    )

    results: dict[str, Any] = {}
    sources_meta: list[dict[str, Any]] = []
    for source_id, rows, sm in completed:
        results[source_id] = rows
        sources_meta.append(sm)

    return results, {
        "sources": sources_meta,
        "total_duration_ms": round((time.perf_counter() - t_all) * 1000.0, 2),
    }
