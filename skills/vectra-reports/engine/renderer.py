"""Render report execution results to HTML, Markdown, or JSON."""

from __future__ import annotations

import html
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from engine.formatters import format_value
from engine.loader import ReportDefinition, SummaryMetric

_MARKDOWN_MAX_ROWS = 50

_SANKEY_PALETTE = (
    "#3182ce", "#805ad5", "#38a169", "#dd6b20",
    "#d69e2e", "#e53e3e", "#0694a2", "#667eea",
    "#ed64a6", "#48bb78", "#f6ad55", "#76e4f7",
)
_SANKEY_MAX_NODES = 12


def _templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def _jinja_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_templates_dir())),
        autoescape=True,
    )
    env.filters["format_value"] = format_value
    env.filters["report_field"] = _get_cell
    return env


def _get_cell(row: dict[str, Any], field: str) -> Any:
    cur: Any = row
    for part in field.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _resolve_row_value(row: dict[str, Any], field: str) -> Any:
    if not isinstance(row, dict) or not field:
        return None
    if field in row:
        return row[field]
    fl = field.lower()
    for k, v in row.items():
        if isinstance(k, str) and k.lower() == fl:
            return v
    return None


def _chart_label(row: dict[str, Any], label_field: str) -> Any:
    v = _resolve_row_value(row, label_field)
    if v is not None:
        return v
    if label_field == "protocol":
        return _resolve_row_value(row, "proto_name")
    return None


def _chart_value(row: dict[str, Any], value_field: str) -> Any:
    v = _resolve_row_value(row, value_field)
    if v is not None:
        return v
    if value_field == "session_count":
        for alt in ("count", "COUNT(*)", "count_star", "cnt"):
            v = _resolve_row_value(row, alt)
            if v is not None:
                return v
    return None


def _rows_for_section(
    results: dict[str, Any], data_source_id: str
) -> tuple[list[dict[str, Any]] | None, str | None]:
    raw = results.get(data_source_id)
    if isinstance(raw, dict) and "error" in raw:
        return None, str(raw["error"])
    if isinstance(raw, list):
        return raw, None
    return [], None


def _aggregate(rows: list[dict[str, Any]], metric: SummaryMetric) -> float | int:
    vals: list[float] = []
    for row in rows:
        v = _get_cell(row, metric.value_field)
        if v is None:
            continue
        try:
            vals.append(float(v))
        except (TypeError, ValueError):
            continue
    if metric.aggregation == "count":
        if not metric.value_field:
            return len(rows)
        return sum(1 for row in rows if _get_cell(row, metric.value_field) is not None)
    if not vals:
        return 0
    if metric.aggregation == "sum":
        return sum(vals)
    if metric.aggregation == "max":
        return max(vals)
    if metric.aggregation == "min":
        return min(vals)
    return 0


def _svg_full_disk(cx: float, cy: float, r: float) -> str:
    return (
        f"M {cx:.2f} {cy - r:.2f} A {r:.2f} {r:.2f} 0 1 1 {cx:.2f} {cy + r:.2f} "
        f"A {r:.2f} {r:.2f} 0 1 1 {cx:.2f} {cy - r:.2f} Z"
    )


def _build_pie_slices(
    rows: list[dict[str, Any]], label_field: str, value_field: str
) -> list[dict[str, Any]]:
    palette = ("#3182ce", "#805ad5", "#38a169", "#dd6b20", "#d69e2e", "#318795")
    parsed: list[tuple[str, float]] = []
    for row in rows:
        lab_raw = _chart_label(row, label_field)
        v_raw = _chart_value(row, value_field)
        try:
            v = float(v_raw)
        except (TypeError, ValueError):
            continue
        if v <= 0:
            continue
        label = "" if lab_raw is None else str(lab_raw)
        parsed.append((label, v))
    total = sum(v for _, v in parsed)
    if total <= 0:
        return []
    cx, cy, r = 100.0, 100.0, 80.0
    out: list[dict[str, Any]] = []
    cum = 0.0
    for idx, (label, v) in enumerate(parsed):
        t0 = -math.pi / 2 + 2 * math.pi * cum / total
        t1 = -math.pi / 2 + 2 * math.pi * (cum + v) / total
        frac = v / total
        if frac >= 0.999999:
            path_d = _svg_full_disk(cx, cy, r)
        else:
            x0 = cx + r * math.cos(t0)
            y0 = cy + r * math.sin(t0)
            x1 = cx + r * math.cos(t1)
            y1 = cy + r * math.sin(t1)
            large = 1 if (t1 - t0) > math.pi else 0
            path_d = (
                f"M {cx:.2f} {cy:.2f} L {x0:.2f} {y0:.2f} A {r:.2f} {r:.2f} 0 "
                f"{large} 1 {x1:.2f} {y1:.2f} Z"
            )
        pct = 100.0 * v / total
        pct_label = f"{pct:.1f}%".replace(".0%", "%")
        out.append(
            {
                "label": label or "(empty)",
                "value_display": format_value(v, "number"),
                "path_d": path_d,
                "color": palette[idx % len(palette)],
                "pct_label": pct_label,
            }
        )
        cum += v
    return out


def _build_sankey_svg(
    rows: list[dict[str, Any]],
    src_field: str,
    dst_field: str,
    value_field: str,
) -> str:
    link_map: dict[tuple[str, str], float] = {}
    for row in rows:
        src = _resolve_row_value(row, src_field)
        dst = _resolve_row_value(row, dst_field)
        val = _resolve_row_value(row, value_field)
        if src is None or dst is None:
            continue
        try:
            val = float(val)
        except (TypeError, ValueError):
            continue
        if val <= 0:
            continue
        link_map[(str(src), str(dst))] = (
            link_map.get((str(src), str(dst)), 0.0) + val
        )
    if not link_map:
        return ""

    src_totals: dict[str, float] = {}
    dst_totals: dict[str, float] = {}
    for (src, dst), val in link_map.items():
        src_totals[src] = src_totals.get(src, 0.0) + val
        dst_totals[dst] = dst_totals.get(dst, 0.0) + val

    top_srcs = sorted(src_totals, key=lambda k: -src_totals[k])[:_SANKEY_MAX_NODES]
    top_dsts = sorted(dst_totals, key=lambda k: -dst_totals[k])[:_SANKEY_MAX_NODES]
    src_set, dst_set = set(top_srcs), set(top_dsts)

    collapsed: dict[tuple[str, str], float] = {}
    for (src, dst), val in link_map.items():
        s = src if src in src_set else "Other"
        d = dst if dst in dst_set else "Other"
        if s == "Other" and d == "Other":
            continue
        collapsed[(s, d)] = collapsed.get((s, d), 0.0) + val
    if not collapsed:
        return ""

    src_t: dict[str, float] = {}
    dst_t: dict[str, float] = {}
    for (src, dst), val in collapsed.items():
        src_t[src] = src_t.get(src, 0.0) + val
        dst_t[dst] = dst_t.get(dst, 0.0) + val
    src_nodes = sorted(src_t, key=lambda k: -src_t[k])
    dst_nodes = sorted(dst_t, key=lambda k: -dst_t[k])

    W = 960
    n_max = max(len(src_nodes), len(dst_nodes))
    H = max(420, n_max * 38 + 80)
    NODE_W = 18
    GAP = 6
    MARGIN_T, MARGIN_B = 30.0, 30.0
    LEFT_R, RIGHT_L = 160, 800
    usable_h = H - MARGIN_T - MARGIN_B

    def _layout(nodes: list[str], totals: dict[str, float]) -> dict[str, dict[str, float]]:
        total_val = sum(totals[n] for n in nodes)
        avail = usable_h - GAP * max(0, len(nodes) - 1)
        pos: dict[str, dict[str, float]] = {}
        y = MARGIN_T
        for node in nodes:
            h = max(8.0, (totals[node] / total_val) * avail)
            pos[node] = {"y": y, "h": h, "total": totals[node]}
            y += h + GAP
        return pos

    src_pos = _layout(src_nodes, src_t)
    dst_pos = _layout(dst_nodes, dst_t)
    src_colors = {n: _SANKEY_PALETTE[i % len(_SANKEY_PALETTE)] for i, n in enumerate(src_nodes)}
    src_off: dict[str, float] = {n: 0.0 for n in src_nodes}
    dst_off: dict[str, float] = {n: 0.0 for n in dst_nodes}
    link_items = sorted(collapsed.items(), key=lambda x: -x[1])

    cx = (LEFT_R + RIGHT_L) / 2.0
    parts: list[str] = [
        f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;">'
    ]

    for (src, dst), val in link_items:
        if src not in src_pos or dst not in dst_pos:
            continue
        sp, dp = src_pos[src], dst_pos[dst]
        lh_s = max(2.0, (val / sp["total"]) * sp["h"])
        lh_d = max(2.0, (val / dp["total"]) * dp["h"])
        y0s = sp["y"] + src_off[src]
        y1s = y0s + lh_s
        y0d = dp["y"] + dst_off[dst]
        y1d = y0d + lh_d
        src_off[src] += lh_s
        dst_off[dst] += lh_d
        path = (
            f"M {LEFT_R} {y0s:.2f} "
            f"C {cx} {y0s:.2f} {cx} {y0d:.2f} {RIGHT_L} {y0d:.2f} "
            f"L {RIGHT_L} {y1d:.2f} "
            f"C {cx} {y1d:.2f} {cx} {y1s:.2f} {LEFT_R} {y1s:.2f} Z"
        )
        color = src_colors.get(src, "#3182ce")
        parts.append(
            f'<path d="{path}" fill="{color}" fill-opacity="0.35" '
            f'stroke="{color}" stroke-width="0.5" stroke-opacity="0.55"/>'
        )

    for node in src_nodes:
        sp = src_pos[node]
        color = src_colors[node]
        label = (node[:22] + "…") if len(node) > 22 else node
        val_str = format_value(sp["total"], "bytes")
        mid_y = sp["y"] + sp["h"] / 2.0
        parts += [
            f'<rect x="{LEFT_R - NODE_W}" y="{sp["y"]:.2f}" width="{NODE_W}" '
            f'height="{sp["h"]:.2f}" fill="{color}" rx="2" opacity="0.9"/>',
            f'<text x="{LEFT_R - NODE_W - 5}" y="{mid_y - 6:.2f}" text-anchor="end" '
            f'dominant-baseline="middle" font-size="11" fill="#2d3748" font-weight="500">'
            f"{html.escape(label)}</text>",
            f'<text x="{LEFT_R - NODE_W - 5}" y="{mid_y + 7:.2f}" text-anchor="end" '
            f'dominant-baseline="middle" font-size="10" fill="#718096">'
            f"{html.escape(val_str)}</text>",
        ]

    for node in dst_nodes:
        dp = dst_pos[node]
        label = (node[:22] + "…") if len(node) > 22 else node
        val_str = format_value(dp["total"], "bytes")
        mid_y = dp["y"] + dp["h"] / 2.0
        parts += [
            f'<rect x="{RIGHT_L}" y="{dp["y"]:.2f}" width="{NODE_W}" '
            f'height="{dp["h"]:.2f}" fill="#4a5568" rx="2" opacity="0.9"/>',
            f'<text x="{RIGHT_L + NODE_W + 5}" y="{mid_y - 6:.2f}" text-anchor="start" '
            f'dominant-baseline="middle" font-size="11" fill="#2d3748" font-weight="500">'
            f"{html.escape(label)}</text>",
            f'<text x="{RIGHT_L + NODE_W + 5}" y="{mid_y + 7:.2f}" text-anchor="start" '
            f'dominant-baseline="middle" font-size="10" fill="#718096">'
            f"{html.escape(val_str)}</text>",
        ]

    parts.append("</svg>")
    return "\n".join(parts)


def _sankey_section_html(title: str, svg: str) -> str:
    t = html.escape(title)
    return (
        f'<section style="background:#fff;border:1px solid #e2e8f0;border-radius:6px;'
        f'margin:16px 24px;overflow:hidden;">'
        f'<div style="padding:12px 20px;border-bottom:1px solid #e2e8f0;background:#f7fafc;">'
        f'<h2 style="margin:0;font-size:14px;font-weight:600;color:#1a202c;">{t}</h2>'
        f'</div>'
        f'<div style="padding:16px 20px;overflow-x:auto;">{svg}</div>'
        f'</section>'
    )


def _mermaid_pie_block(
    section_title: str,
    rows: list[dict[str, Any]],
    label_field: str,
    value_field: str,
) -> str:
    parts: list[str] = []
    for row in rows:
        lab = _chart_label(row, label_field)
        v_raw = _chart_value(row, value_field)
        try:
            v = float(v_raw)
        except (TypeError, ValueError):
            continue
        if v <= 0:
            continue
        label = "(empty)" if lab is None else str(lab)
        label = label.replace('"', "'").replace("\n", " ")[:80]
        parts.append(f'    "{label}" : {v:g}')
    if not parts:
        return ""
    safe_title = section_title.replace('"', "'").replace("\n", " ")[:120]
    return "\n".join(["```mermaid", "pie", f"    title {safe_title}", *parts, "```"])


def _format_metric_display(val: float | int, fmt: str) -> str:
    if fmt == "bytes":
        return format_value(int(val), "bytes")
    if fmt == "duration":
        return format_value(int(val), "duration")
    return format_value(val, "number")


def render_report(
    results: dict[str, Any],
    execution_metadata: dict[str, Any],
    definition: ReportDefinition,
    output_format: str,
    report_params: dict[str, Any],
) -> str:
    """Render execution results to HTML, markdown, or JSON string."""
    fmt = (output_format or definition.output.default_format).lower()
    if fmt not in ("html", "markdown", "json"):
        fmt = definition.output.default_format

    now = datetime.now(timezone.utc)
    title_ctx = {
        **report_params,
        "name": definition.name,
        "id": definition.id,
        "category": definition.category,
        "now": now,
    }
    title_env = SandboxedEnvironment(autoescape=False)
    report_title = title_env.from_string(definition.output.title_template).render(
        **title_ctx
    )

    if fmt == "json":
        return _render_json(definition, report_title, now.isoformat(), results, execution_metadata)
    if fmt == "markdown":
        return _render_markdown(definition, report_title, now.isoformat(), results, execution_metadata)
    return _render_html(definition, report_title, now.isoformat(), results, execution_metadata)


def _render_json(
    definition: ReportDefinition,
    report_title: str,
    now_iso: str,
    results: dict[str, Any],
    execution_metadata: dict[str, Any],
) -> str:
    payload: dict[str, Any] = {
        "title": report_title,
        "generated_at": now_iso,
        "report": {
            "id": definition.id,
            "name": definition.name,
            "version": definition.version,
            "category": definition.category,
        },
        "data_sources": results,
        "execution": execution_metadata,
    }
    return json.dumps(payload, indent=2, default=str)


def _render_markdown(
    definition: ReportDefinition,
    report_title: str,
    now_iso: str,
    results: dict[str, Any],
    execution_metadata: dict[str, Any],
) -> str:
    lines: list[str] = [
        f"# {report_title}",
        "",
        f"*Generated {now_iso} · {definition.category}*",
        "",
    ]
    for sec in definition.sections:
        lines.append(f"## {sec.title}")
        lines.append("")
        rows, err = _rows_for_section(results, sec.data_source)
        if err:
            lines.append(f"**Error:** {err}")
            lines.append("")
            continue
        assert rows is not None
        if sec.type == "summary":
            for m in sec.metrics:
                val = _aggregate(rows, m)
                lines.append(
                    f"**{m.label}:** {_format_metric_display(val, m.format)}"
                )
            lines.append("")
        elif sec.type == "chart":
            if not rows:
                lines.append(sec.empty_message)
                lines.append("")
                continue
            if sec.chart_type == "sankey":
                lines.append(
                    "*Sankey chart: use `--format html` for the interactive SVG. "
                    "Below: top 20 flows.*"
                )
                lines.append("")
                link_map: dict[tuple[str, str], float] = {}
                for row in rows:
                    src = _resolve_row_value(row, sec.label_field)
                    dst = _resolve_row_value(row, sec.dst_field)
                    val_r = _resolve_row_value(row, sec.value_field)
                    if src is None or dst is None:
                        continue
                    try:
                        fv = float(val_r)
                    except (TypeError, ValueError):
                        continue
                    if fv > 0:
                        key = (str(src), str(dst))
                        link_map[key] = link_map.get(key, 0.0) + fv
                top_flows = sorted(link_map.items(), key=lambda x: -x[1])[:20]
                if top_flows:
                    lines.append("| Source | Destination | Value |")
                    lines.append("| --- | --- | --- |")
                    for (src, dst), fv in top_flows:
                        lines.append(
                            f"| {src} | {dst} | {format_value(fv, 'bytes')} |"
                        )
                lines.append("")
            else:  # pie
                lines.append(
                    "*Pie chart: use `--format html` for the inline SVG.*"
                )
                lines.append("")
                for row in rows:
                    lab = _chart_label(row, sec.label_field)
                    v = _chart_value(row, sec.value_field)
                    lines.append(
                        f"- **{lab}:** {format_value(v, 'number')}"
                        if v is not None
                        else f"- **{lab}:** —"
                    )
                lines.append("")
                mermaid = _mermaid_pie_block(
                    sec.title, rows, sec.label_field, sec.value_field
                )
                if mermaid:
                    lines.append(mermaid)
                    lines.append("")
        else:  # table
            if not rows:
                lines.append(sec.empty_message)
                lines.append("")
                continue
            cols = sec.columns
            lines.append("| " + " | ".join(c.label for c in cols) + " |")
            lines.append("| " + " | ".join("---" for _ in cols) + " |")
            limit = min(sec.row_limit, _MARKDOWN_MAX_ROWS, len(rows))
            for row in rows[:limit]:
                cells = [
                    str(format_value(_get_cell(row, c.field), c.format)).replace("|", "\\|")
                    for c in cols
                ]
                lines.append("| " + " | ".join(cells) + " |")
            if len(rows) > limit:
                lines.append("")
                lines.append(f"*Showing {limit} of {len(rows)} rows.*")
            lines.append("")

    if definition.output.include_metadata:
        lines.append("---")
        lines.append("")
        for src in execution_metadata.get("sources", []):
            err = src.get("error") or ""
            lines.append(
                f"- **{src['id']}:** {src.get('row_count', 0)} rows, "
                f"{src.get('duration_ms', 0)} ms"
                + (f" — {err}" if err else "")
            )
        lines.append(f"- **Total:** {execution_metadata.get('total_duration_ms', 0)} ms")
    return "\n".join(lines)


def _render_html(
    definition: ReportDefinition,
    report_title: str,
    now_iso: str,
    results: dict[str, Any],
    execution_metadata: dict[str, Any],
) -> str:
    env = _jinja_env()
    generated_display = format_value(now_iso, "timestamp") if now_iso else now_iso
    section_blocks: list[str] = []

    for sec in definition.sections:
        rows, err = _rows_for_section(results, sec.data_source)
        if err:
            section_blocks.append(_fallback_error_section(sec.title, err))
            continue
        assert rows is not None
        if sec.type == "summary":
            metrics_out = [
                {"label": m.label, "value": _format_metric_display(_aggregate(rows, m), m.format)}
                for m in sec.metrics
            ]
            section_blocks.append(
                env.get_template("summary.html").render(
                    section_title=sec.title, metrics=metrics_out
                )
            )
        elif sec.type == "chart":
            if not rows:
                section_blocks.append(_fallback_empty_section(sec.title, sec.empty_message))
                continue
            if sec.chart_type == "sankey":
                svg = _build_sankey_svg(
                    rows, sec.label_field, sec.dst_field, sec.value_field
                )
                if not svg:
                    section_blocks.append(_fallback_empty_section(sec.title, sec.empty_message))
                    continue
                section_blocks.append(_sankey_section_html(sec.title, svg))
            else:
                slices = _build_pie_slices(rows, sec.label_field, sec.value_field)
                if not slices:
                    section_blocks.append(_fallback_empty_section(sec.title, sec.empty_message))
                    continue
                section_blocks.append(
                    env.get_template("pie_chart.html").render(
                        section_title=sec.title, slices=slices
                    )
                )
        else:  # table
            if not rows:
                section_blocks.append(_fallback_empty_section(sec.title, sec.empty_message))
                continue
            total = len(rows)
            display_rows = rows[: sec.row_limit]
            columns_payload = [
                {"field": c.field, "label": c.label, "format": c.format}
                for c in sec.columns
            ]
            section_blocks.append(
                env.get_template("table.html").render(
                    section_title=sec.title,
                    columns=columns_payload,
                    rows=display_rows,
                    total_rows=total,
                    row_limit=sec.row_limit,
                )
            )

    footer_html = ""
    if definition.output.include_metadata:
        footer_html = _fallback_footer(execution_metadata, definition.version)
    return env.get_template("base.html").render(
        report_title=report_title,
        generated_at=generated_display,
        report_category=definition.category,
        section_html="\n".join(section_blocks),
        footer_html=footer_html,
    )


def _fallback_error_section(title: str, err: str) -> str:
    return (
        f'<section style="margin:16px 24px;padding:16px;border:1px solid #e53e3e;'
        f'border-radius:6px;"><h2>{html.escape(title)}</h2>'
        f"<p>{html.escape(err)}</p></section>"
    )


def _fallback_empty_section(title: str, message: str) -> str:
    return (
        f'<section style="margin:16px 24px;padding:32px;text-align:center;'
        f'color:#718096;"><h2>{html.escape(title)}</h2>'
        f"<p>{html.escape(message)}</p></section>"
    )


def _fallback_footer(metadata: dict[str, Any], version: str) -> str:
    lines: list[str] = []
    for src in metadata.get("sources", []):
        err = src.get("error") or ""
        sid = html.escape(str(src.get("id", "")))
        e = html.escape(err) if err else ""
        line = (
            f"{sid}: {src.get('row_count', 0)} rows · {src.get('duration_ms', 0)}ms"
            + (f" · {e}" if e else "")
        )
        lines.append(line)
    body = "<br>".join(lines)
    return (
        f'<footer style="margin:16px 24px 32px;padding:12px 16px;background:#f8f9fa;'
        f'border:1px solid #e2e8f0;border-radius:4px;font-size:11px;color:#718096;'
        f'font-family:SFMono-Regular,Consolas,monospace;line-height:1.8;">'
        f'<strong style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;'
        f'color:#4a5568;">Report Metadata</strong><br>{body}<br>'
        f"Total execution: {metadata.get('total_duration_ms', 0)}ms · "
        f"Report version: {html.escape(version)}</footer>"
    )
