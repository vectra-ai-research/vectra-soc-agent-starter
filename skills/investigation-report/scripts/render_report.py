#!/usr/bin/env python3
"""Render an investigation case file (JSON) into one self-contained HTML report.

    python3 render_report.py case.json                 # -> Investigation-Report-<slug>.html
    python3 render_report.py case.json -o report.html
    python3 render_report.py case.json --check         # validate only, write nothing

Design constraints, each one the result of something that broke
--------------------------------------------------------------
**Standard library only.** The tester runs this with bare `python3`. A
dependency means a virtualenv, and a virtualenv means a support thread.

**No JavaScript anywhere in the output.** Progressive disclosure uses native
`<details>`. An earlier timeline renderer produced a blank page because a
pasted snippet re-declared a `const` the template already had; with no script
element, that entire class of failure is impossible rather than merely
unlikely.

**No raw HTML in the case file.** Every string is escaped, then a three-token
mini-markup is applied (`` `code` ``, `**bold**`, `_italic_`). An agent writing
raw HTML into a JSON field will eventually emit something unbalanced and the
page will render wrong in a way nobody notices. Escaping first makes that
impossible; the markup covers what the reports actually needed.

**The agent does not choose a layout.** Six diagram shapes emerged from six
investigations — fan, chain, identity, loop, middle-of-chain, ladder — but
asking a model to pick one is a decision it will sometimes get wrong. Nodes and
edges are laid out automatically by longest-path layering, so the shape is an
emergent property of the evidence.

**Geometry is checked, not trusted.** `_check_overlaps` compares every pair of
node rectangles. A previous report shipped with an identity banner sitting on
top of a DCSync box because the layout was eyeballed.

The case-file contract is documented in ../references/case-schema.md and
validated by validate_case.py. This script validates too — it is the thing that
actually has to survive the data.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

SCHEMA = 1

# --------------------------------------------------------------------- grading

#: How much weight an item carries. The grade is displayed, because grading is
#: what gives a reader permission not to read everything.
GRADES = {
    "decisive": ("Decision-defining", "#b3261e"),
    "supporting": ("Supporting", "#8a5a00"),
    "context": ("Context", "#5f6368"),
    "ambiguous": ("Ambiguous", "#6b4fa0"),
}

#: Gap outcomes, from the gap-closing rule in workflow-entity-deep-dive.md.
OUTCOMES = {
    "CLOSED": "#1e6e3c",
    "NO DATA": "#8a5a00",
    "BLOCKED": "#b3261e",
    "OUT OF REACH": "#5f6368",
}

VERDICTS = {
    "TP-High": "#b3261e",
    "TP-Low": "#8a5a00",
    "BTP": "#1e6e3c",
    "Need-more-data": "#5f6368",
    "NMD": "#5f6368",
}

#: Node roles -> (fill, stroke). Roles rather than colours in the case file, so
#: a case cannot specify something unreadable in dark mode.
ROLES = {
    "subject": ("#fde7e9", "#b3261e"),
    "attacker": ("#fff4e5", "#8a5a00"),
    "victim": ("#e8f0fe", "#1a56b0"),
    "external": ("#f3e8fd", "#6b4fa0"),
    "identity": ("#e6f4ea", "#1e6e3c"),
    "infra": ("#f1f3f4", "#5f6368"),
}
DEFAULT_ROLE = "infra"


class CaseError(Exception):
    """The case file cannot be rendered, with a reason a human can act on."""


# ------------------------------------------------------------------- text

_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<![\w*])_([^_]+)_(?![\w*])")


def inline(text) -> str:
    """Escape *text*, then apply the mini-markup. Never trusts input as HTML."""
    if text is None:
        return ""
    out = html.escape(str(text))
    out = _CODE.sub(r"<code>\1</code>", out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    out = _ITALIC.sub(r"<em>\1</em>", out)
    return out


def slugify(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(text)).strip("-")
    return slug or "entity"


# ------------------------------------------------------------- validation

def _need(obj, key, where):
    if key not in obj or obj[key] in (None, ""):
        raise CaseError(f"{where}: missing required field {key!r}")
    return obj[key]


def validate(case: dict) -> list:
    """Return a list of warnings; raise CaseError for anything unrenderable."""
    warnings = []

    schema = case.get("schema")
    if schema != SCHEMA:
        raise CaseError(
            f"case schema is {schema!r}, this renderer speaks {SCHEMA}. "
            f"See references/case-schema.md."
        )

    entity = _need(case, "entity", "case")
    _need(entity, "name", "entity")

    # The tenant is mandatory, and this is the one field worth refusing to
    # render without. Entity and detection IDs are tenant-scoped and their
    # ranges overlap between tenants, so a report citing bare IDs with no
    # tenant recorded is ambiguous the moment a second tenant exists — and
    # resolves to the wrong entity rather than erroring.
    tenant = _need(case, "tenant", "case")
    _need(tenant, "label", "tenant")

    _need(case, "verdict", "case")
    verdict = case["verdict"].get("code") if isinstance(case["verdict"], dict) else case["verdict"]
    if verdict not in VERDICTS:
        raise CaseError(
            f"verdict {verdict!r} is not one of {', '.join(sorted(VERDICTS))}"
        )

    _need(case, "answer", "case")
    if len(str(case["answer"]).split()) > 90:
        warnings.append("answer is long; it is meant to be the one-sentence answer")
    _need(case, "next_action", "case")

    for name in ("timeline", "evidence"):
        if not case.get(name):
            warnings.append(f"{name} is empty")

    for i, item in enumerate(case.get("timeline") or []):
        _need(item, "title", f"timeline[{i}]")
        grade = item.get("grade", "context")
        if grade not in GRADES:
            raise CaseError(
                f"timeline[{i}].grade is {grade!r}; use one of {', '.join(GRADES)}"
            )

    for i, item in enumerate(case.get("gaps") or []):
        outcome = _need(item, "outcome", f"gaps[{i}]")
        if outcome not in OUTCOMES:
            raise CaseError(
                f"gaps[{i}].outcome is {outcome!r}; use one of {', '.join(OUTCOMES)}"
            )

    diagram = case.get("diagram") or {}
    nodes = diagram.get("nodes") or []
    ids = [n.get("id") for n in nodes]
    if len(set(ids)) != len(ids):
        raise CaseError("diagram node ids must be unique")
    for i, node in enumerate(nodes):
        _need(node, "id", f"diagram.nodes[{i}]")
        _need(node, "label", f"diagram.nodes[{i}]")
        role = node.get("role", DEFAULT_ROLE)
        if role not in ROLES:
            raise CaseError(
                f"diagram.nodes[{i}].role is {role!r}; use one of {', '.join(ROLES)}"
            )
    known = set(ids)
    for i, edge in enumerate(diagram.get("edges") or []):
        for end in ("from", "to"):
            ref = _need(edge, end, f"diagram.edges[{i}]")
            if ref not in known:
                raise CaseError(
                    f"diagram.edges[{i}].{end} is {ref!r}, which is not a node id"
                )

    if nodes and not any(n.get("role") == "subject" for n in nodes):
        warnings.append(
            "no diagram node has role 'subject'; the reader cannot tell which "
            "entity the report is about"
        )

    return warnings


# ----------------------------------------------------------------- diagram

NODE_W = 190
LINE_H = 15
PAD_Y = 11
COL_GAP = 92
ROW_GAP = 26
MARGIN = 18
CHARS_PER_LINE = 26


def _wrap(text: str, width: int = CHARS_PER_LINE) -> list:
    words, lines, current = str(text).split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width or not current:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _layer(nodes: list, edges: list) -> dict:
    """Assign each node a column by longest path from a source.

    Cycles are broken by ignoring any edge that would push a node it has
    already placed — investigations do contain loops (an attacker returning to
    an earlier host), and a layout that raises on one is useless.
    """
    ids = [n["id"] for n in nodes]
    incoming = {i: [] for i in ids}
    outgoing = {i: [] for i in ids}
    for edge in edges:
        if edge.get("back"):
            continue
        outgoing[edge["from"]].append(edge["to"])
        incoming[edge["to"]].append(edge["from"])

    explicit = {n["id"]: n["column"] for n in nodes if isinstance(n.get("column"), int)}
    column = dict(explicit)

    # Sources: no incoming edges. If every node has one (a pure cycle), start
    # from the first node so the layout still resolves.
    frontier = [i for i in ids if not incoming[i] and i not in column]
    if not frontier and not column:
        frontier = [ids[0]]
    for i in frontier:
        column[i] = 0

    for _ in range(len(ids) + 1):          # bounded: no infinite loop on a cycle
        changed = False
        for node_id in ids:
            if node_id not in column:
                continue
            for target in outgoing[node_id]:
                if target in explicit:
                    continue
                candidate = column[node_id] + 1
                if column.get(target, -1) < candidate:
                    column[target] = candidate
                    changed = True
        if not changed:
            break

    for i in ids:                          # anything unreachable goes in column 0
        column.setdefault(i, 0)
    return column


def _check_overlaps(boxes: list) -> list:
    """Every pair of node rectangles must be disjoint. Eyeballing is not a check."""
    problems = []
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            a, b = boxes[i], boxes[j]
            if (a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"]
                    and a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]):
                problems.append(f"{a['id']!r} overlaps {b['id']!r}")
    return problems


def build_diagram(diagram: dict) -> tuple:
    """Return (svg, problems). Empty svg when there is nothing to draw."""
    nodes = diagram.get("nodes") or []
    edges = diagram.get("edges") or []
    if not nodes:
        return "", []

    column = _layer(nodes, edges)
    by_column = {}
    for node in nodes:
        by_column.setdefault(column[node["id"]], []).append(node)

    boxes = {}
    for col in sorted(by_column):
        y = MARGIN
        for node in by_column[col]:
            label_lines = _wrap(node["label"])
            sub_lines = _wrap(node.get("sublabel", ""), 30) if node.get("sublabel") else []
            height = PAD_Y * 2 + LINE_H * len(label_lines) + (12 * len(sub_lines))
            boxes[node["id"]] = {
                "id": node["id"],
                "x": MARGIN + col * (NODE_W + COL_GAP),
                "y": y,
                "w": NODE_W,
                "h": height,
                "label": label_lines,
                "sub": sub_lines,
                "role": node.get("role", DEFAULT_ROLE),
            }
            y += height + ROW_GAP

    problems = _check_overlaps(list(boxes.values()))

    width = max(b["x"] + b["w"] for b in boxes.values()) + MARGIN
    height = max(b["y"] + b["h"] for b in boxes.values()) + MARGIN

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'style="max-width:{width}px" role="img" '
        f'aria-label="Relationship diagram for this investigation" '
        f'xmlns="http://www.w3.org/2000/svg">',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#5f6368"/></marker></defs>',
    ]

    for edge in edges:
        a, b = boxes[edge["from"]], boxes[edge["to"]]
        dashed = ' stroke-dasharray="5 4"' if edge.get("kind") == "dashed" else ""
        if edge.get("back"):
            # Route return edges below everything, so a loop never crosses a box.
            y = height - 6
            x1, x2 = a["x"] + a["w"] / 2, b["x"] + b["w"] / 2
            parts.append(
                f'<path d="M {x1:.0f} {a["y"] + a["h"]:.0f} L {x1:.0f} {y} '
                f'L {x2:.0f} {y} L {x2:.0f} {b["y"] + b["h"]:.0f}" '
                f'fill="none" stroke="#5f6368" stroke-width="1.5"'
                f'{dashed} marker-end="url(#arrow)"/>'
            )
        else:
            x1, y1 = a["x"] + a["w"], a["y"] + a["h"] / 2
            x2, y2 = b["x"], b["y"] + b["h"] / 2
            parts.append(
                f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                f'stroke="#5f6368" stroke-width="1.5"{dashed} '
                f'marker-end="url(#arrow)"/>'
            )
        if edge.get("label"):
            mx = (a["x"] + a["w"] + b["x"]) / 2
            my = (a["y"] + a["h"] / 2 + b["y"] + b["h"] / 2) / 2 - 5
            parts.append(
                f'<text x="{mx:.0f}" y="{my:.0f}" text-anchor="middle" '
                f'class="edgelabel">{inline(edge["label"])}</text>'
            )

    for box in boxes.values():
        fill, stroke = ROLES[box["role"]]
        parts.append(
            f'<rect x="{box["x"]}" y="{box["y"]}" width="{box["w"]}" '
            f'height="{box["h"]:.0f}" rx="6" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="1.5"/>'
        )
        text_y = box["y"] + PAD_Y + 11
        for line in box["label"]:
            parts.append(
                f'<text x="{box["x"] + box["w"] / 2:.0f}" y="{text_y:.0f}" '
                f'text-anchor="middle" class="nodelabel">{inline(line)}</text>'
            )
            text_y += LINE_H
        for line in box["sub"]:
            parts.append(
                f'<text x="{box["x"] + box["w"] / 2:.0f}" y="{text_y:.0f}" '
                f'text-anchor="middle" class="nodesub">{inline(line)}</text>'
            )
            text_y += 12

    parts.append("</svg>")
    return "\n".join(parts), problems


# -------------------------------------------------------------------- HTML

CSS = """
:root{--ink:#1f1f1f;--dim:#5f6368;--rule:#e0e0e0;--bg:#fff;--panel:#f8f9fa}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
 font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:28px 20px 64px}
h1{font-size:26px;margin:0 0 2px}
h2{font-size:17px;margin:34px 0 10px;padding-bottom:5px;border-bottom:1px solid var(--rule)}
.sub{color:var(--dim);font-size:13px;margin:0 0 4px}
.prov{color:var(--dim);font-size:12px;margin:0 0 18px}
.badge{display:inline-block;padding:3px 10px;border-radius:11px;color:#fff;
 font-size:12px;font-weight:600;letter-spacing:.02em}
.answer{background:var(--panel);border-left:4px solid #1a56b0;padding:14px 16px;
 margin:16px 0;font-size:16px}
.action{background:#fff8e1;border-left:4px solid #8a5a00;padding:14px 16px;margin:16px 0}
.action strong{display:block;font-size:12px;text-transform:uppercase;
 letter-spacing:.05em;color:#8a5a00;margin-bottom:4px}
.stats{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.stat{flex:1 1 180px;background:var(--panel);border:1px solid var(--rule);
 border-radius:7px;padding:12px 14px}
.stat b{display:block;font-size:24px;line-height:1.1}
.stat span{display:block;font-size:13px;margin-top:2px}
.stat i{display:block;font-size:12px;color:var(--dim);font-style:normal;margin-top:4px}
.figure{overflow-x:auto;border:1px solid var(--rule);border-radius:7px;
 padding:12px;margin:14px 0;background:var(--bg)}
.nodelabel{font:600 12px sans-serif;fill:#1f1f1f}
.nodesub{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;fill:#5f6368}
.edgelabel{font:11px sans-serif;fill:#5f6368}
table{width:100%;border-collapse:collapse;font-size:13px;margin:12px 0}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--rule);
 vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}
td.t{white-space:nowrap;font-variant-numeric:tabular-nums;color:var(--dim)}
.tag{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;
 font-weight:600;color:#fff;white-space:nowrap}
code{background:var(--panel);padding:1px 4px;border-radius:3px;
 font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}
details{border:1px solid var(--rule);border-radius:7px;padding:10px 13px;margin:9px 0;
 background:var(--bg)}
details[open]{background:var(--panel)}
summary{cursor:pointer;font-weight:600}
details p{margin:9px 0 0}
.legend{font-size:12px;color:var(--dim);margin-top:26px;padding-top:12px;
 border-top:1px solid var(--rule)}
.warn{background:#fff8e1;border:1px solid #8a5a00;border-radius:7px;
 padding:11px 14px;margin:16px 0;font-size:13px}
@media (prefers-color-scheme:dark){
 :root{--ink:#e8eaed;--dim:#9aa0a6;--rule:#3c4043;--bg:#1f2023;--panel:#282a2d}
 .answer{background:var(--panel)}
 .action{background:#332b12}
 .nodelabel{fill:#101010}
 .nodesub{fill:#404040}
 .edgelabel{fill:#9aa0a6}
 .warn{background:#332b12}
}
@media print{.wrap{max-width:none}details{break-inside:avoid}}
"""


def _rows(items, columns):
    out = []
    for item in items:
        cells = "".join(f"<td>{fn(item)}</td>" for _, fn in columns)
        out.append(f"<tr>{cells}</tr>")
    return "\n".join(out)


def _grade_tag(grade):
    label, colour = GRADES.get(grade or "context", GRADES["context"])
    return f'<span class="tag" style="background:{colour}">{label}</span>'


def _section(title, body):
    return f"<h2>{html.escape(title)}</h2>\n{body}" if body else ""


def _claim_blocks(items):
    return "\n".join(
        f"<details><summary>{inline(i.get('claim'))}</summary>"
        f"<p>{inline(i.get('evidence'))}</p></details>"
        for i in items
    )


def render(case: dict, warnings: list) -> str:
    entity = case["entity"]
    tenant = case["tenant"]
    verdict = case["verdict"]
    code = verdict["code"] if isinstance(verdict, dict) else verdict
    colour = VERDICTS[code]

    svg, problems = build_diagram(case.get("diagram") or {})
    if problems:
        raise CaseError("diagram geometry: " + "; ".join(problems))

    ident = " · ".join(
        str(x) for x in (
            f"{entity.get('kind', 'entity')} {entity['id']}" if entity.get("id") else None,
            entity.get("ip"),
            entity.get("note"),
        ) if x
    )

    stats = "".join(
        f'<div class="stat"><b>{inline(s.get("value"))}</b>'
        f'<span>{inline(s.get("label"))}</span>'
        f'<i>{inline(s.get("detail"))}</i></div>'
        for s in (case.get("headline") or [])
    )

    timeline = _rows(case.get("timeline") or [], [
        ("", lambda i: f'<span class="t">{inline(i.get("time"))}</span>'),
        ("", lambda i: (f'<strong>{inline(i.get("title"))}</strong>'
                        + (f'<br>{inline(i.get("detail"))}' if i.get("detail") else ""))),
        ("", lambda i: inline(i.get("lane"))),
        ("", lambda i: f'<code>{inline(i.get("provenance"))}</code>' if i.get("provenance") else ""),
        ("", lambda i: _grade_tag(i.get("grade"))),
    ])

    evidence = _rows(case.get("evidence") or [], [
        ("", lambda i: f'<code>{inline(i.get("id"))}</code>' if i.get("id") else ""),
        ("", lambda i: inline(i.get("what"))),
        ("", lambda i: f'<code>{inline(i.get("source"))}</code>' if i.get("source") else ""),
        ("", lambda i: _grade_tag(i.get("grade"))),
    ])

    gaps = _rows(case.get("gaps") or [], [
        ("", lambda i: inline(i.get("question"))),
        ("", lambda i: (f'<span class="tag" style="background:'
                        f'{OUTCOMES[i["outcome"]]}">{html.escape(i["outcome"])}</span>')),
        ("", lambda i: inline(i.get("detail"))),
    ])

    warn_block = ""
    if warnings:
        warn_block = ('<div class="warn"><strong>Renderer warnings.</strong><ul>'
                      + "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
                      + "</ul></div>")

    body = [
        f'<h1>{inline(entity["name"])}</h1>',
        f'<p class="sub">{inline(ident)}</p>' if ident else "",
        f'<p class="prov">Tenant <code>{inline(tenant["label"])}</code>'
        + (f' · {inline(tenant.get("url"))}' if tenant.get("url") else "")
        + (f' · generated {inline(case.get("generated"))}' if case.get("generated") else "")
        + '</p>',
        f'<p><span class="badge" style="background:{colour}">{html.escape(code)}</span></p>',
        f'<div class="answer">{inline(case["answer"])}</div>',
        f'<div class="action"><strong>Recommended next action</strong>'
        f'{inline(case["next_action"])}</div>',
        warn_block,
        f'<div class="stats">{stats}</div>' if stats else "",
    ]

    # The diagram sits above the narrative on purpose: a reader who meets the
    # shape first spends the prose confirming it rather than assembling it.
    if svg:
        body.append(_section("How these entities relate", f'<div class="figure">{svg}</div>'))

    if case.get("composition"):
        body.append(_section("Why the composition matters", f"<p>{inline(case['composition'])}</p>"))

    if timeline:
        body.append(_section("Sequence", (
            "<table><tr><th>Time</th><th>Event</th><th>Category</th>"
            "<th>Provenance</th><th>Weight</th></tr>" + timeline + "</table>"
        )))

    if case.get("established"):
        body.append(_section("What is established", _claim_blocks(case["established"])))

    if case.get("sweep"):
        body.append(_section("What looking beyond the detections found",
                             _claim_blocks(case["sweep"])))

    # Kept as its own section rather than folded into the findings. An
    # investigation that only reports what it confirmed reads as more certain
    # than it is, and the things a sweep *failed* to establish are how a reader
    # calibrates the rest — a shared TLS fingerprint that links tooling but not
    # operators belongs on the page, clearly labelled as not proven.
    if case.get("ruled_out"):
        body.append(_section("Considered and not established",
                             _claim_blocks(case["ruled_out"])))

    if gaps:
        body.append(_section("Open questions, and what was done about them", (
            "<table><tr><th>Question</th><th>Outcome</th><th>Detail</th></tr>"
            + gaps + "</table>"
        )))

    if case.get("next_steps"):
        body.append(_section("What would settle the rest", "<table>"
            "<tr><th>Do this</th><th>Because</th></tr>" + _rows(case["next_steps"], [
                ("", lambda i: f'<strong>{inline(i.get("title"))}</strong>'),
                ("", lambda i: inline(i.get("why"))),
            ]) + "</table>"))

    if evidence:
        body.append(_section("Evidence and provenance", (
            "<table><tr><th>ID</th><th>What it shows</th><th>Source</th>"
            "<th>Weight</th></tr>" + evidence + "</table>"
        )))

    body.append(
        '<p class="legend"><strong>Weight</strong> — '
        + " · ".join(f"{label}" for label, _ in GRADES.values())
        + '. Every claim above carries the detection ID or tool call it rests on. '
        'Identifiers are scoped to the tenant named at the top: the same ID in '
        'another tenant is a different entity.</p>'
    )

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>Investigation Report — {html.escape(str(entity['name']))}</title>"
        f"<style>{CSS}</style></head><body><div class=\"wrap\">"
        + "\n".join(p for p in body if p)
        + "</div></body></html>\n"
    )


# -------------------------------------------------------------------- main

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("case", help="path to the case JSON file")
    parser.add_argument("-o", "--output", help="output HTML path")
    parser.add_argument("--check", action="store_true",
                        help="validate and lay out, but write nothing")
    args = parser.parse_args(argv)

    try:
        case = json.loads(Path(args.case).read_text())
    except FileNotFoundError:
        print(f"no such case file: {args.case}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"{args.case} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        warnings = validate(case)
        page = render(case, warnings)
    except CaseError as exc:
        print(f"{args.case}: {exc}", file=sys.stderr)
        return 1

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    if args.check:
        nodes = len((case.get("diagram") or {}).get("nodes") or [])
        print(f"OK — {len(page)} bytes, {nodes} diagram nodes, "
              f"{len(case.get('timeline') or [])} timeline entries, "
              f"{len(warnings)} warnings")
        return 0

    out = Path(args.output) if args.output else Path(
        f"Investigation-Report-{slugify(case['entity']['name'])}.html")
    out.write_text(page)
    print(f"wrote {out} ({len(page)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
