#!/usr/bin/env python3
"""Show full metadata for a single report (parameters, queries, sections).

Usage:
    python scripts/show_report.py <report_id>
    python scripts/show_report.py <report_id> --json
"""

from __future__ import annotations

import _path  # noqa: F401
import argparse
import json
import sys

from engine.loader import find_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_id", help="ID of the report to inspect.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    defn = find_report(args.report_id)
    if defn is None:
        print(f"error: report {args.report_id!r} not found", file=sys.stderr)
        print("Hint: run `python scripts/list_reports.py`", file=sys.stderr)
        return 1

    if args.json:
        print(defn.model_dump_json(indent=2))
        return 0

    print(f"# {defn.name}  ({defn.id})")
    print(f"category: {defn.category}    version: {defn.version}")
    print()
    if defn.description:
        print(defn.description.strip())
        print()

    print("## Parameters")
    if not defn.parameters:
        print("  (none)")
    for p in defn.parameters:
        req = " [required]" if p.required else ""
        default = f" (default: {p.default!r})" if p.default is not None else ""
        print(f"  --{p.name}: {p.type}{req}{default}")
        if p.description:
            print(f"      {p.description}")
    print()

    print("## Data sources")
    for ds in defn.data_sources:
        print(f"  {ds.id}  ({ds.type})")
        if ds.type == "investigation_query":
            sql = ds.query.strip().splitlines()
            for ln in sql[:6]:
                print(f"      | {ln}")
            if len(sql) > 6:
                print(f"      | ... ({len(sql) - 6} more lines)")
        elif ds.type == "vectra_rest":
            print(f"      method: {ds.client_method}")
            for k, v in ds.arguments.items():
                print(f"      arg {k}: {v}")
    print()

    print("## Sections")
    for sec in defn.sections:
        print(f"  {sec.id}: {sec.title}  ({sec.type})")
        if sec.type == "summary":
            for m in sec.metrics:
                print(f"      metric: {m.label} = {m.aggregation}({m.value_field}) :{m.format}")
        elif sec.type == "table":
            for c in sec.columns:
                print(f"      column: {c.label} = {c.field} :{c.format}")
        elif sec.type == "chart":
            print(f"      chart_type: {sec.chart_type}")
            print(f"      label_field: {sec.label_field}")
            if sec.dst_field:
                print(f"      dst_field:   {sec.dst_field}")
            print(f"      value_field: {sec.value_field}")

    print()
    print(
        f"## Output\n  default_format: {defn.output.default_format}\n"
        f"  title: {defn.output.title_template}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
