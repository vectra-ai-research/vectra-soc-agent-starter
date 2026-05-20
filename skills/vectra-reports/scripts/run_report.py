#!/usr/bin/env python3
"""Run a Vectra report end-to-end and write the rendered output to stdout.

Usage:
    python scripts/run_report.py <report_id> [--<param> <value> ...] [--format html|markdown|json]

Examples:
    python scripts/run_report.py active_connections --hours 1
    python scripts/run_report.py c2_beacon_report --hours 24 --limit 100 --format markdown
    python scripts/run_report.py top_talkers_senders_by_ip --hours 6 > talkers.html

Behaviour:
    * Investigation queries within the report are submitted and polled in
      parallel, gated only by the documented 5 req/min token bucket.
    * Errors in any single data source are isolated — other sections still
      render. Per-source errors appear in the report footer.
"""

from __future__ import annotations

import _path  # noqa: F401
import argparse
import asyncio
import sys
from typing import Any

from engine.client import VectraClient, load_credentials
from engine.executor import execute_report
from engine.loader import ReportDefinition, find_report
from engine.renderer import render_report


def _coerce(value: str, type_name: str) -> Any:
    if type_name == "int":
        return int(value)
    if type_name == "bool":
        return value.lower() in ("1", "true", "yes", "on")
    return value


def _build_arg_parser(defn: ReportDefinition) -> argparse.ArgumentParser:
    """Build a parser whose flags reflect the report's declared parameters."""
    parser = argparse.ArgumentParser(
        prog=f"run_report.py {defn.id}",
        description=defn.description or defn.name,
    )
    for p in defn.parameters:
        kwargs: dict[str, Any] = {
            "help": (p.description or "") + (
                f" (default: {p.default!r})" if p.default is not None else ""
            ),
            "required": p.required and p.default is None,
        }
        if p.default is not None:
            kwargs["default"] = str(p.default)
        parser.add_argument(f"--{p.name}", **kwargs)
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("html", "markdown", "json"),
        default=defn.output.default_format,
        help=f"Output format (default: {defn.output.default_format}).",
    )
    return parser


async def _run(defn: ReportDefinition, params: dict[str, Any], output_format: str) -> str:
    creds = load_credentials()
    async with VectraClient(creds) as client:
        results, meta = await execute_report(defn, params, client)
    return render_report(results, meta, defn, output_format, params)


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0 if "-h" in sys.argv or "--help" in sys.argv else 2

    report_id = sys.argv[1]
    defn = find_report(report_id)
    if defn is None:
        print(f"error: report {report_id!r} not found", file=sys.stderr)
        print("Hint: run `python scripts/list_reports.py`", file=sys.stderr)
        return 1

    parser = _build_arg_parser(defn)
    args = parser.parse_args(sys.argv[2:])

    params: dict[str, Any] = {}
    for p in defn.parameters:
        raw = getattr(args, p.name, None)
        if raw is None:
            if p.required:
                parser.error(f"--{p.name} is required")
            continue
        try:
            params[p.name] = _coerce(str(raw), p.type)
        except (TypeError, ValueError) as exc:
            parser.error(f"--{p.name}: invalid {p.type} value {raw!r}: {exc}")

    try:
        rendered = asyncio.run(_run(defn, params, args.output_format))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(rendered)
    if not rendered.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
