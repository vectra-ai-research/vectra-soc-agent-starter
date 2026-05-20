#!/usr/bin/env python3
"""List every report bundled with the skill, grouped by category.

Usage:
    python scripts/list_reports.py
    python scripts/list_reports.py --json    # machine-readable
"""

from __future__ import annotations

import _path  # noqa: F401  — sys.path bootstrap
import argparse
import json
import sys
from collections import defaultdict

from engine.loader import load_report_definitions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    defs = load_report_definitions()
    if not defs:
        print("No report definitions found in definitions/.", file=sys.stderr)
        return 1

    if args.json:
        payload = [
            {
                "id": d.id,
                "name": d.name,
                "category": d.category,
                "version": d.version,
                "description": d.description,
                "parameters": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "required": p.required,
                        "default": p.default,
                        "description": p.description,
                    }
                    for p in d.parameters
                ],
            }
            for d in defs
        ]
        print(json.dumps(payload, indent=2, default=str))
        return 0

    by_cat: dict[str, list] = defaultdict(list)
    for d in defs:
        by_cat[d.category].append(d)

    print(f"{len(defs)} report(s) available:\n")
    for cat in sorted(by_cat):
        print(f"== {cat} ==")
        for d in sorted(by_cat[cat], key=lambda x: x.id):
            params = ", ".join(
                f"{p.name}={p.default!r}" if p.default is not None else p.name
                for p in d.parameters
            )
            print(f"  {d.id:36s} {d.name}")
            if d.description:
                first_line = d.description.strip().splitlines()[0]
                print(f"    {first_line[:110]}")
            if params:
                print(f"    params: {params}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
