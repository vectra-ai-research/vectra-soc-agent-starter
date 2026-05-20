#!/usr/bin/env python3
"""Validate every YAML definition under definitions/.

Exits non-zero if any file is broken or any directory is empty.
"""

from __future__ import annotations

import _path  # noqa: F401
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from engine.loader import ReportDefinition, definitions_dir


def main() -> int:
    base: Path = definitions_dir()
    if not base.is_dir():
        print(f"error: definitions directory not found: {base}", file=sys.stderr)
        return 2

    files = sorted(base.glob("*.yaml"))
    if not files:
        print(f"error: no YAML files in {base}", file=sys.stderr)
        return 2

    failures: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    for path in files:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("root YAML must be a mapping")
            defn = ReportDefinition.model_validate(data)
        except (ValidationError, yaml.YAMLError, OSError, ValueError) as exc:
            failures.append((path.name, str(exc)))
            continue
        if defn.id in seen_ids:
            failures.append((path.name, f"duplicate report id: {defn.id}"))
            continue
        seen_ids.add(defn.id)
        print(f"  ok  {path.name:40s} -> {defn.id}")

    print()
    if failures:
        print(f"FAILED: {len(failures)} file(s)")
        for name, err in failures:
            print(f"  - {name}: {err}")
        return 1

    print(f"OK: {len(files)} report(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
