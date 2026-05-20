"""Make the engine package importable from the scripts directory.

Each script imports this module first so it can run as
``python scripts/run_report.py ...`` without requiring the user to set
PYTHONPATH or install the package.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
