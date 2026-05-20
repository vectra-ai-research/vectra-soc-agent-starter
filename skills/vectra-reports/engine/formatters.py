"""Cell value formatters for report output (numbers, bytes, durations, etc.)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def format_bytes(n: int) -> str:
    n = abs(int(n))
    if n <= 999:
        return f"{n} B"
    if n < 1_000_000:
        return f"{n / 1000:.1f} KB".replace(".0 KB", " KB")
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.1f} MB".replace(".0 MB", " MB")
    return f"{n / 1_000_000_000:.1f} GB".replace(".0 GB", " GB")


def format_duration_ms(ms: int) -> str:
    ms = abs(int(ms))
    if ms < 1000:
        return f"{ms}ms"
    if ms < 60_000:
        return f"{ms // 1000}s"
    if ms < 3_600_000:
        m, s = divmod(ms // 1000, 60)
        return f"{m}m {s}s" if s else f"{m}m"
    h, rem = divmod(ms // 1000, 3600)
    m = rem // 60
    return f"{h}h {m}m" if m else f"{h}h"


def format_timestamp(ts: Any) -> str:
    if ts is None:
        return ""
    s = str(ts).strip()
    if not s:
        return ""
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return s


def format_number(n: Any) -> str:
    if n is None:
        return ""
    try:
        x = int(float(n)) if not isinstance(n, int) else n
        return f"{x:,}"
    except (TypeError, ValueError):
        return str(n)


def format_hash(s: Any) -> str:
    if s is None:
        return ""
    t = str(s)
    return t if len(t) <= 16 else t[:16] + "…"


def format_percent(n: Any) -> str:
    try:
        return f"{float(n):.1f}%"
    except (TypeError, ValueError):
        return "" if n is None else str(n)


def format_text(s: Any, max_len: int = 80) -> str:
    if s is None:
        return ""
    t = str(s).replace("\n", " ").replace("\r", "")
    return t if len(t) <= max_len else t[: max_len - 1] + "…"


def format_ip(ip: Any) -> str:
    return "" if ip is None else str(ip)


def format_value(value: Any, fmt: str) -> str:
    """Dispatch by format name (used as a Jinja filter and from renderer code)."""
    if value is None or value == "":
        return ""
    fmt = (fmt or "text").lower()
    if fmt == "bytes":
        try:
            return format_bytes(int(value))
        except (TypeError, ValueError):
            return str(value)
    if fmt == "duration":
        try:
            return format_duration_ms(int(float(value)))
        except (TypeError, ValueError):
            return str(value)
    if fmt == "timestamp":
        return format_timestamp(value)
    if fmt == "ip":
        return format_ip(value)
    if fmt == "number":
        return format_number(value)
    if fmt == "hash":
        return format_hash(value)
    if fmt == "percent":
        return format_percent(value)
    return format_text(value)
