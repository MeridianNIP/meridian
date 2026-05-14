from __future__ import annotations

from datetime import datetime, timedelta, timezone


def cadence_to_cron(cadence: str, *, time_of_day: int = 7,
                    day_of_week: int = 1, day_of_month: int = 1,
                    custom: str | None = None) -> str:
    """Translate the declarative cadence form from the UI into a 5-field
    cron expression. `time_of_day` is an hour 0-23; `day_of_week` is
    0=Sun..6=Sat; `day_of_month` is 1-28 (clamped to avoid Feb edge)."""
    h = max(0, min(23, int(time_of_day)))
    if cadence == "daily":
        return f"0 {h} * * *"
    if cadence == "weekly":
        dow = max(0, min(6, int(day_of_week)))
        return f"0 {h} * * {dow}"
    if cadence == "monthly":
        dom = max(1, min(28, int(day_of_month)))
        return f"0 {h} {dom} * *"
    if cadence == "custom":
        expr = (custom or "").strip()
        if not expr or len(expr.split()) != 5:
            raise ValueError("Custom cadence requires a 5-field cron expression.")
        return expr
    raise ValueError(f"Unknown cadence {cadence!r}")


def next_fire_after(cron_expr: str, now: datetime | None = None) -> datetime | None:
    """Compute the next fire time for a 5-field cron expression after
    `now`. Tolerant of `*`, `*/N`, comma-lists, and numeric ranges
    — rich enough for the cadence macros + simple custom expressions.
    Returns UTC datetime or None on parse error."""
    if now is None:
        now = datetime.now(timezone.utc)
    fields = cron_expr.split()
    if len(fields) != 5:
        return None
    try:
        m_set   = _parse_field(fields[0], 0, 59)
        h_set   = _parse_field(fields[1], 0, 23)
        dom_set = _parse_field(fields[2], 1, 31)
        mon_set = _parse_field(fields[3], 1, 12)
        dow_set = _parse_field(fields[4], 0, 6)
    except ValueError:
        return None

    # Walk minute by minute up to ~366 days. That's enough for `0 0 1 1 *`.
    t = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(60 * 24 * 366):
        if (t.minute in m_set and t.hour in h_set and t.month in mon_set
                and t.day in dom_set and (t.weekday() + 1) % 7 in dow_set):
            return t
        t += timedelta(minutes=1)
    return None


def _parse_field(raw: str, lo: int, hi: int) -> set[int]:
    if raw == "*":
        return set(range(lo, hi + 1))
    out: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        step = 1
        if "/" in chunk:
            chunk, step_raw = chunk.split("/", 1)
            step = int(step_raw)
        if chunk == "*":
            start, end = lo, hi
        elif "-" in chunk:
            start_raw, end_raw = chunk.split("-", 1)
            start, end = int(start_raw), int(end_raw)
        else:
            start = end = int(chunk)
        if start < lo or end > hi or start > end:
            raise ValueError(f"field out of range: {chunk}")
        out.update(range(start, end + 1, step))
    return out
