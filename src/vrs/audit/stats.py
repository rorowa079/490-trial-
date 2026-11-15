"""Daily counters behind the transparency report.

Counts only (vehicles read, hotlist hits, review outcomes). They identify no
vehicle, so they are kept after the sightings they count have been purged;
otherwise a yearly report could never add up.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from ..db import Database

FIELDS = ("reads", "plate_reads", "hits", "approved", "dismissed")


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


class DailyStats:
    def __init__(self, db: Database):
        self.db = db

    def bump(self, field: str, ts: float | None = None, by: int = 1) -> None:
        if field not in FIELDS:
            raise ValueError(f"unknown counter {field!r}")
        day = _day(ts if ts is not None else time.time())
        with self.db.transaction() as conn:
            conn.execute("INSERT OR IGNORE INTO daily_stats (day) VALUES (?)", (day,))
            conn.execute(f"UPDATE daily_stats SET {field} = {field} + ? WHERE day = ?", (by, day))

    def totals(self, day_from: str, day_to: str) -> dict:
        row = self.db.one(
            "SELECT " + ", ".join(f"COALESCE(SUM({f}), 0) AS {f}" for f in FIELDS)
            + " FROM daily_stats WHERE day >= ? AND day <= ?", (day_from, day_to))
        return dict(row)
