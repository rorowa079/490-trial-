"""Legal holds: pause the purge for one bounded time window, nothing more.

A hold names a case, a start and end time, and its own expiry. While it is
active, clips inside the window survive the rolling purge. Clips outside the
window, even on the same day, are still purged on schedule. Holds lapse on
their expiry date unless someone renews them, and every change is logged.
"""
from __future__ import annotations

import time

from ..audit.audit_log import AuditLog
from ..db import Database
from .vault import day_of

MAX_WINDOW_HOURS = 72
MAX_HOLD_DAYS = 180


class LegalHolds:
    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def create(self, case_ref: str, ts_start: float, ts_end: float, hold_days: int, user: str) -> int:
        if not case_ref.strip():
            raise ValueError("a legal hold needs a case reference")
        if ts_end <= ts_start:
            raise ValueError("hold window must end after it starts")
        if ts_end - ts_start > MAX_WINDOW_HOURS * 3600:
            raise ValueError(f"a hold may cover at most {MAX_WINDOW_HOURS} hours of footage")
        if not 1 <= hold_days <= MAX_HOLD_DAYS:
            raise ValueError(f"a hold lasts between 1 and {MAX_HOLD_DAYS} days")
        now = time.time()
        cur = self.db.execute(
            "INSERT INTO legal_holds (case_ref, ts_start, ts_end, expires_ts, created_by, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (case_ref.strip(), ts_start, ts_end, now + hold_days * 86400, user, now),
        )
        self.audit.record(user, "hold.created", {
            "hold_id": cur.lastrowid, "case_ref": case_ref.strip(), "ts_start": ts_start, "ts_end": ts_end,
            "hold_days": hold_days,
        })
        return cur.lastrowid

    def release(self, hold_id: int, user: str) -> None:
        self.db.execute("UPDATE legal_holds SET released_ts = ? WHERE id = ? AND released_ts IS NULL",
                        (time.time(), hold_id))
        self.audit.record(user, "hold.released", {"hold_id": hold_id})

    def active(self, now: float | None = None) -> list[dict]:
        now = now or time.time()
        rows = self.db.query(
            "SELECT * FROM legal_holds WHERE released_ts IS NULL AND expires_ts > ? ORDER BY created_ts DESC", (now,))
        return [dict(r) for r in rows]

    def held_days(self, now: float | None = None) -> set[str]:
        days = set()
        for hold in self.active(now):
            t = hold["ts_start"]
            while t <= hold["ts_end"]:
                days.add(day_of(t))
                t += 86400
            days.add(day_of(hold["ts_end"]))
        return days

    def covers(self, ts_start: float, ts_end: float, now: float | None = None) -> bool:
        """True if a clip spanning [ts_start, ts_end] overlaps any active hold window."""
        return any(ts_start <= h["ts_end"] and ts_end >= h["ts_start"] for h in self.active(now))
