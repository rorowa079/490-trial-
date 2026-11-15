"""The human verification gate.

A hotlist match becomes a *pending alert* and stops there. The system takes no
outward action on its own: no notification, no dispatch, no export. A logged-in
reviewer must look at the evidence and either approve or dismiss it.

Design rules enforced here:
* Approving needs a written justification; dismissing is one click. The costly
  direction (acting on a wrong match) is the one with friction.
* Dismissals are logged but never counted against the reviewer.
* The reviewer records what they actually saw, next to what the system claimed.
"""
from __future__ import annotations

import json
import time

from ..audit.audit_log import AuditLog
from ..audit.stats import DailyStats
from ..db import Database
from ..evidence.snapshots import ReviewSnapshots

DECISIONS = ("approved", "dismissed")


class ReviewError(ValueError):
    pass


class AlertQueue:
    def __init__(self, db: Database, audit: AuditLog, snapshots: ReviewSnapshots, min_justification_chars: int = 20,
                 daily: DailyStats | None = None):
        self.db, self.audit, self.snapshots = db, audit, snapshots
        self.daily = daily or DailyStats(db)
        self.min_justification = min_justification_chars

    def enqueue(self, sighting_id: int, match: dict, snapshot_jpeg: bytes | None = None) -> int:
        snapshot = self.snapshots.store(snapshot_jpeg) if snapshot_jpeg else None
        cur = self.db.execute(
            "INSERT INTO alerts (sighting_id, hotlist_hash, case_ref, confidence, attr_report, created_ts, snapshot_path)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sighting_id, match["entry"]["plate_hash"], match["entry"].get("case_ref"), match["confidence"],
             json.dumps(match["report"]), time.time(), snapshot),
        )
        self.audit.record("system", "alert.queued", {
            "alert_id": cur.lastrowid, "sighting_id": sighting_id, "confidence": match["confidence"],
            "case_ref": match["entry"].get("case_ref"),
        })
        return cur.lastrowid

    @staticmethod
    def _row(row) -> dict:
        alert = dict(row)
        alert["attr_report"] = json.loads(alert["attr_report"])
        alert["observations"] = json.loads(alert["observations"]) if alert["observations"] else None
        alert["has_snapshot"] = bool(alert.pop("snapshot_path"))
        return alert

    _SELECT = (
        "SELECT a.*, s.ts AS sighting_ts, s.camera_id, s.color, s.body_type, s.make, s.model, s.damage,"
        " s.direction, s.speed_kph, s.ocr_confidence, s.clip_id"
        " FROM alerts a JOIN sightings s ON s.id = a.sighting_id"
    )

    def list(self, status: str | None = "pending", limit: int = 100) -> list[dict]:
        if status:
            rows = self.db.query(self._SELECT + " WHERE a.status = ? ORDER BY a.created_ts DESC LIMIT ?", (status, limit))
        else:
            rows = self.db.query(self._SELECT + " ORDER BY a.created_ts DESC LIMIT ?", (limit,))
        return [self._row(r) for r in rows]

    def get(self, alert_id: int) -> dict | None:
        row = self.db.one(self._SELECT + " WHERE a.id = ?", (alert_id,))
        return self._row(row) if row else None

    def snapshot(self, alert_id: int) -> bytes | None:
        row = self.db.one("SELECT snapshot_path FROM alerts WHERE id = ?", (alert_id,))
        return self.snapshots.load(row["snapshot_path"]) if row and row["snapshot_path"] else None

    def review(self, alert_id: int, reviewer: str, decision: str, justification: str = "",
               observations: dict | None = None) -> dict:
        if decision not in DECISIONS:
            raise ReviewError(f"decision must be one of {DECISIONS}")
        row = self.db.one("SELECT status, snapshot_path FROM alerts WHERE id = ?", (alert_id,))
        if row is None:
            raise ReviewError("no such alert")
        if row["status"] != "pending":
            raise ReviewError("this alert has already been reviewed")
        justification = (justification or "").strip()
        if decision == "approved" and len(justification) < self.min_justification:
            raise ReviewError(f"approving a match needs a written justification of at least "
                              f"{self.min_justification} characters")
        self.db.execute(
            "UPDATE alerts SET status = ?, reviewed_ts = ?, reviewed_by = ?, justification = ?, observations = ?,"
            " snapshot_path = NULL WHERE id = ?",
            (decision, time.time(), reviewer, justification, json.dumps(observations or {}), alert_id),
        )
        self.snapshots.delete(row["snapshot_path"])
        self.daily.bump(decision)
        self.audit.record(reviewer, f"alert.{decision}", {
            "alert_id": alert_id, "justification": justification, "observations": observations or {},
        })
        return self.get(alert_id)

    def pending_count(self) -> int:
        return self.db.one("SELECT COUNT(*) AS n FROM alerts WHERE status = 'pending'")["n"]
