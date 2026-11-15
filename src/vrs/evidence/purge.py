"""Rolling retention.

Two tiers, both configurable:

* Sealed clips   - ``retention.clip_days``  (default 30). Purged by destroying
                   the day's wrapped keys, then removing the dead files.
* Hash index     - ``retention.index_days`` (default 90). Rows are deleted.

Clips inside an active legal hold window are skipped; everything else on that
day still goes.
"""
from __future__ import annotations

import time

from ..audit.audit_log import AuditLog
from ..db import Database
from .legal_hold import LegalHolds
from .snapshots import ReviewSnapshots
from .vault import EvidenceVault, day_of


class PurgeService:
    def __init__(self, db: Database, vault: EvidenceVault, holds: LegalHolds, snapshots: ReviewSnapshots,
                 audit: AuditLog, retention_cfg: dict):
        self.db, self.vault, self.holds, self.snapshots, self.audit = db, vault, holds, snapshots, audit
        self.clip_days = retention_cfg["clip_days"]
        self.index_days = retention_cfg["index_days"]
        self.snapshot_hours = retention_cfg["snapshot_hours"]
        self.last_run: float | None = None

    def run(self, now: float | None = None) -> dict:
        now = now or time.time()
        clip_cutoff_day = day_of(now - self.clip_days * 86400)
        held_days = self.holds.held_days(now)
        keys_destroyed, clips_removed, clips_held = [], 0, 0

        # 1. Sealed clips older than the retention window.
        for key_id in self.vault.key_ids():
            day = key_id.split(".")[0]
            if day >= clip_cutoff_day:
                continue
            clips = self.db.query("SELECT id, ts_start, ts_end FROM clips WHERE key_id = ?", (key_id,))
            keep_key = False
            for clip in clips:
                if day in held_days and self.holds.covers(clip["ts_start"], clip["ts_end"], now):
                    keep_key = True
                    clips_held += 1
                else:
                    self.vault.delete_clip(clip["id"])
                    clips_removed += 1
            if not keep_key:
                self.vault.destroy_key(key_id)
                keys_destroyed.append(key_id)

        # 2. Hash index rows older than the index window.
        index_cutoff = now - self.index_days * 86400
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM alerts WHERE sighting_id IN (SELECT id FROM sightings WHERE ts < ?)",
                         (index_cutoff,))
            sightings_removed = conn.execute("DELETE FROM sightings WHERE ts < ?", (index_cutoff,)).rowcount

        # 3. Review snapshots nobody acted on.
        expired = self.snapshots.expire(self.snapshot_hours, now)
        for name in expired:
            self.db.execute("UPDATE alerts SET snapshot_path = NULL WHERE snapshot_path = ?", (name,))

        self.last_run = now
        result = {
            "keys_destroyed": keys_destroyed, "clips_removed": clips_removed, "clips_held": clips_held,
            "sightings_removed": sightings_removed, "snapshots_expired": len(expired),
        }
        if keys_destroyed or clips_removed or sightings_removed or expired:
            self.audit.record("system", "purge.run", result)
        return result

    def status(self, now: float | None = None) -> dict:
        now = now or time.time()
        oldest = self.db.one("SELECT MIN(ts_start) AS t FROM clips")["t"]
        return {
            "clip_days": self.clip_days, "index_days": self.index_days, "last_run": self.last_run,
            "oldest_clip_ts": oldest,
            "next_clip_purge_ts": (oldest + (self.clip_days + 1) * 86400) if oldest else None,
            "active_holds": len(self.holds.active(now)),
        }
