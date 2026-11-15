"""Unsealing evidence: nobody can do it alone.

Flow
----
1. A user files an unseal request for one clip, with a case reference and reason.
2. Custodians log in under their own accounts and each enter their key share.
3. When shares from ``threshold`` *different users* have arrived, the vault
   private key is rebuilt in RAM, the clip is decrypted, and every share and
   the rebuilt key are zeroed.
4. The decrypted frames stay in RAM for a few minutes for viewing, then vanish.
   Nothing unsealed is written to disk.

The two-person rule is enforced twice: by the workflow (distinct accounts) and
by the mathematics (fewer than ``threshold`` shares reveal nothing).
"""
from __future__ import annotations

import json
import threading
import time

from ..audit.audit_log import AuditLog
from ..db import Database
from ..privacy.scrubber import scrub
from . import shamir
from .vault import EvidenceVault, UnsealError


class UnsealService:
    def __init__(self, db: Database, vault: EvidenceVault, audit: AuditLog, threshold: int, view_minutes: float = 10):
        self.db, self.vault, self.audit = db, vault, audit
        self.threshold, self.view_seconds = threshold, view_minutes * 60
        self._lock = threading.Lock()
        self._shares: dict[int, dict[str, str]] = {}                 # request -> user -> share
        self._open: dict[int, tuple[float, list[bytes]]] = {}        # request -> (expiry, frames)

    def request(self, clip_id: str, case_ref: str, reason: str, user: str) -> int:
        if not case_ref.strip() or len(reason.strip()) < 10:
            raise UnsealError("an unseal request needs a case reference and a reason")
        if self.db.one("SELECT 1 FROM clips WHERE id = ?", (clip_id,)) is None:
            raise UnsealError("no such clip (it may have been purged)")
        cur = self.db.execute(
            "INSERT INTO unseal_requests (clip_id, case_ref, reason, requested_by, created_ts) VALUES (?, ?, ?, ?, ?)",
            (clip_id, case_ref.strip(), reason.strip(), user, time.time()),
        )
        self.audit.record(user, "unseal.requested", {
            "request_id": cur.lastrowid, "clip_id": clip_id, "case_ref": case_ref.strip(), "reason": reason.strip()})
        return cur.lastrowid

    def get(self, request_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM unseal_requests WHERE id = ?", (request_id,))
        if row is None:
            return None
        info = dict(row)
        info["contributors"] = json.loads(info["contributors"])
        info["shares_needed"] = self.threshold
        for expired in [rid for rid, (expiry, _) in self._open.items() if expiry <= time.time()]:
            self._open.pop(expired, None)                         # decrypted footage leaves RAM
        entry = self._open.get(request_id)
        info["viewable"] = bool(entry and entry[0] > time.time())
        info["frame_count"] = len(entry[1]) if info["viewable"] else 0
        return info

    def list(self, limit: int = 50) -> list[dict]:
        ids = self.db.query("SELECT id FROM unseal_requests ORDER BY created_ts DESC LIMIT ?", (limit,))
        return [self.get(r["id"]) for r in ids]

    def submit_share(self, request_id: int, user: str, share: str) -> dict:
        with self._lock:
            row = self.db.one("SELECT * FROM unseal_requests WHERE id = ?", (request_id,))
            if row is None:
                raise UnsealError("no such unseal request")
            if row["status"] != "awaiting_shares":
                raise UnsealError(f"this request is already {row['status']}")
            shamir.parse(share)                                   # reject malformed input early
            held = self._shares.setdefault(request_id, {})
            if user in held:
                raise UnsealError("you have already supplied a share for this request")
            held[user] = share.strip()
            self.db.execute("UPDATE unseal_requests SET contributors = ? WHERE id = ?",
                            (json.dumps(sorted(held)), request_id))
            self.audit.record(user, "unseal.share_submitted", {"request_id": request_id, "have": len(held),
                                                                "need": self.threshold})
            if len(held) < self.threshold:
                return self.get(request_id)

            private_key = None
            try:
                private_key = shamir.combine(list(held.values()))
                frames = self.vault.open(row["clip_id"], private_key)
            except (UnsealError, ValueError) as exc:
                self._finish(request_id, "failed")
                self.audit.record("system", "unseal.failed", {"request_id": request_id, "error": str(exc)})
                raise UnsealError(str(exc)) from exc
            finally:
                scrub(private_key)
                self._shares.pop(request_id, None)
            self._open[request_id] = (time.time() + self.view_seconds, frames)
            self._finish(request_id, "unsealed")
            self.audit.record("system", "unseal.opened", {
                "request_id": request_id, "clip_id": row["clip_id"], "case_ref": row["case_ref"],
                "custodians": sorted(held), "requested_by": row["requested_by"]})
            return self.get(request_id)

    def _finish(self, request_id: int, status: str) -> None:
        self.db.execute("UPDATE unseal_requests SET status = ?, resolved_ts = ? WHERE id = ?",
                        (status, time.time(), request_id))

    def frame(self, request_id: int, index: int, user: str) -> bytes:
        """One decrypted frame, for people involved in the request, while the view window is open."""
        info = self.get(request_id)
        if info is None or user not in {info["requested_by"], *info["contributors"]}:
            raise UnsealError("you are not part of this unseal request")
        entry = self._open.get(request_id)
        if not entry or entry[0] <= time.time():
            self._open.pop(request_id, None)
            raise UnsealError("the viewing window for this clip has closed")
        if not 0 <= index < len(entry[1]):
            raise UnsealError("no such frame")
        if index == 0:
            self.audit.record(user, "unseal.viewed", {"request_id": request_id})
        return entry[1][index]

    def scrub(self) -> None:
        """Forget pending shares and decrypted footage (tamper or shutdown)."""
        with self._lock:
            self._shares.clear()
            self._open.clear()
