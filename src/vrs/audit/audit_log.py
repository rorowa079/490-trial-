"""Append-only, hash-chained audit log.

Every entry carries the SHA-256 of the entry before it, so editing or removing
any past line breaks the chain from that point on and ``verify()`` reports it.
The log lives in its own file, not in the database, so nothing that can write
to the database can quietly rewrite history.

Every entry records who (``actor``), for which agency (``org``), on which
device (``device``), when (``ts``), what (``action``) and the particulars
(``detail``: search criteria, case number, justification...), which is the
content NIST SP 800-53 AU-3 and the CJIS policy ask for.

Callers must never pass a plaintext plate in ``detail``. Plate searches are
recorded as "plate search (hashed)" with the hash only.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}          # every field is covered by the chain
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, organization: str = "", device: str = ""):
        self.path = Path(path)
        self.organization, self.device = organization, device
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = GENESIS
        if self.path.exists():
            for entry in self._read():
                self._seq, self._last_hash = entry["seq"], entry["hash"]

    def _read(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open() as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def record(self, actor: str, action: str, detail: dict | None = None) -> dict:
        with self._lock:
            entry = {
                "seq": self._seq + 1,
                "ts": time.time(),
                "org": self.organization,
                "device": self.device,
                "actor": actor,
                "action": action,
                "detail": detail or {},
                "prev_hash": self._last_hash,
            }
            entry["hash"] = _digest(entry)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq, self._last_hash = entry["seq"], entry["hash"]
            return entry

    def entries(self, limit: int | None = 200, action: str | None = None, actor: str | None = None,
                ts_from: float | None = None, ts_to: float | None = None) -> list[dict]:
        """Newest first. ``limit=None`` returns everything that matches."""
        rows = self._read()
        if action:
            rows = [r for r in rows if action.lower() in r["action"].lower()]
        if actor:
            rows = [r for r in rows if r["actor"] == actor]
        if ts_from is not None:
            rows = [r for r in rows if r["ts"] >= ts_from]
        if ts_to is not None:
            rows = [r for r in rows if r["ts"] <= ts_to]
        return (rows if limit is None else rows[-limit:])[::-1]

    def head(self) -> dict:
        """Sequence number and hash of the newest entry. Publishing this lets anyone detect later truncation."""
        return {"seq": self._seq, "hash": self._last_hash}

    def verify(self) -> tuple[bool, int | None]:
        """Return (True, None) if the chain is intact, else (False, first bad seq)."""
        prev, expected_seq = GENESIS, 1
        for entry in self._read():
            if entry["seq"] != expected_seq or entry["prev_hash"] != prev or _digest(entry) != entry["hash"]:
                return False, entry.get("seq", expected_seq)
            prev, expected_seq = entry["hash"], expected_seq + 1
        return True, None
