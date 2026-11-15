"""Stolen-vehicle hotlist, kept on the device as hashes only.

Plates arrive from the source (a CSV export, an agency feed), are hashed in RAM
with the device key, and only the hash plus non-identifying attributes are
stored. No plaintext hotlist ever exists on disk, so nobody who gets at the
device can read it, and nobody can add a plate to it without the device key.

Every hotlist change is written to the audit log, because the hotlist decides
which vehicles get flagged.

Two ways in
-----------
* ``scripts/hash_hotlist.py``: an operator loads a CSV at the device.
* ``HotlistSync``: the device fetches the list from the agency's server over
  mutual TLS 1.3. It presents its own X.509 certificate (IA-3), accepts only a
  server certificate signed by the pinned CA, and with
  ``hotlist_sync.require_signature`` also checks a detached signature on the
  list itself (SI-7), so neither a spoofed server nor a tampered file can put a
  plate on the list. The list is held in RAM while it is hashed, never on disk.
"""
from __future__ import annotations

import csv
import io
import time
import urllib.request
from pathlib import Path
from typing import Iterable

from ..audit.audit_log import AuditLog
from ..crypto import IntegrityError
from ..db import Database
from ..privacy.hasher import PlateHasher
from ..privacy.scrubber import scrub, to_buffer

ATTRIBUTES = ("color", "body_type", "make", "model")


def _clean(value) -> str | None:
    value = (value or "").strip().lower()
    return value or None


class Hotlist:
    def __init__(self, db: Database, hasher: PlateHasher, audit: AuditLog):
        self.db, self.hasher, self.audit = db, hasher, audit

    def ingest(self, rows: Iterable[dict], source: str, actor: str = "system", replace: bool = False) -> dict:
        """Hash and store hotlist rows. Each row needs ``plate``; attributes are optional."""
        entries, skipped = [], 0
        for row in rows:
            plate_hash = self.hasher.hash_plate(to_buffer(row.get("plate") or ""))
            if plate_hash is None:
                skipped += 1
                continue
            entries.append((
                plate_hash, _clean(row.get("case_ref")), _clean(row.get("color")), _clean(row.get("body_type")),
                _clean(row.get("make")), _clean(row.get("model")), source, time.time(),
            ))
        with self.db.transaction() as conn:
            if replace:
                conn.execute("DELETE FROM hotlist")
            conn.executemany(
                "INSERT OR REPLACE INTO hotlist (plate_hash, case_ref, color, body_type, make, model, source, added_ts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)", entries,
            )
        result = {"stored": len(entries), "skipped": skipped, "replaced": replace}
        self.audit.record(actor, "hotlist.update", {"source": source, **result})
        return result

    def ingest_csv(self, path: str | Path, source: str | None = None, actor: str = "system", replace: bool = False) -> dict:
        """CSV columns: plate, case_ref, color, body_type, make, model (only plate is required)."""
        with open(path, newline="") as fh:
            return self.ingest(csv.DictReader(fh), source or Path(path).name, actor, replace)

    def lookup(self, plate_hash: str) -> dict | None:
        row = self.db.one("SELECT * FROM hotlist WHERE plate_hash = ?", (plate_hash,))
        return dict(row) if row else None

    def count(self) -> int:
        return self.db.one("SELECT COUNT(*) AS n FROM hotlist")["n"]


class HotlistSyncError(RuntimeError):
    pass


class HotlistSync:
    """Pull the hotlist from ``hotlist_sync.url`` over mutual TLS and replace the local one."""

    MAX_BYTES = 50 * 2 ** 20

    def __init__(self, hotlist: Hotlist, cfg: dict, verifier, audit: AuditLog, context_factory=None):
        self.hotlist, self.cfg, self.verifier, self.audit = hotlist, cfg, verifier, audit
        self.settings = cfg["hotlist_sync"]
        self._context_factory = context_factory
        self.last_ok: float | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.settings.get("url"))

    def _context(self):
        if self._context_factory:
            return self._context_factory()
        from ..security.device_identity import client_context
        return client_context(self.cfg, self.settings.get("ca_file", ""))

    def _get(self, url: str, context) -> bytearray:
        with urllib.request.urlopen(url, context=context, timeout=30) as response:     # noqa: S310 (https only)
            data = bytearray(response.read(self.MAX_BYTES + 1))
        if len(data) > self.MAX_BYTES:
            scrub(data)
            raise HotlistSyncError("hotlist is larger than the 50 MB limit")
        return data

    def run_once(self) -> dict:
        url = self.settings["url"]
        payload = None
        try:
            if not url.lower().startswith("https://"):
                raise HotlistSyncError("hotlist_sync.url must be an https:// address")
            context = self._context()
            payload = self._get(url, context)
            if self.settings.get("require_signature", True):
                if self.verifier is None:
                    raise IntegrityError("no update signing key is installed to check the hotlist signature")
                self.verifier.verify_bytes(bytes(payload), bytes(self._get(url + ".sig", context)))
            rows = csv.DictReader(io.StringIO(payload.decode("utf-8-sig")))
            result = self.hotlist.ingest(rows, f"sync:{url}", "hotlist-sync", replace=True)
        except (HotlistSyncError, IntegrityError, OSError, ValueError) as exc:
            # The existing list stays in force; a failed or forged update never empties or alters it.
            self.audit.record("hotlist-sync", "hotlist.sync_failed", {"url": url, "error": str(exc)[:200]})
            raise HotlistSyncError(str(exc)) from exc
        finally:
            scrub(payload)
        self.last_ok = time.time()
        return result
