"""Fail closed: when the device may have been tampered with, it stops and forgets.

On a tamper event the controller
  1. runs every registered scrub callback (keys, day keys, pending shares,
     frame buffer) so nothing useful is left in RAM,
  2. writes a lock file so the device stays locked across reboots,
  3. records the event in the audit log.

The device then refuses to process frames until an admin has physically
inspected it and cleared the lock.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Callable

from ..audit.audit_log import AuditLog

log = logging.getLogger(__name__)


class FailClosedController:
    def __init__(self, lock_path: str | Path, audit: AuditLog):
        self.lock_path = Path(lock_path)
        self.audit = audit
        self._scrubbers: list[Callable[[], None]] = []

    def register(self, scrub_callback: Callable[[], None]) -> None:
        self._scrubbers.append(scrub_callback)

    @property
    def locked(self) -> bool:
        return self.lock_path.exists()

    def lock_info(self) -> dict | None:
        return json.loads(self.lock_path.read_text()) if self.locked else None

    def trip(self, reason: str, source: str = "sensor") -> None:
        if self.locked:
            return
        for scrub_callback in self._scrubbers:
            try:
                scrub_callback()
            except Exception:                      # one failed scrub must not stop the others
                log.exception("scrub callback failed during fail-closed")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.write_text(json.dumps({"reason": reason, "source": source, "ts": time.time()}))
        self.audit.record("system", "tamper.locked", {"reason": reason, "source": source})
        log.critical("TAMPER: %s (%s). Device locked.", reason, source)

    def unlock(self, user: str, inspection_note: str) -> None:
        """Clear the lock after a physical inspection. Keys are reloaded by restarting the service."""
        if not self.locked:
            return
        if len(inspection_note.strip()) < 10:
            raise ValueError("unlocking needs a note describing the physical inspection")
        self.lock_path.unlink()
        self.audit.record(user, "tamper.unlocked", {"inspection_note": inspection_note.strip()})
