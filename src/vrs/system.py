"""Wires every subsystem together. Used by app.py, the scripts and the tests."""
from __future__ import annotations

import logging
import shutil
import threading
import time
from pathlib import Path

from . import crypto
from .api.auth import Auth
from .audit.audit_log import AuditLog
from .audit.stats import DailyStats
from .capture.camera import open_source
from .db import Database
from .evidence.legal_hold import LegalHolds
from .evidence.purge import PurgeService
from .evidence.snapshots import ReviewSnapshots
from .evidence.unseal import UnsealService
from .evidence.vault import EvidenceVault, UnsealError
from .matching.alert_queue import AlertQueue
from .matching.hotlist_sync import Hotlist, HotlistSync, HotlistSyncError
from .matching.matcher import Matcher
from .pipeline import Pipeline
from .privacy.hasher import PlateHasher
from .privacy.key_manager import KeyManager
from .provision import is_provisioned, vault_public_path
from .security.fail_closed import FailClosedController
from .security.secure_boot import attest
from .security.signed_update import UpdateVerifier, verify_models
from .security.tamper_detect import TamperMonitor
from .vision.detector import build_detector
from .vision.ocr import build_plate_reader
from .vision.redaction import RedactionUnavailable, Redactor

log = logging.getLogger(__name__)


class StartupError(RuntimeError):
    pass


class System:
    def __init__(self, cfg: dict, detector=None, plate_reader=None):
        self.cfg = cfg
        data = Path(cfg["data_dir"])
        data.mkdir(parents=True, exist_ok=True)
        if not is_provisioned(cfg):
            raise StartupError("device is not provisioned; run scripts/init_device.py")

        try:
            crypto.enforce_policy(cfg)           # SC-13: no start without the validated module, if required
        except crypto.CryptoPolicyError as exc:
            raise StartupError(str(exc)) from exc

        self.audit = AuditLog(data / "audit.log", cfg.get("organization", ""), cfg["camera_id"])
        self.db = Database(data / "index.db")
        self.daily = DailyStats(self.db)
        self.fail_closed = FailClosedController(data / "TAMPER.lock", self.audit)

        # SI-7: every model file is checked against the signed manifest before anything loads it.
        self.updates = UpdateVerifier.from_config(cfg)
        if cfg["updates"]["require_signed_models"]:
            try:
                verified = verify_models(cfg, self.updates)
            except crypto.IntegrityError as exc:
                self.audit.record("system", "integrity.model_rejected", {"error": str(exc)})
                raise StartupError(f"model integrity check failed: {exc}") from exc
            self.audit.record("system", "integrity.models_verified", {"files": verified})
        try:
            redactor = Redactor.from_config(cfg["privacy"])
        except RedactionUnavailable as exc:      # never fall back to storing unblurred faces
            raise StartupError(f"{exc}. Restore the model or set privacy.redaction.faces: false.") from exc

        ok, detail = attest(cfg)
        self.audit.record("system", "boot.attestation", {"ok": ok, "detail": detail})
        if not ok:
            self.fail_closed.trip(detail, "attestation")

        self.keys = KeyManager.from_config(cfg)
        if not self.fail_closed.locked:
            self.keys.load()                 # a locked device never loads its keys

        self.hasher = PlateHasher(self.keys, cfg["privacy"])
        self.hotlist = Hotlist(self.db, self.hasher, self.audit)
        self.matcher = Matcher(self.hotlist)
        self.snapshots = ReviewSnapshots(data / "snapshots", self.keys)
        self.alerts = AlertQueue(self.db, self.audit, self.snapshots, cfg["matching"]["min_justification_chars"],
                                 self.daily)
        try:
            self.vault = EvidenceVault(data / "vault", self.db, self.audit, vault_public_path(cfg).read_bytes())
        except UnsealError as exc:
            raise StartupError(str(exc)) from exc
        self.holds = LegalHolds(self.db, self.audit)
        self.purge = PurgeService(self.db, self.vault, self.holds, self.snapshots, self.audit, cfg["retention"])
        self.unseal = UnsealService(self.db, self.vault, self.audit, cfg["evidence"]["shamir_threshold"],
                                    cfg["evidence"]["unsealed_view_minutes"])
        self.auth = Auth(self.db, self.audit, cfg["api"])
        self.tamper = TamperMonitor.from_config(self.fail_closed, cfg["security"])
        self.pipeline = Pipeline(cfg, self.db, self.audit, self.hasher, self.matcher, self.alerts, self.vault,
                                 self.tamper, detector or build_detector(cfg["vision"]),
                                 plate_reader or build_plate_reader(cfg["vision"]), redactor=redactor,
                                 daily=self.daily)
        self.hotlist_sync = HotlistSync(self.hotlist, cfg, self.updates, self.audit)

        # Everything that must be forgotten the moment tampering is suspected.
        for scrubber in (self.keys.scrub, self.vault.scrub, self.unseal.scrub, self.pipeline.scrub,
                         self.auth.end_all_sessions):
            self.fail_closed.register(scrubber)

        self.started_ts = time.time()
        self._chain, self._chain_checked = (True, None), 0.0
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self.audit.record("system", "system.start", {
            "camera_id": cfg["camera_id"], "key_backend": cfg["keys"]["backend"], "locked": self.fail_closed.locked,
            "fips_provider": crypto.fips_provider_active(), "tls": cfg["api"]["tls"]["enabled"],
            "signed_models": cfg["updates"]["require_signed_models"], "redaction": redactor.active})

    # ----------------------------------------------------------- background

    def start(self, source=None) -> None:
        """Run the pipeline and the purge timer in background threads."""
        if self.fail_closed.locked:
            log.critical("device is locked after a tamper event; pipeline not started")
            return
        source = source or open_source(self.cfg["capture"])
        self._threads = [
            threading.Thread(target=self.pipeline.run, args=(source,), name="pipeline", daemon=True),
            threading.Thread(target=self._purge_loop, name="purge", daemon=True),
        ]
        if self.hotlist_sync.enabled:
            self._threads.append(threading.Thread(target=self._hotlist_loop, name="hotlist-sync", daemon=True))
        for thread in self._threads:
            thread.start()

    def _purge_loop(self) -> None:
        interval = self.cfg["retention"]["purge_interval_minutes"] * 60
        while not self._stop.is_set():
            try:
                self.purge.run()
            except Exception:
                log.exception("purge failed")
            self._stop.wait(interval)

    def _hotlist_loop(self) -> None:
        interval = self.cfg["hotlist_sync"]["interval_minutes"] * 60
        while not self._stop.is_set():
            try:
                self.hotlist_sync.run_once()
            except HotlistSyncError as exc:
                log.error("hotlist sync failed, keeping the current list: %s", exc)
            except Exception:
                log.exception("hotlist sync crashed")
            self._stop.wait(interval)

    def shutdown(self) -> None:
        """Orderly termination: stop work, then destroy every key held in RAM."""
        self._stop.set()
        self.pipeline.stop()
        for thread in self._threads:
            thread.join(timeout=5)
        self.unseal.scrub()
        self.vault.scrub()
        self.keys.scrub()
        self.audit.record("system", "system.shutdown", {"keys_scrubbed": True})
        self.db.close()

    # --------------------------------------------------------------- status

    def status(self) -> dict:
        vault = self.vault.stats()
        disk = shutil.disk_usage(self.cfg["data_dir"])
        if time.time() - self._chain_checked > 60:          # re-reading the whole log is not free
            self._chain = self.audit.verify()
            self._chain_checked = time.time()
        chain_ok, bad_seq = self._chain
        return {
            "camera_id": self.cfg["camera_id"],
            "uptime_seconds": int(time.time() - self.started_ts),
            "locked": self.fail_closed.locked,
            "lock_info": self.fail_closed.lock_info(),
            "pipeline": dict(self.pipeline.stats),
            "video_online": self.pipeline.live_jpeg() is not None,
            "pending_reviews": self.alerts.pending_count(),
            "hotlist_entries": self.hotlist.count(),
            "sightings_indexed": self.db.one("SELECT COUNT(*) AS n FROM sightings")["n"],
            "vault": vault,
            "storage_used_fraction": round(disk.used / disk.total, 3),
            "retention": self.purge.status(),
            "audit_chain_ok": chain_ok,
            "audit_first_bad_seq": bad_seq,
            "key_backend": self.cfg["keys"]["backend"],
            "organization": self.cfg.get("organization", ""),
            "redaction": {"faces": self.pipeline.redactor.face_detector is not None,
                          "people": self.pipeline.redactor.people},
            "hotlist_sync": {"enabled": self.hotlist_sync.enabled, "last_ok": self.hotlist_sync.last_ok},
        }
