"""The processing pipeline: one frame in, at most hashes and sealed bytes out.

Per frame
    tamper check -> ring buffer -> motion gate -> detect -> track ->
    attributes + speed -> OCR -> HASH IN RAM -> scrub plaintext ->
    blur faces and people -> ring buffer / live view

When a vehicle leaves the scene
    pick its plate hash by confidence-weighted vote -> compare with the hashed
    hotlist -> store hash + attributes -> seal the clip ->
    on a match: queue an alert for a human. Nothing else happens automatically.

A plaintext plate exists only inside ``_observe`` for the duration of one call.
Votes are kept as hashes, so nothing readable waits in memory between frames.
Reading and attribute extraction use the raw frame; every image that is kept
(buffer, sealed clip, review snapshot, live view) has been through the redactor.
"""
from __future__ import annotations

import logging
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import cv2

from .audit.audit_log import AuditLog
from .audit.stats import DailyStats
from .capture.camera import FramePacket
from .capture.frame_buffer import FrameBuffer
from .capture.motion_gate import MotionGate
from .db import Database
from .evidence.vault import EvidenceVault
from .matching.alert_queue import AlertQueue
from .matching.matcher import Matcher
from .privacy.hasher import PlateHasher
from .privacy.key_manager import KeysUnavailable
from .privacy.scrubber import scrub
from .security.tamper_detect import TamperMonitor
from .vision.attributes import AttributeExtractor
from .vision.detector import Detection
from .vision.redaction import Redactor
from .vision.speed_estimator import KalmanTrack
from .vision.tracker import IouTracker

log = logging.getLogger(__name__)
MIN_TRACK_FRAMES = 3


@dataclass
class TrackState:
    track_id: int
    first_ts: float
    last_ts: float
    last_index: int
    kalman: KalmanTrack
    frames: int = 1
    votes: dict = field(default_factory=lambda: defaultdict(float))    # plate hash -> summed confidence
    best_conf: dict = field(default_factory=dict)                      # plate hash -> best single read
    attrs: dict = field(default_factory=lambda: defaultdict(Counter))  # attribute -> value counts
    best_area: int = 0
    best_crop: bytes | None = None                                     # JPEG of the clearest view


class Pipeline:
    def __init__(self, cfg: dict, db: Database, audit: AuditLog, hasher: PlateHasher, matcher: Matcher,
                 alerts: AlertQueue, vault: EvidenceVault, tamper: TamperMonitor, detector, plate_reader,
                 attributes: AttributeExtractor | None = None, redactor: Redactor | None = None,
                 daily: DailyStats | None = None):
        self.cfg, self.db, self.audit = cfg, db, audit
        self.redactor = redactor or Redactor.from_config(cfg["privacy"])
        self.daily = daily or DailyStats(db)
        self.hasher, self.matcher, self.alerts, self.vault, self.tamper = hasher, matcher, alerts, vault, tamper
        self.detector, self.plate_reader = detector, plate_reader
        self.attributes = attributes or AttributeExtractor()
        vision, capture, evidence = cfg["vision"], cfg["capture"], cfg["evidence"]
        self.tracker = IouTracker(max_missed=vision["track_lost_frames"])
        self.motion = MotionGate(capture["motion_min_area"], capture["motion_cooldown_frames"])
        self.buffer = FrameBuffer(capture["buffer_seconds"], evidence["clip_fps"], evidence["jpeg_quality"])
        self.min_ocr = cfg["matching"]["min_ocr_confidence"]
        self.tracks: dict[int, TrackState] = {}
        self.stats = Counter()
        self._live_lock = threading.Lock()
        self._live_jpeg: bytes | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ per frame

    def process(self, packet: FramePacket) -> None:
        if self.tamper.check(packet.image):
            self.stats["frames_refused_locked"] += 1
            return
        self.stats["frames"] += 1
        people: list = []
        if self.motion.update(packet.image) or self.tracks:
            try:
                detections = self.tracker.update(self.detector.detect(packet))
                people = list(getattr(self.detector, "people", ()))
                for det in detections:
                    self._observe(packet, det)
            except KeysUnavailable:
                log.error("keys unavailable; frame dropped without storing anything")
                return
        self._keep_redacted(packet, people)
        self._close_lost_tracks(packet.index)

    def _keep_redacted(self, packet: FramePacket, people: list) -> None:
        """Blur faces and people, then hand the frame to the buffer and the live view. Raw frames go no further.

        Only frames the buffer samples (``evidence.clip_fps``) are processed, so the face detector runs a few
        times a second rather than on every frame. The live view shows the same blurred frames.
        """
        if not self.buffer.wants(packet.ts):
            return
        image, regions = self.redactor.apply(packet.image, people)
        self.stats["regions_redacted"] += regions
        self.buffer.add(packet.ts, image)
        self._update_live(image)

    def _observe(self, packet: FramePacket, det: Detection) -> None:
        cx, cy = det.center
        track = self.tracks.get(det.track_id)
        if track is None:
            track = self.tracks[det.track_id] = TrackState(det.track_id, packet.ts, packet.ts, packet.index,
                                                           KalmanTrack(packet.ts, cx, cy))
        else:
            track.kalman.update(packet.ts, cx, cy)
            track.last_ts, track.last_index = packet.ts, packet.index
            track.frames += 1

        for name, value in self.attributes.extract(packet.image, det).items():
            if value:
                track.attrs[name][value] += 1

        if det.area > track.best_area:
            x1, y1, x2, y2 = det.bbox
            crop, _ = self.redactor.apply(packet.image[max(y1, 0):y2, max(x1, 0):x2])
            ok, jpeg = cv2.imencode(".jpg", crop)
            if ok:
                track.best_area, track.best_crop = det.area, jpeg.tobytes()

        read = self.plate_reader.read(packet.image, det)
        if read is None:
            return
        plate, confidence = read
        if confidence < self.min_ocr:
            scrub(plate)                                 # too uncertain to keep even as a hash
            return
        plate_hash = self.hasher.hash_plate(plate)       # zeroes `plate` before returning
        if plate_hash:
            track.votes[plate_hash] += confidence
            track.best_conf[plate_hash] = max(confidence, track.best_conf.get(plate_hash, 0.0))

    # ------------------------------------------------- when a vehicle leaves

    def _close_lost_tracks(self, index: int) -> None:
        lost_after = self.cfg["vision"]["track_lost_frames"]
        for track_id in [t for t, s in self.tracks.items() if index - s.last_index > lost_after]:
            self._finalize(self.tracks.pop(track_id))

    def _finalize(self, track: TrackState) -> None:
        if track.frames < MIN_TRACK_FRAMES:
            return
        plate_hash = max(track.votes, key=track.votes.get) if track.votes else None
        ocr_confidence = track.best_conf.get(plate_hash) if plate_hash else None
        observed = {name: counts.most_common(1)[0][0] for name, counts in track.attrs.items()}
        vision = self.cfg["vision"]

        # Hash-to-hash comparison. The hotlist was hashed with the same key.
        match = self.matcher.check(plate_hash, observed, ocr_confidence or 0.0)

        clip_id = None
        evidence = self.cfg["evidence"]
        if match or evidence["seal_all_events"]:
            max_frames = int(evidence["clip_fps"] * evidence["clip_max_seconds"])
            frames = self.buffer.between(track.first_ts - 2.0, track.last_ts + 3.0, max_frames)
            if frames:
                clip_id = self.vault.seal(frames, track.first_ts, track.last_ts)

        cur = self.db.execute(
            "INSERT INTO sightings (ts, camera_id, track_id, plate_hash, ocr_confidence, color, body_type, make, model,"
            " damage, direction, speed_kph, clip_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (track.first_ts, self.cfg["camera_id"], track.track_id, plate_hash, ocr_confidence,
             observed.get("color"), observed.get("body_type"), observed.get("make"), observed.get("model"),
             observed.get("damage"), track.kalman.direction(vision["image_up_bearing"]),
             track.kalman.speed_kph(vision["meters_per_pixel"]), clip_id),
        )
        self.stats["sightings"] += 1
        self.daily.bump("reads", track.first_ts)
        if plate_hash:
            self.daily.bump("plate_reads", track.first_ts)
        if match:
            self.alerts.enqueue(cur.lastrowid, match, track.best_crop)
            self.stats["alerts"] += 1
            self.daily.bump("hits", track.first_ts)

    def flush(self) -> None:
        """Close every open track (end of video or shutdown)."""
        for track_id in list(self.tracks):
            self._finalize(self.tracks.pop(track_id))

    # ------------------------------------------------------------- running

    def run(self, source) -> None:
        try:
            for packet in source.frames():
                if self._stop.is_set():
                    break
                self.process(packet)
        finally:
            if not self.tamper.controller.locked:
                self.flush()
            source.close()

    def stop(self) -> None:
        self._stop.set()

    def scrub(self) -> None:
        """Forget everything in flight (tamper)."""
        self.tracks.clear()
        self.buffer.clear()
        with self._live_lock:
            self._live_jpeg = None

    # ------------------------------------------------------------ live view

    def _update_live(self, image) -> None:
        small = cv2.resize(image, (640, int(image.shape[0] * 640 / image.shape[1])))
        ok, jpeg = cv2.imencode(".jpg", small, [cv2.IMWRITE_JPEG_QUALITY, 60])
        if ok:
            with self._live_lock:
                self._live_jpeg = jpeg.tobytes()

    def live_jpeg(self) -> bytes | None:
        with self._live_lock:
            return self._live_jpeg
