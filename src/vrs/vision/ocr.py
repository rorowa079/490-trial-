"""License plate reading.

Every reader returns ``(plate, confidence)`` with the plate in a ``bytearray``
so the hasher can zero it. The pipeline hashes it in the same call and never
keeps it.

``PaddlePlateReader`` has not been run against real footage yet: it needs
``paddleocr`` installed and, ideally, a plate-localizer model. Treat its crop
heuristics and thresholds as a starting point to tune.
"""
from __future__ import annotations

import re

import numpy as np

from ..privacy.scrubber import to_buffer
from .detector import Detection

_PLATE_SHAPE = re.compile(r"^[A-Z0-9]{2,8}$")


class SimulatedPlateReader:
    """Returns the simulator's ground-truth plate with a confidence that depends on visibility."""

    def read(self, image: np.ndarray, det: Detection) -> tuple[bytearray, float] | None:
        if not det.truth:
            return None
        confidence = 0.93 if det.truth.get("fully_visible") else 0.45
        return to_buffer(det.truth["plate"]), confidence


class PaddlePlateReader:
    def __init__(self, plate_weights: str = ""):
        from paddleocr import PaddleOCR            # heavy import, only when used
        self.ocr = PaddleOCR(use_angle_cls=False, lang="en", show_log=False)
        self.localizer = None
        if plate_weights:
            from ultralytics import YOLO
            self.localizer = YOLO(plate_weights)

    def _plate_crop(self, image: np.ndarray, det: Detection) -> np.ndarray:
        x1, y1, x2, y2 = det.bbox
        vehicle = image[y1:y2, x1:x2]
        if self.localizer is not None:
            boxes = self.localizer(vehicle, verbose=False)[0].boxes
            if len(boxes):
                px1, py1, px2, py2 = (int(v) for v in boxes[int(boxes.conf.argmax())].xyxy[0].tolist())
                return vehicle[py1:py2, px1:px2]
        return vehicle[int(vehicle.shape[0] * 0.5):]       # no localizer: plates sit in the lower half

    def read(self, image: np.ndarray, det: Detection) -> tuple[bytearray, float] | None:
        crop = self._plate_crop(image, det)
        if crop.size == 0:
            return None
        best: tuple[str, float] | None = None
        for line in (self.ocr.ocr(crop, cls=False) or [[]])[0] or []:
            text, confidence = line[1]
            text = re.sub(r"[^A-Za-z0-9]", "", text).upper()
            if _PLATE_SHAPE.match(text) and (best is None or confidence > best[1]):
                best = (text, float(confidence))
        if best is None:
            return None
        # `best[0]` is an immutable str we cannot wipe; see privacy/scrubber.py.
        return to_buffer(best[0]), best[1]


def build_plate_reader(vision_cfg: dict):
    if vision_cfg["ocr"] == "paddle":
        return PaddlePlateReader(vision_cfg.get("plate_weights", ""))
    return SimulatedPlateReader()
