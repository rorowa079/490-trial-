"""Blur people before anything is kept (PII minimisation; NIST SP 800-53 SC-28 covers what is then stored).

The system is about vehicles. Faces of drivers, passengers and passers-by are
pixelated in every image that outlives the frame it came from: the frames that
go into sealed clips, the review snapshot, and the live view. Plate reading and
attribute extraction run on the untouched frame, which exists only in RAM.

What gets blurred
-----------------
* **Faces**, found by YuNet (a small open-source detector from the OpenCV model
  zoo, shipped in ``vision/models``).
* **People**, when the vehicle detector reports them (YOLO's ``person`` class).
  The simulated detector never does.

Limits, stated plainly: a face detector misses faces, especially small ones
behind windshield glare, at night, or in profile. This reduces what is stored;
it does not guarantee no face is ever stored. Bumper stickers and other
writing on vehicles are not detected or blurred.
"""
from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np

Box = tuple[int, int, int, int]            # x1, y1, x2, y2


class RedactionUnavailable(RuntimeError):
    pass


class YuNetFaces:
    def __init__(self, model_path: str | Path, score: float = 0.6):
        if not Path(model_path).exists():
            raise RedactionUnavailable(f"face detector model not found: {model_path}")
        self._detector = cv2.FaceDetectorYN.create(str(model_path), "", (320, 320), score, 0.3, 5000)
        self._size: tuple[int, int] | None = None

    def detect(self, image: np.ndarray) -> list[Box]:
        height, width = image.shape[:2]
        if height < 16 or width < 16:
            return []
        if self._size != (width, height):
            self._detector.setInputSize((width, height))
            self._size = (width, height)
        faces = self._detector.detect(image)[1]
        if faces is None:
            return []
        return [(int(x), int(y), int(x + w), int(y + h)) for x, y, w, h in faces[:, :4]]


def pixelate(image: np.ndarray, box: Box, blocks: int = 6) -> None:
    """Replace a region, in place, with a coarse mosaic. Unlike a soft blur this destroys the detail."""
    height, width = image.shape[:2]
    x1, y1, x2, y2 = max(0, box[0]), max(0, box[1]), min(width, box[2]), min(height, box[3])
    if x2 - x1 < 2 or y2 - y1 < 2:
        return
    region = image[y1:y2, x1:x2]
    small = cv2.resize(region, (min(blocks, x2 - x1), min(blocks, y2 - y1)), interpolation=cv2.INTER_AREA)
    image[y1:y2, x1:x2] = cv2.resize(small, (x2 - x1, y2 - y1), interpolation=cv2.INTER_NEAREST)


def _grow(box: Box, fraction: float) -> Box:
    x1, y1, x2, y2 = box
    dx, dy = int((x2 - x1) * fraction), int((y2 - y1) * fraction)
    return x1 - dx, y1 - dy, x2 + dx, y2 + dy


class Redactor:
    def __init__(self, face_detector=None, people: bool = True, margin: float = 0.25):
        self.face_detector, self.people, self.margin = face_detector, people, margin

    @classmethod
    def from_config(cls, privacy_cfg: dict) -> "Redactor":
        cfg = privacy_cfg["redaction"]
        faces = YuNetFaces(cfg["face_model"], cfg.get("face_score", 0.6)) if cfg["faces"] else None
        return cls(faces, cfg["people"])

    @property
    def active(self) -> bool:
        return self.face_detector is not None or self.people

    def apply(self, image: np.ndarray, people: list[Box] | tuple = ()) -> tuple[np.ndarray, int]:
        """Return (a redacted copy, number of regions blurred). The input image is not changed."""
        boxes: list[Box] = []
        if self.face_detector is not None:
            boxes += [_grow(b, self.margin) for b in self.face_detector.detect(image)]
        if self.people:
            boxes += list(people)
        if not boxes:
            return image, 0
        out = image.copy()
        for box in boxes:
            pixelate(out, box)
        return out, len(boxes)
