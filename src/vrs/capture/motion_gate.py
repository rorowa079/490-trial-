"""Motion gate: the expensive vision stage only runs while something is moving."""
from __future__ import annotations

import cv2
import numpy as np


class MotionGate:
    def __init__(self, min_area: int = 1500, cooldown_frames: int = 30, scale: float = 0.25):
        self.min_area = min_area * scale * scale      # area threshold in downscaled pixels
        self.cooldown, self.scale = cooldown_frames, scale
        self._previous = None
        self._quiet_frames = cooldown_frames

    def update(self, image: np.ndarray) -> bool:
        """Feed one frame; returns True while motion is present or recently was."""
        small = cv2.resize(image, None, fx=self.scale, fy=self.scale, interpolation=cv2.INTER_AREA)
        gray = cv2.GaussianBlur(cv2.cvtColor(small, cv2.COLOR_BGR2GRAY), (5, 5), 0)
        moving = False
        if self._previous is not None:
            diff = cv2.absdiff(gray, self._previous)
            moving = int(np.count_nonzero(diff > 25)) >= self.min_area
        self._previous = gray
        self._quiet_frames = 0 if moving else self._quiet_frames + 1
        return self._quiet_frames < self.cooldown
