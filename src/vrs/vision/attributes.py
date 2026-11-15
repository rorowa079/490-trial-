"""Vehicle attributes that do not identify a person: color, body type, make/model.

Color is computed directly from pixels and works today. Body type comes from the
detector's class. Make/model and damage need a trained classifier: plug one in
through ``AttributeExtractor(classifier=...)``; until then they are left empty
rather than guessed.
"""
from __future__ import annotations

from typing import Callable

import cv2
import numpy as np

from .detector import Detection

_BODY = {"car": "car", "truck": "truck", "bus": "bus", "motorcycle": "motorcycle"}


def dominant_color(image: np.ndarray, bbox: tuple[int, int, int, int]) -> str | None:
    """Name the body color from the middle band of the vehicle (below windows, above plate)."""
    x1, y1, x2, y2 = bbox
    w, h = x2 - x1, y2 - y1
    if w < 20 or h < 20:
        return None
    crop = image[max(y1 + int(h * 0.45), 0): y1 + int(h * 0.65), max(x1 + int(w * 0.15), 0): x1 + int(w * 0.85)]
    if crop.size == 0:
        return None
    hsv = cv2.cvtColor(crop, cv2.COLOR_BGR2HSV).reshape(-1, 3)
    hue, sat, val = (float(np.median(hsv[:, i])) for i in range(3))
    if val < 55:
        return "black"
    if sat < 40:
        return "white" if val > 200 else "silver"
    for limit, name in ((10, "red"), (25, "orange"), (35, "yellow"), (85, "green"), (130, "blue"), (160, "purple")):
        if hue < limit:
            return name
    return "red"                     # hue wraps around: 160-180 is red again


class AttributeExtractor:
    def __init__(self, classifier: Callable[[np.ndarray], dict] | None = None):
        """``classifier(crop) -> {"make":..., "model":..., "damage":...}`` when a model is available."""
        self.classifier = classifier

    def extract(self, image: np.ndarray, det: Detection) -> dict:
        attrs = {"color": dominant_color(image, det.bbox), "body_type": _BODY.get(det.label),
                 "make": None, "model": None, "damage": None}
        if det.truth:                                    # simulator supplies make/model
            attrs.update(make=det.truth.get("make"), model=det.truth.get("model"))
        elif self.classifier is not None:
            x1, y1, x2, y2 = det.bbox
            attrs.update({k: v for k, v in self.classifier(image[y1:y2, x1:x2]).items() if k in attrs})
        return attrs
