"""Vehicle detection.

``YoloDetector``      YOLOv8 through the ``ultralytics`` package, with its built-in
                      ByteTrack tracker supplying stable track ids.
``SimulatedDetector`` Reads the simulator's ground truth, so everything
                      downstream can be developed and tested without a model.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..capture.camera import FramePacket

VEHICLE_CLASSES = {"car", "truck", "bus", "motorcycle"}


@dataclass
class Detection:
    bbox: tuple[int, int, int, int]            # x1, y1, x2, y2 in pixels
    label: str                                  # car | truck | bus | motorcycle
    confidence: float
    track_id: int | None = None
    truth: dict | None = field(default=None, repr=False)   # simulator only

    @property
    def center(self) -> tuple[float, float]:
        x1, y1, x2, y2 = self.bbox
        return (x1 + x2) / 2, (y1 + y2) / 2

    @property
    def area(self) -> int:
        x1, y1, x2, y2 = self.bbox
        return max(0, x2 - x1) * max(0, y2 - y1)


class YoloDetector:
    def __init__(self, weights: str, confidence: float = 0.35):
        from ultralytics import YOLO           # heavy import, only when actually used
        self.model = YOLO(weights)
        self.confidence = confidence
        self.people: list[tuple[int, int, int, int]] = []   # person boxes in the last frame, for redaction

    def detect(self, packet: FramePacket) -> list[Detection]:
        result = self.model.track(packet.image, persist=True, tracker="bytetrack.yaml", conf=self.confidence,
                                  verbose=False)[0]
        detections, self.people = [], []
        for box in result.boxes:
            label = result.names[int(box.cls)]
            x1, y1, x2, y2 = (int(v) for v in box.xyxy[0].tolist())
            if label == "person":
                self.people.append((x1, y1, x2, y2))
            if label not in VEHICLE_CLASSES:
                continue
            track_id = int(box.id) if box.id is not None else None
            detections.append(Detection((x1, y1, x2, y2), label, float(box.conf), track_id))
        return detections


class SimulatedDetector:
    def detect(self, packet: FramePacket) -> list[Detection]:
        return [
            Detection(tuple(t["bbox"]), "truck" if t["body_type"] == "truck" else "car", 0.95, None, t)
            for t in (packet.truth or [])
        ]


def build_detector(vision_cfg: dict):
    if vision_cfg["detector"] == "yolo":
        return YoloDetector(vision_cfg["yolo_weights"], vision_cfg["yolo_confidence"])
    return SimulatedDetector()
