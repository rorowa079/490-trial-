"""Track ids for detectors that do not provide them.

The YOLO detector already carries ByteTrack ids. This small IoU tracker fills
the gap for everything else (the simulator, or a detector exported to TFLite
for the Coral accelerator, which has no tracker attached).
"""
from __future__ import annotations

from .detector import Detection


def iou(a: tuple, b: tuple) -> float:
    ix1, iy1, ix2, iy2 = max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])
    inter = max(0, ix2 - ix1) * max(0, iy2 - iy1)
    union = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / union if union > 0 else 0.0


class IouTracker:
    def __init__(self, min_iou: float = 0.25, max_missed: int = 20):
        self.min_iou, self.max_missed = min_iou, max_missed
        self._tracks: dict[int, tuple[tuple, int]] = {}     # id -> (last bbox, frames missed)
        self._next_id = 1

    def update(self, detections: list[Detection]) -> list[Detection]:
        """Assign a track id to every detection that lacks one (greedy best-IoU match)."""
        if detections and all(d.track_id is not None for d in detections):
            return detections
        pairs = sorted(
            ((iou(bbox, det.bbox), track_id, i) for track_id, (bbox, _) in self._tracks.items()
             for i, det in enumerate(detections)), reverse=True)
        used_tracks, used_dets = set(), set()
        for score, track_id, i in pairs:
            if score < self.min_iou:
                break
            if track_id in used_tracks or i in used_dets:
                continue
            detections[i].track_id = track_id
            used_tracks.add(track_id)
            used_dets.add(i)
        for i, det in enumerate(detections):
            if i not in used_dets:
                det.track_id = self._next_id
                self._next_id += 1
        seen = {d.track_id for d in detections}
        for track_id in list(self._tracks):
            if track_id not in seen:
                bbox, missed = self._tracks[track_id]
                if missed + 1 > self.max_missed:
                    del self._tracks[track_id]
                else:
                    self._tracks[track_id] = (bbox, missed + 1)
        for det in detections:
            self._tracks[det.track_id] = (det.bbox, 0)
        return detections
