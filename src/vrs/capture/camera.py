"""Frame sources: a real camera, a video file, or a simulated road for development."""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Iterator

import cv2
import numpy as np


@dataclass
class FramePacket:
    index: int
    ts: float
    image: np.ndarray
    # Ground truth from the simulator only (None for real video). The simulated
    # detector and plate reader use it; the rest of the pipeline never sees it.
    truth: list[dict] | None = field(default=None, repr=False)


class CameraSource:
    """USB/CSI camera index or an RTSP URL, read through OpenCV."""

    def __init__(self, device: int | str = 0, width: int = 1280, height: int = 720, fps: int = 15):
        self.cap = cv2.VideoCapture(device)
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        self.cap.set(cv2.CAP_PROP_FPS, fps)
        if not self.cap.isOpened():
            raise RuntimeError(f"cannot open camera {device!r}")

    def frames(self) -> Iterator[FramePacket]:
        index = 0
        while True:
            ok, image = self.cap.read()
            if not ok:
                break
            yield FramePacket(index, time.time(), image)
            index += 1

    def close(self) -> None:
        self.cap.release()


class FileSource(CameraSource):
    """A recorded video, timestamped as if it were playing live from ``start_ts``."""

    def __init__(self, path: str, start_ts: float | None = None):
        self.cap = cv2.VideoCapture(path)
        if not self.cap.isOpened():
            raise RuntimeError(f"cannot open video {path!r}")
        self.fps = self.cap.get(cv2.CAP_PROP_FPS) or 15
        self.start_ts = start_ts or time.time()

    def frames(self) -> Iterator[FramePacket]:
        index = 0
        while True:
            ok, image = self.cap.read()
            if not ok:
                break
            yield FramePacket(index, self.start_ts + index / self.fps, image)
            index += 1


# ----------------------------------------------------------------- simulator

_COLORS = {"white": (235, 235, 235), "black": (25, 25, 25), "silver": (150, 150, 150), "red": (40, 40, 200),
           "blue": (190, 80, 30), "green": (60, 140, 40)}
_MODELS = [("toyota", "camry", "car"), ("honda", "civic", "car"), ("ford", "f-150", "truck"),
           ("toyota", "rav4", "car"), ("tesla", "model 3", "car"), ("chevrolet", "silverado", "truck")]


def random_plate(rng: random.Random) -> str:
    """California-style 1ABC234. Purely synthetic."""
    letters = "ABCDEFGHJKLMNPRSTUVWXYZ"
    return f"{rng.randint(1, 9)}{''.join(rng.choice(letters) for _ in range(3))}{rng.randint(100, 999)}"


class SimulatedSource:
    """Draws vehicles driving across a road so the whole pipeline runs with no hardware.

    ``script`` is a list of dicts: plate, color, make, model, body_type,
    start_frame, speed (pixels per frame, negative = right to left). When it is
    omitted, random traffic is generated forever (or until ``max_frames``).
    """

    def __init__(self, width: int = 1280, height: int = 720, fps: int = 15, script: list[dict] | None = None,
                 max_frames: int | None = None, realtime: bool = False, start_ts: float | None = None, seed: int = 7,
                 plate_pool: list[dict] | None = None, pool_rate: float = 0.3):
        self.w, self.h, self.fps = width, height, fps
        self.script = script
        # Demo aid: vehicles drawn from this pool (same keys as a script entry,
        # minus start_frame/speed) appear in random traffic at ``pool_rate``.
        self.plate_pool, self.pool_rate = plate_pool or [], pool_rate
        self.max_frames, self.realtime = max_frames, realtime
        self.start_ts = start_ts or time.time()
        self.rng = random.Random(seed)

    def _random_vehicle(self, frame: int, uid: int) -> dict:
        make, model, body = self.rng.choice(_MODELS)
        vehicle = {"plate": random_plate(self.rng), "color": self.rng.choice(list(_COLORS)), "make": make,
                   "model": model, "body_type": body}
        if self.plate_pool and self.rng.random() < self.pool_rate:
            vehicle.update(self.rng.choice(self.plate_pool))
        return {**vehicle, "uid": uid, "start_frame": frame,
                "speed": self.rng.choice([-1, 1]) * self.rng.randint(14, 26)}

    def frames(self) -> Iterator[FramePacket]:
        pending = [dict(v, uid=i + 1) for i, v in enumerate(self.script or [])]
        active: list[dict] = []
        uid, next_spawn, index = len(pending), 20, 0
        while self.max_frames is None or index < self.max_frames:
            if self.script is None and index >= next_spawn:
                uid += 1
                pending.append(self._random_vehicle(index, uid))
                next_spawn = index + self.rng.randint(60, 160)
            for vehicle in [v for v in pending if v["start_frame"] <= index]:
                pending.remove(vehicle)
                vw = 300 if vehicle["body_type"] == "truck" else 240
                vehicle.update(w=vw, h=130, x=float(-vw if vehicle["speed"] > 0 else self.w),
                               y=self.h * (0.52 if vehicle["speed"] > 0 else 0.30))
                active.append(vehicle)

            image = np.full((self.h, self.w, 3), 95, np.uint8)                   # road surface
            image[: int(self.h * 0.2)] = (170, 150, 120)                         # sky/background
            cv2.line(image, (0, int(self.h * 0.5)), (self.w, int(self.h * 0.5)), (220, 220, 220), 3)
            image += self.rng.randint(0, 4)                                      # a little sensor noise

            truth = []
            for vehicle in list(active):
                vehicle["x"] += vehicle["speed"]
                x1, y1 = int(vehicle["x"]), int(vehicle["y"])
                x2, y2 = x1 + vehicle["w"], y1 + vehicle["h"]
                if x2 < 0 or x1 > self.w:
                    active.remove(vehicle)
                    continue
                cv2.rectangle(image, (x1, y1), (x2, y2), _COLORS[vehicle["color"]], -1)
                cv2.rectangle(image, (x1 + 30, y1 + 12), (x2 - 30, y1 + 50), (60, 50, 40), -1)      # windows
                px = x1 + vehicle["w"] // 2 - 55
                cv2.rectangle(image, (px, y2 - 38), (px + 110, y2 - 8), (255, 255, 255), -1)        # plate
                cv2.putText(image, vehicle["plate"], (px + 4, y2 - 15), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 0, 0), 2)
                bx1, bx2 = max(x1, 0), min(x2, self.w)
                if bx2 - bx1 > vehicle["w"] * 0.5:                               # mostly in view
                    truth.append({**{k: vehicle[k] for k in ("uid", "plate", "color", "make", "model", "body_type")},
                                  "bbox": (bx1, y1, bx2, y2), "fully_visible": x1 >= 0 and x2 <= self.w})

            yield FramePacket(index, self.start_ts + index / self.fps, image, truth)
            index += 1
            if self.realtime:
                time.sleep(1 / self.fps)

    def close(self) -> None:
        pass


def open_source(capture_cfg: dict):
    kind = capture_cfg["source"]
    if kind == "camera":
        return CameraSource(capture_cfg["device"], capture_cfg["width"], capture_cfg["height"], capture_cfg["fps"])
    if kind == "file":
        return FileSource(capture_cfg["file"])
    return SimulatedSource(capture_cfg["width"], capture_cfg["height"], capture_cfg["fps"], realtime=True)
