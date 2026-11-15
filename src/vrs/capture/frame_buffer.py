"""Ring buffer of recent frames, held in RAM only.

Frames are JPEG-encoded and sampled down to ``clip_fps`` on the way in, so a
15-second buffer costs a few megabytes. When a vehicle track closes, the frames
that cover it are handed to the evidence vault. Anything not sealed simply
falls off the end of the buffer and is gone.
"""
from __future__ import annotations

from collections import deque

import cv2
import numpy as np


class FrameBuffer:
    def __init__(self, seconds: float = 15, clip_fps: float = 5, jpeg_quality: int = 80):
        self.interval = 1.0 / clip_fps
        self.quality = jpeg_quality
        self._frames: deque[tuple[float, bytes]] = deque(maxlen=max(1, int(seconds * clip_fps)))
        self._last_ts = float("-inf")

    def wants(self, ts: float) -> bool:
        """True if a frame at ``ts`` would be kept (lets the caller skip redaction for frames that would not)."""
        return ts - self._last_ts >= self.interval - 1e-6

    def add(self, ts: float, image: np.ndarray) -> None:
        if not self.wants(ts):
            return
        ok, jpeg = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, self.quality])
        if ok:
            self._frames.append((ts, jpeg.tobytes()))
            self._last_ts = ts

    def between(self, ts_start: float, ts_end: float, max_frames: int | None = None) -> list[bytes]:
        frames = [jpeg for ts, jpeg in self._frames if ts_start <= ts <= ts_end]
        return frames[:max_frames] if max_frames else frames

    def clear(self) -> None:
        self._frames.clear()

    def __len__(self) -> int:
        return len(self._frames)
