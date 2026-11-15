"""Speed and heading from a constant-velocity Kalman filter, one per track.

State is [x, y, vx, vy] in pixels and pixels/second. Pixel speed becomes road
speed through ``meters_per_pixel``, which must be measured on site (see
config/hardware.yaml). These are estimates for search and for the reviewer's
context, never evidence of speeding.
"""
from __future__ import annotations

import math

import numpy as np

_COMPASS = ("N", "NE", "E", "SE", "S", "SW", "W", "NW")


class KalmanTrack:
    def __init__(self, ts: float, x: float, y: float, process_noise: float = 50.0, measurement_noise: float = 4.0):
        self.state = np.array([x, y, 0.0, 0.0])
        self.cov = np.diag([measurement_noise ** 2, measurement_noise ** 2, 1e4, 1e4])
        self.q, self.r = process_noise, measurement_noise
        self.ts = ts
        self.updates = 1

    def update(self, ts: float, x: float, y: float) -> None:
        dt = max(ts - self.ts, 1e-3)
        self.ts = ts
        f = np.array([[1, 0, dt, 0], [0, 1, 0, dt], [0, 0, 1, 0], [0, 0, 0, 1]], dtype=float)
        g = np.array([[dt ** 2 / 2, 0], [0, dt ** 2 / 2], [dt, 0], [0, dt]])
        self.state = f @ self.state
        self.cov = f @ self.cov @ f.T + g @ g.T * self.q ** 2
        h = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=float)
        innovation = np.array([x, y]) - h @ self.state
        s = h @ self.cov @ h.T + np.eye(2) * self.r ** 2
        gain = self.cov @ h.T @ np.linalg.inv(s)
        self.state = self.state + gain @ innovation
        self.cov = (np.eye(4) - gain @ h) @ self.cov
        self.updates += 1

    @property
    def velocity(self) -> tuple[float, float]:
        return float(self.state[2]), float(self.state[3])

    def speed_kph(self, meters_per_pixel: float) -> float | None:
        if self.updates < 4:
            return None
        return round(math.hypot(*self.velocity) * meters_per_pixel * 3.6, 1)

    def direction(self, image_up_bearing: float = 0.0) -> str | None:
        """Compass direction of travel. ``image_up_bearing`` is the bearing of image-up."""
        vx, vy = self.velocity
        if self.updates < 4 or math.hypot(vx, vy) < 5:
            return None
        bearing = (math.degrees(math.atan2(vx, -vy)) + image_up_bearing) % 360     # image y points down
        return _COMPASS[int((bearing + 22.5) // 45) % 8]

    def predict(self, seconds_ahead: float) -> tuple[float, float]:
        """Where the vehicle would be if it kept going. An estimate, to be shown as one."""
        return float(self.state[0] + self.state[2] * seconds_ahead), float(self.state[1] + self.state[3] * seconds_ahead)
