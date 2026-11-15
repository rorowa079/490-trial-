"""Tamper sensors.

* LensObstructionSensor - works from the video itself; no extra hardware.
* GpioIntrusionSensor   - case-open switch on a GPIO pin (needs gpiozero, Pi only).
* MotionSensor          - accelerometer hook; supply a ``read_g`` function from
                          your sensor's driver (e.g. an MPU-6050 over I2C).

``TamperMonitor.check()`` is called once per frame and trips the fail-closed
controller on the first sensor that fires.
"""
from __future__ import annotations

import logging
from typing import Callable

import cv2
import numpy as np

from .fail_closed import FailClosedController

log = logging.getLogger(__name__)


class LensObstructionSensor:
    """Fires when the image goes dark or featureless *abruptly* and stays that way.

    Nightfall also makes frames dark, but gradually. So a bad streak only counts
    if the scene was clearly brighter just before it began. Tune the thresholds
    on site; a camera with IR illumination needs lower ones.
    """

    def __init__(self, dark_threshold: float = 12, blur_threshold: float = 4.0, bad_frames: int = 45):
        self.dark, self.blur, self.needed = dark_threshold, blur_threshold, bad_frames
        self._baseline = None          # slow average of brightness
        self._streak = 0
        self._baseline_at_start = 0.0

    def check(self, image: np.ndarray) -> str | None:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image
        small = cv2.resize(gray, (160, 90), interpolation=cv2.INTER_AREA)
        brightness = float(small.mean())
        sharpness = float(cv2.Laplacian(small, cv2.CV_64F).var())
        bad = brightness < self.dark or sharpness < self.blur
        if bad:
            if self._streak == 0:
                self._baseline_at_start = self._baseline if self._baseline is not None else brightness
            self._streak += 1
            if self._streak >= self.needed and self._baseline_at_start >= self.dark * 3:
                return f"lens obstructed (brightness {brightness:.0f}, sharpness {sharpness:.1f})"
        else:
            self._streak = 0
            self._baseline = brightness if self._baseline is None else 0.98 * self._baseline + 0.02 * brightness
        return None


class GpioIntrusionSensor:
    """Normally-closed case switch between a GPIO pin and ground."""

    def __init__(self, pin: int):
        from gpiozero import Button    # imported here: only available on the Pi
        self._switch = Button(pin, pull_up=True)

    def check(self, image=None) -> str | None:
        return None if self._switch.is_pressed else "enclosure opened"


class MotionSensor:
    """Fires when the housing is moved or struck harder than ``max_delta_g``."""

    def __init__(self, read_g: Callable[[], tuple[float, float, float]], max_delta_g: float = 0.5):
        self._read, self._max = read_g, max_delta_g
        self._rest = np.array(read_g(), dtype=float)

    def check(self, image=None) -> str | None:
        delta = float(np.linalg.norm(np.array(self._read(), dtype=float) - self._rest))
        return f"housing moved ({delta:.2f} g)" if delta > self._max else None


class TamperMonitor:
    def __init__(self, controller: FailClosedController, sensors: list):
        self.controller, self.sensors = controller, sensors

    @classmethod
    def from_config(cls, controller: FailClosedController, security_cfg: dict) -> "TamperMonitor":
        sensors: list = [LensObstructionSensor(security_cfg["lens_dark_threshold"],
                                               security_cfg["lens_blur_threshold"], security_cfg["lens_bad_frames"])]
        pin = security_cfg.get("intrusion_gpio_pin")
        if pin is not None:
            try:
                sensors.append(GpioIntrusionSensor(pin))
            except Exception as exc:
                # A configured sensor that cannot start is itself a reason not to run.
                controller.trip(f"intrusion sensor unavailable: {exc}", "startup")
        return cls(controller, sensors)

    def check(self, image: np.ndarray | None = None) -> bool:
        """Return True if the device is (now) locked."""
        if self.controller.locked:
            return True
        for sensor in self.sensors:
            reason = sensor.check(image)
            if reason:
                self.controller.trip(reason, type(sensor).__name__)
                return True
        return False
