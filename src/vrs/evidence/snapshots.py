"""Review snapshots: the one image a reviewer may see without an unseal.

When a sighting matches the hotlist, a single cropped still of that vehicle is
encrypted with the device's review key so the operator has something to judge.
It is deleted as soon as the alert is approved or dismissed, and after
``retention.snapshot_hours`` if nobody reviews it. Vehicles that did not match
never get a snapshot; their footage exists only in the sealed vault.
"""
from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..privacy.key_manager import KeyManager


class ReviewSnapshots:
    def __init__(self, root: str | Path, keys: KeyManager):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.keys = keys

    def store(self, jpeg: bytes) -> str:
        name = f"{secrets.token_hex(12)}.enc"
        nonce = secrets.token_bytes(12)
        blob = nonce + AESGCM(bytes(self.keys.review_key())).encrypt(nonce, jpeg, name.encode())
        (self.root / name).write_bytes(blob)
        return name

    def load(self, name: str) -> bytes | None:
        path = self.root / Path(name).name
        if not path.exists():
            return None
        blob = path.read_bytes()
        return AESGCM(bytes(self.keys.review_key())).decrypt(blob[:12], blob[12:], path.name.encode())

    def delete(self, name: str | None) -> None:
        if name:
            path = self.root / Path(name).name
            if path.exists():
                os.remove(path)

    def expire(self, max_age_hours: float, now: float | None = None) -> list[str]:
        cutoff = (now or time.time()) - max_age_hours * 3600
        removed = []
        for path in self.root.glob("*.enc"):
            if path.stat().st_mtime < cutoff:
                os.remove(path)
                removed.append(path.name)
        return removed
