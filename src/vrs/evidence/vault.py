"""Sealed evidence vault.

The device can put footage *into* the vault but cannot take it out.

How it works
------------
* Each UTC day gets a fresh random AES-256 "day key". Event clips are encrypted
  with it (AES-GCM) and written as ``clips/<day>/<clip_id>.enc``.
* The day key is written to disk only after being wrapped to the vault's
  P-384 *public* key (ephemeral ECDH + HKDF-SHA-384 + AES-256-GCM, all FIPS
  approved; see crypto.py). The matching private key is not on the device: it
  was split into Shamir shares at provisioning and handed to custodians.
* The unwrapped day key lives in RAM for the current day only. After a restart
  the device cannot recover it, so it simply starts a new key for the rest of
  that day (key ids look like ``2026-11-14.3fa2c1d0``).
* Purging a day means destroying its wrapped keys. The clip files become
  unreadable to everyone, custodians included.

Clips are short runs of JPEG frames packed in memory. Nothing unencrypted is
ever written to disk on the way in.
"""
from __future__ import annotations

import os
import secrets
import struct
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import crypto
from ..audit.audit_log import AuditLog
from ..db import Database
from ..privacy.scrubber import scrub

_MAGIC = b"VRSC1"
_POINT = crypto.POINT_BYTES


class UnsealError(RuntimeError):
    pass


def day_of(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def generate_vault_keypair() -> tuple[bytearray, bytes]:
    """Return (private key bytes, public key bytes). The private half goes straight to Shamir."""
    return crypto.generate_keypair()


def _wrap_info(key_id: str) -> bytes:
    return b"vrs-daykey-wrap-v2:" + key_id.encode()


def pack_frames(frames: list[bytes]) -> bytes:
    parts = [_MAGIC, struct.pack(">I", len(frames))]
    for frame in frames:
        parts += [struct.pack(">I", len(frame)), frame]
    return b"".join(parts)


def unpack_frames(blob: bytes) -> list[bytes]:
    if blob[:5] != _MAGIC:
        raise UnsealError("not a clip container")
    (count,), pos, frames = struct.unpack(">I", blob[5:9]), 9, []
    for _ in range(count):
        (size,) = struct.unpack(">I", blob[pos:pos + 4])
        frames.append(blob[pos + 4:pos + 4 + size])
        pos += 4 + size
    return frames


class EvidenceVault:
    def __init__(self, root: str | Path, db: Database, audit: AuditLog, public_key: bytes):
        self.root = Path(root)
        self.keys_dir = self.root / "keys"
        self.clips_dir = self.root / "clips"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.clips_dir.mkdir(parents=True, exist_ok=True)
        self.db, self.audit = db, audit
        try:
            self._public = crypto.load_public(public_key)
        except ValueError as exc:
            raise UnsealError(
                "the vault public key is not a P-384 key. This data directory was created by an earlier "
                "version; delete it and provision the device again.") from exc
        self._day_keys: dict[str, tuple[str, bytearray]] = {}     # day -> (key_id, key)

    # ---------------------------------------------------------------- sealing

    def _day_key(self, day: str) -> tuple[str, bytearray]:
        if day not in self._day_keys:
            for old in [d for d in self._day_keys if d != day]:     # yesterday's key leaves RAM
                scrub(self._day_keys.pop(old)[1])
            key_id = f"{day}.{secrets.token_hex(4)}"
            key = bytearray(secrets.token_bytes(32))
            ephemeral = ec.generate_private_key(crypto.CURVE)
            wrap = crypto.derive_wrap_key(ephemeral, self._public, _wrap_info(key_id))
            nonce = secrets.token_bytes(12)
            wrapped = crypto.public_bytes(ephemeral.public_key()) + nonce + AESGCM(wrap).encrypt(
                nonce, bytes(key), key_id.encode())
            (self.keys_dir / f"{key_id}.wrapped").write_bytes(wrapped)
            self._day_keys[day] = (key_id, key)
            self.audit.record("system", "vault.day_key_created", {"key_id": key_id})
        return self._day_keys[day]

    def seal(self, frames: list[bytes], ts_start: float, ts_end: float) -> str:
        """Encrypt a clip (list of JPEG frames) and return its id."""
        day = day_of(ts_start)
        key_id, key = self._day_key(day)
        clip_id = secrets.token_hex(12)
        nonce = secrets.token_bytes(12)
        blob = nonce + AESGCM(bytes(key)).encrypt(nonce, pack_frames(frames), clip_id.encode())
        directory = self.clips_dir / day
        directory.mkdir(exist_ok=True)
        path = directory / f"{clip_id}.enc"
        path.write_bytes(blob)
        self.db.execute(
            "INSERT INTO clips (id, ts_start, ts_end, day, key_id, path, frame_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (clip_id, ts_start, ts_end, day, key_id, str(path.relative_to(self.root)), len(frames)),
        )
        return clip_id

    # -------------------------------------------------------------- unsealing

    def open(self, clip_id: str, private_key: bytearray) -> list[bytes]:
        """Decrypt a clip with the rebuilt vault private key. Raises UnsealError on any failure."""
        row = self.db.one("SELECT * FROM clips WHERE id = ?", (clip_id,))
        if row is None:
            raise UnsealError("no such clip")
        wrapped_path = self.keys_dir / f"{row['key_id']}.wrapped"
        clip_path = self.root / row["path"]
        if not wrapped_path.exists() or not clip_path.exists():
            raise UnsealError("this clip has been purged: its key no longer exists")
        wrapped = wrapped_path.read_bytes()
        day_key = None
        try:
            private = crypto.load_private(private_key)
            wrap = crypto.derive_wrap_key(private, crypto.load_public(wrapped[:_POINT]), _wrap_info(row["key_id"]))
            day_key = bytearray(AESGCM(wrap).decrypt(wrapped[_POINT:_POINT + 12], wrapped[_POINT + 12:],
                                                     row["key_id"].encode()))
            blob = clip_path.read_bytes()
            return unpack_frames(AESGCM(bytes(day_key)).decrypt(blob[:12], blob[12:], clip_id.encode()))
        except (InvalidTag, ValueError) as exc:
            raise UnsealError("the shares supplied do not open this clip") from exc
        finally:
            scrub(day_key)

    # ---------------------------------------------------------------- purging

    def key_ids(self) -> list[str]:
        return sorted(p.name[:-len(".wrapped")] for p in self.keys_dir.glob("*.wrapped"))

    def destroy_key(self, key_id: str) -> None:
        """Cryptographic purge: overwrite and remove a wrapped day key."""
        day = key_id.split(".")[0]
        if day in self._day_keys and self._day_keys[day][0] == key_id:
            scrub(self._day_keys.pop(day)[1])
        path = self.keys_dir / f"{key_id}.wrapped"
        if path.exists():
            # Best effort on flash storage, where wear levelling may keep old
            # blocks. With a TPM, keep wrapped keys in an NV index instead.
            with path.open("r+b") as fh:
                fh.write(secrets.token_bytes(path.stat().st_size))
                fh.flush()
                os.fsync(fh.fileno())
            os.remove(path)

    def delete_clip(self, clip_id: str) -> None:
        row = self.db.one("SELECT path FROM clips WHERE id = ?", (clip_id,))
        if row is None:
            return
        path = self.root / row["path"]
        if path.exists():
            os.remove(path)
        with self.db.transaction() as conn:
            conn.execute("UPDATE sightings SET clip_id = NULL WHERE clip_id = ?", (clip_id,))
            conn.execute("DELETE FROM unseal_requests WHERE clip_id = ?", (clip_id,))
            conn.execute("DELETE FROM clips WHERE id = ?", (clip_id,))

    def scrub(self) -> None:
        """Drop every day key from RAM (tamper or shutdown). Sealed data stays sealed."""
        for _, key in self._day_keys.values():
            scrub(key)
        self._day_keys.clear()

    def stats(self) -> dict:
        row = self.db.one("SELECT COUNT(*) AS n, MIN(ts_start) AS oldest FROM clips")
        size = sum(p.stat().st_size for p in self.clips_dir.rglob("*.enc"))
        return {"clips": row["n"], "oldest_ts": row["oldest"], "bytes": size}
