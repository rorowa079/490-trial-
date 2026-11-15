"""Keyed plate hashing: the privacy boundary of the whole system.

Order of operations (hash-first):

    OCR read -> normalize -> HMAC-SHA256 with the device key -> scrub plaintext
    -> only then compare against the (already hashed) hotlist or touch disk

Why HMAC and not a plain SHA-256: there are only tens of millions of possible
plates per state. An unkeyed hash can be reversed by hashing every possible
plate once. With a secret key held in the TPM, the hashes are meaningless to
anyone who copies the database.
"""
from __future__ import annotations

import hashlib
import hmac

from .key_manager import KeyManager
from .normalizer import is_plausible, normalize_plate
from .scrubber import scrub

HASH_VERSION = "v1"
_DOMAIN = b"vrs-plate-v1\x00"     # domain separation: this key is used for plates only


class PlateHasher:
    def __init__(self, keys: KeyManager, privacy_cfg: dict | None = None):
        cfg = privacy_cfg or {}
        self._keys = keys
        self._fold = cfg.get("fold_ambiguous", True)
        self._min = cfg.get("min_plate_length", 2)
        self._max = cfg.get("max_plate_length", 8)

    def hash_plate(self, raw: bytearray) -> str | None:
        """Return the keyed hash of a plate read, or None if it is not a plausible plate.

        ``raw`` is CONSUMED: it is zeroed before this function returns, whatever
        happens. The normalized copy is zeroed too. Nothing here writes to disk
        or logs the plate.
        """
        if not isinstance(raw, bytearray):
            raise TypeError("plate must be a bytearray so it can be scrubbed (see scrubber.to_buffer)")
        normalized = None
        try:
            normalized = normalize_plate(raw, self._fold)
            if not is_plausible(normalized, self._min, self._max):
                return None
            mac = hmac.new(self._keys.hmac_key(), digestmod=hashlib.sha256)
            mac.update(_DOMAIN)
            mac.update(normalized)      # fed from the mutable buffer, no immutable copy made
            return f"{HASH_VERSION}:{mac.hexdigest()}"
        finally:
            scrub(raw)
            scrub(normalized)
