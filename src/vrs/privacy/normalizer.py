"""Plate normalization: the same plate must always produce the same bytes.

Works on ``bytearray`` only so the caller can scrub both input and output.
The hotlist and live reads go through this same function; if they did not,
their hashes would never match.
"""
from __future__ import annotations

# Look-alike characters that OCR confuses. Folded to one canonical byte.
_FOLD = {ord("O"): ord("0"), ord("Q"): ord("0"), ord("I"): ord("1")}


def normalize_plate(raw: bytearray, fold_ambiguous: bool = True) -> bytearray:
    """Uppercase, drop everything that is not A-Z or 0-9, optionally fold look-alikes.

    Returns a new bytearray. The caller owns (and must scrub) both buffers.
    """
    out = bytearray(len(raw))
    n = 0
    for b in raw:
        if 97 <= b <= 122:            # a-z -> A-Z
            b -= 32
        if 48 <= b <= 57 or 65 <= b <= 90:
            if fold_ambiguous:
                b = _FOLD.get(b, b)
            out[n] = b
            n += 1
    del out[n:]
    return out


def is_plausible(plate: bytearray, min_len: int = 2, max_len: int = 8) -> bool:
    return min_len <= len(plate) <= max_len
