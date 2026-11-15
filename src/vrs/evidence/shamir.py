"""Shamir secret sharing over GF(256).

Splits the vault private key into ``n`` shares so that any ``k`` rebuild it and
any ``k - 1`` reveal nothing. This is what makes "no single person can open
sealed footage" a mathematical fact instead of a policy.

Share format: ``"<x as 2 hex digits>-<hex bytes>"``, e.g. ``"03-9af1..."``.
"""
from __future__ import annotations

import secrets

from ..privacy.scrubber import scrub

# Log/antilog tables for GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1, generator 3.
_EXP = [0] * 510
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _EXP[_i + 255] = _x
    _LOG[_x] = _i
    _x ^= ((_x << 1) ^ (0x1B if _x & 0x80 else 0)) & 0xFF


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[(_LOG[a] - _LOG[b]) % 255]


def split(secret: bytes | bytearray, threshold: int, shares: int) -> list[str]:
    if not 2 <= threshold <= shares <= 255:
        raise ValueError("need 2 <= threshold <= shares <= 255")
    ys = [bytearray(len(secret)) for _ in range(shares)]
    for pos, byte in enumerate(secret):
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for x in range(1, shares + 1):
            acc = 0
            for c in reversed(coeffs):          # Horner evaluation
                acc = _mul(acc, x) ^ c
            ys[x - 1][pos] = acc
    out = [f"{x:02x}-{ys[x - 1].hex()}" for x in range(1, shares + 1)]
    for y in ys:
        scrub(y)
    return out


def parse(share: str) -> tuple[int, bytearray]:
    try:
        x_hex, y_hex = share.strip().split("-", 1)
        x, y = int(x_hex, 16), bytearray.fromhex(y_hex)
    except ValueError as exc:
        raise ValueError("malformed share") from exc
    if not 1 <= x <= 255 or not y:
        raise ValueError("malformed share")
    return x, y


def combine(shares: list[str]) -> bytearray:
    """Rebuild the secret. With too few or wrong shares the result is garbage, not an error."""
    points = [parse(s) for s in shares]
    xs = [x for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate shares")
    if len({len(y) for _, y in points}) != 1:
        raise ValueError("shares have different lengths")
    secret = bytearray(len(points[0][1]))
    for pos in range(len(secret)):
        acc = 0
        for i, (xi, yi) in enumerate(points):
            weight = 1
            for j, xj in enumerate(xs):
                if j != i:
                    weight = _mul(weight, _div(xj, xj ^ xi))   # Lagrange basis at x = 0
            acc ^= _mul(yi[pos], weight)
        secret[pos] = acc
    for _, y in points:
        scrub(y)
    return secret
