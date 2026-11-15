"""Every cryptographic primitive the system uses, in one place.

Algorithms (all on the FIPS-approved lists; NIST SP 800-53 control SC-13)
-------------------------------------------------------------------------
* Plate hash            HMAC-SHA-256                      (FIPS 198-1)
* Clip and key sealing  AES-256-GCM                       (SP 800-38D)
* Day-key wrapping      ECDH P-384 + HKDF-SHA-384         (SP 800-56A / 56C)
* Update signatures     ECDSA P-384 with SHA-384          (FIPS 186-5)
* Passwords             PBKDF2-HMAC-SHA-256               (SP 800-132)
* Audit chain, digests  SHA-256 / SHA-384                 (FIPS 180-4)

Deliberately NOT used: X25519, scrypt, ChaCha20, MD5, SHA-1 for signatures.
(TOTP codes still use HMAC-SHA-1 because authenticator apps require it; the
phishing-resistant path is security keys, see api/auth.py.)

Approved algorithms are necessary for FIPS 140-3 but not sufficient. The
standard is met only when these calls are served by a *validated cryptographic
module*: an operating system whose OpenSSL FIPS provider holds a CMVP
certificate. ``fips_provider_active()`` reports whether one is in use, and
``crypto.require_fips_provider: true`` makes the device refuse to start
without it. Splitting the vault key with Shamir's scheme is secret sharing,
not encryption, and has no FIPS-approved equivalent to swap in.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP384R1()
SCALAR_BYTES = 48                     # P-384 private scalar
POINT_BYTES = 97                      # uncompressed P-384 public point (0x04 || X || Y)
PBKDF2_MIN_ITERATIONS = 1000          # SP 800-132 floor; the configured default is far higher


class CryptoPolicyError(RuntimeError):
    """The configured cryptographic policy cannot be met on this machine."""


class IntegrityError(RuntimeError):
    """A signature or digest did not verify."""


def fips_provider_active() -> bool:
    """True when OpenSSL is running with its FIPS provider (a validated module, if the OS ships one)."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        return bool(getattr(backend, "_fips_enabled", False))
    except Exception:
        return False


def enforce_policy(cfg: dict) -> None:
    if cfg.get("crypto", {}).get("require_fips_provider") and not fips_provider_active():
        raise CryptoPolicyError(
            "crypto.require_fips_provider is set but OpenSSL is not running a FIPS provider. "
            "Run on an operating system with a FIPS 140-3 validated OpenSSL module and enable FIPS mode.")


# ------------------------------------------------------------------ passwords

def hash_password(password: str, salt: bytes, iterations: int) -> bytes:
    if iterations < PBKDF2_MIN_ITERATIONS:
        raise CryptoPolicyError(f"PBKDF2 needs at least {PBKDF2_MIN_ITERATIONS} iterations")
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)


# ------------------------------------------------------------- P-384 key pairs

def generate_keypair() -> tuple[bytearray, bytes]:
    """Return (private scalar, public point) as raw bytes."""
    private = ec.generate_private_key(CURVE)
    scalar = private.private_numbers().private_value.to_bytes(SCALAR_BYTES, "big")
    return bytearray(scalar), public_bytes(private.public_key())


def public_bytes(public: ec.EllipticCurvePublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_private(scalar: bytes | bytearray) -> ec.EllipticCurvePrivateKey:
    if len(scalar) != SCALAR_BYTES:
        raise ValueError("not a P-384 private key")
    return ec.derive_private_key(int.from_bytes(bytes(scalar), "big"), CURVE)


def load_public(point: bytes) -> ec.EllipticCurvePublicKey:
    if len(point) != POINT_BYTES:
        raise ValueError("not a P-384 public key")
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, point)


def derive_wrap_key(private: ec.EllipticCurvePrivateKey, public: ec.EllipticCurvePublicKey, info: bytes) -> bytes:
    """One-pass ECDH followed by HKDF-SHA-384: a 256-bit key-wrapping key."""
    shared = private.exchange(ec.ECDH(), public)
    return HKDF(hashes.SHA384(), 32, salt=None, info=info).derive(shared)


# ------------------------------------------------------------------ signatures

def sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Base64 of a DER ECDSA signature. Used off-device by scripts/sign_update.py."""
    return base64.b64encode(private_key.sign(data, ec.ECDSA(hashes.SHA384())))


def verify(public_key_pem: bytes, signature_b64: bytes, data: bytes) -> None:
    """Raise IntegrityError unless ``signature_b64`` is a valid P-384 signature over ``data``."""
    try:
        public = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != CURVE.name:
            raise IntegrityError("the update signing key must be an ECDSA P-384 key")
        public.verify(base64.b64decode(signature_b64, validate=True), data, ec.ECDSA(hashes.SHA384()))
    except (InvalidSignature, ValueError) as exc:
        raise IntegrityError("signature does not verify") from exc


def sha384_file(path: str | Path) -> str:
    digest = hashlib.sha384()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
