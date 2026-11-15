"""Signed updates (NIST SP 800-53 SI-7): nothing new runs until its signature verifies.

What is covered
---------------
* **Model weights** (vehicle detector, plate localizer, face detector). A signed
  manifest lists each file and its SHA-384. With ``updates.require_signed_models``
  the device checks every model it is about to load, on every start, and refuses
  to start if one is missing from the manifest or differs from it.
* **Hotlist files.** A detached signature (``list.csv.sig``) proves the list came
  from whoever holds the signing key, so a tampered feed cannot add a plate.
* **Software bundles.** ``scripts/apply_update.py`` verifies a bundle's signature
  before unpacking it.

The device holds only the *public* key (``updates.public_key_file``). The private
key stays off the device with whoever is allowed to publish updates; create it
and sign with ``scripts/sign_update.py``.

Not covered here: the operating system and bootloader. Those are measured by
secure boot and the TPM (see secure_boot.py), not by this module.
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import crypto
from ..crypto import IntegrityError

MANIFEST_VERSION = 1


def build_manifest(files: list[Path], version: str) -> bytes:
    """Canonical manifest bytes for ``files`` (used by the signing script)."""
    body = {"manifest_version": MANIFEST_VERSION, "version": version,
            "files": {Path(f).name: crypto.sha384_file(f) for f in sorted(files)}}
    return json.dumps(body, sort_keys=True, indent=2).encode() + b"\n"


class UpdateVerifier:
    def __init__(self, public_key_pem: bytes):
        self._public = public_key_pem

    @classmethod
    def from_config(cls, cfg: dict) -> "UpdateVerifier | None":
        path = Path(cfg["updates"]["public_key_file"])
        return cls(path.read_bytes()) if path.exists() else None

    def verify_bytes(self, data: bytes, signature_b64: bytes) -> None:
        crypto.verify(self._public, signature_b64.strip(), data)

    def verify_file(self, path: str | Path, signature_path: str | Path | None = None) -> None:
        path = Path(path)
        signature_path = Path(signature_path) if signature_path else path.with_name(path.name + ".sig")
        if not signature_path.exists():
            raise IntegrityError(f"{path.name} has no signature file")
        self.verify_bytes(path.read_bytes(), signature_path.read_bytes())

    def manifest(self, manifest_path: str | Path) -> dict[str, str]:
        """Verify the manifest's own signature and return {file name: sha384}."""
        manifest_path = Path(manifest_path)
        if not manifest_path.exists():
            raise IntegrityError("there is no signed model manifest")
        self.verify_file(manifest_path)
        body = json.loads(manifest_path.read_text())
        if body.get("manifest_version") != MANIFEST_VERSION:
            raise IntegrityError("unsupported manifest version")
        return dict(body["files"])

    def verify_model(self, model_path: str | Path, manifest_path: str | Path) -> str:
        """Raise IntegrityError unless ``model_path`` is listed in the signed manifest with a matching digest."""
        model_path = Path(model_path)
        files = self.manifest(manifest_path)
        if not model_path.exists():
            raise IntegrityError(f"model file {model_path.name} is missing")
        expected = files.get(model_path.name)
        if expected is None:
            raise IntegrityError(f"{model_path.name} is not in the signed manifest")
        if crypto.sha384_file(model_path) != expected:
            raise IntegrityError(f"{model_path.name} does not match the signed manifest")
        return expected


def models_in_use(cfg: dict) -> list[Path]:
    """Every model file the current configuration will load."""
    vision, redaction = cfg["vision"], cfg["privacy"]["redaction"]
    paths = []
    if vision["detector"] == "yolo":
        paths.append(vision["yolo_weights"])
    if vision["ocr"] == "paddle" and vision.get("plate_weights"):
        paths.append(vision["plate_weights"])
    if redaction["faces"]:
        paths.append(redaction["face_model"])
    return [Path(p) for p in paths]


def verify_models(cfg: dict, verifier: "UpdateVerifier | None") -> list[str]:
    """Check every model in use. Returns the verified file names; raises IntegrityError on the first problem."""
    if verifier is None:
        raise IntegrityError("updates.require_signed_models is set but no signing public key is installed")
    return [str(path.name) for path in models_in_use(cfg)
            if verifier.verify_model(path, cfg["updates"]["manifest"])]
