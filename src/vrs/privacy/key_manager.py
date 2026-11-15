"""Custody of the device secrets.

Two secrets live here:

* ``hmac``   - keys the plate hash. Without it the hash index cannot be
               brute-forced back to plates, even though the plate space is small.
* ``review`` - encrypts the short-lived snapshot a reviewer sees for an alert.

Backends
--------
``software``  Keys in files under ``keys.software_dir``. DEVELOPMENT ONLY: anyone
              who copies the disk gets the key. Fine for laptops and tests.
``tpm``       Keys sealed to a TPM 2.0 and released only when the boot
              measurements (PCRs) match. This is what the deployed device uses.
              Provision it with scripts/setup_tpm.sh.

Keys are held in ``bytearray`` so ``scrub()`` can zero them on tamper or shutdown.
"""
from __future__ import annotations

import logging
import os
import secrets
import subprocess
from pathlib import Path

from .scrubber import scrub

log = logging.getLogger(__name__)
KEY_NAMES = ("hmac", "review")
KEY_BYTES = 32


class KeysUnavailable(RuntimeError):
    """Raised when keys were scrubbed (tamper, shutdown) or never loaded."""


class SoftwareKeyBackend:
    def __init__(self, directory: str | Path):
        self.dir = Path(directory)

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.key"

    def exists(self) -> bool:
        return all(self._path(n).exists() for n in KEY_NAMES)

    def provision(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        for name in KEY_NAMES:
            path = self._path(name)
            if not path.exists():
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(secrets.token_bytes(KEY_BYTES))

    def load(self, name: str) -> bytearray:
        return bytearray(self._path(name).read_bytes())


class TpmKeyBackend:
    """Unseals keys with tpm2-tools. Needs a TPM and the objects made by setup_tpm.sh."""

    def __init__(self, contexts: dict[str, str], pcrs: str):
        self.contexts, self.pcrs = contexts, pcrs

    def exists(self) -> bool:
        # Persistent handles (0x81...) cannot be checked on disk; a missing one
        # surfaces as KeysUnavailable when load() asks the TPM for it.
        return all(str(p).startswith("0x") or Path(p).exists() for p in self.contexts.values())

    def provision(self) -> None:
        raise RuntimeError("TPM keys are provisioned once with scripts/setup_tpm.sh")

    def load(self, name: str) -> bytearray:
        try:
            out = subprocess.run(
                ["tpm2_unseal", "-c", self.contexts[name], "-p", f"pcr:{self.pcrs}"],
                check=True, capture_output=True, timeout=20,
            ).stdout
        except FileNotFoundError as exc:
            raise KeysUnavailable("tpm2-tools is not installed") from exc
        except subprocess.CalledProcessError as exc:
            # Wrong PCR values mean the boot chain changed: refuse to release keys.
            raise KeysUnavailable(f"TPM refused to unseal '{name}' (boot state changed?)") from exc
        return bytearray(out)


class KeyManager:
    def __init__(self, backend):
        self.backend = backend
        self._keys: dict[str, bytearray] = {}

    @classmethod
    def from_config(cls, cfg: dict) -> "KeyManager":
        kcfg = cfg["keys"]
        if kcfg["backend"] == "tpm":
            backend = TpmKeyBackend(
                {"hmac": kcfg["tpm_hmac_handle"], "review": kcfg["tpm_review_handle"]}, kcfg["tpm_pcrs"]
            )
        else:
            log.warning("software key backend in use: development only, not for a deployed device")
            backend = SoftwareKeyBackend(kcfg["software_dir"])
        return cls(backend)

    def load(self) -> None:
        if not self.backend.exists():
            raise KeysUnavailable("device keys are not provisioned; run scripts/init_device.py")
        for name in KEY_NAMES:
            key = self.backend.load(name)
            if len(key) != KEY_BYTES:
                scrub(key)
                raise KeysUnavailable(f"key '{name}' has the wrong length")
            self._keys[name] = key

    def _get(self, name: str) -> bytearray:
        try:
            return self._keys[name]
        except KeyError:
            raise KeysUnavailable("keys are not loaded (device locked or shut down)") from None

    def hmac_key(self) -> bytearray:
        return self._get("hmac")

    def review_key(self) -> bytearray:
        return self._get("review")

    @property
    def loaded(self) -> bool:
        return len(self._keys) == len(KEY_NAMES)

    def scrub(self) -> None:
        """Zero every key in RAM. Used on tamper and at shutdown."""
        for key in self._keys.values():
            scrub(key)
        self._keys.clear()
