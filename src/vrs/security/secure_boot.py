"""Boot-state attestation.

On the deployed device the HMAC key is sealed to TPM PCR values, so a modified
boot chain already cannot unseal it. This check is the explicit, logged
counterpart: read the PCRs, compare them to the digest recorded at
provisioning, and refuse to start on a mismatch.

On a development machine (``security.require_attestation: false``) it reports
"skipped" and lets the system run.
"""
from __future__ import annotations

import hashlib
import subprocess


def read_pcr_digest(pcrs: str) -> str:
    """SHA-256 over the selected PCR values, as printed by tpm2_pcrread."""
    out = subprocess.run(["tpm2_pcrread", pcrs], check=True, capture_output=True, timeout=20).stdout
    values = [line.split(b":")[1].strip() for line in out.splitlines() if b"0x" in line]
    return hashlib.sha256(b"".join(values)).hexdigest()


def attest(cfg: dict) -> tuple[bool, str]:
    """Return (ok, detail). ``ok`` is False only when attestation is required and fails."""
    security = cfg["security"]
    if not security.get("require_attestation"):
        return True, "skipped (development mode)"
    try:
        digest = read_pcr_digest(cfg["keys"]["tpm_pcrs"])
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return False, f"could not read TPM PCRs: {exc}"
    if digest != security.get("expected_pcr_digest"):
        return False, "boot measurements do not match the provisioned state"
    return True, "boot measurements verified"
