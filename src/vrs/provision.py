"""One-time device provisioning.

Creates the device keys, the device's X.509 identity and the evidence-vault key pair. The vault private key
is split into Shamir shares and returned exactly once; it is never written to
disk. Whoever runs this hands one share to each custodian and keeps no copy.
"""
from __future__ import annotations

from pathlib import Path

from .evidence import shamir
from .evidence.vault import generate_vault_keypair
from .privacy.key_manager import KeyManager
from .privacy.scrubber import scrub
from .security.device_identity import ensure_identity


def vault_public_path(cfg: dict) -> Path:
    return Path(cfg["data_dir"]) / "vault" / "public.key"


def is_provisioned(cfg: dict) -> bool:
    return vault_public_path(cfg).exists()


def provision_device(cfg: dict) -> list[str]:
    """Provision keys and return the custodian shares. Refuses to run twice."""
    public_path = vault_public_path(cfg)
    if public_path.exists():
        raise RuntimeError("device is already provisioned; re-provisioning would orphan all sealed evidence")
    keys = KeyManager.from_config(cfg)
    if cfg["keys"]["backend"] == "software":
        keys.backend.provision()
    elif not keys.backend.exists():
        raise RuntimeError("TPM keys missing: run scripts/setup_tpm.sh first")

    private, public = generate_vault_keypair()
    try:
        shares = shamir.split(private, cfg["evidence"]["shamir_threshold"], cfg["evidence"]["shamir_shares"])
    finally:
        scrub(private)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(public)
    ensure_identity(cfg)                 # device key, CSR and a first certificate (IA-3)
    return shares
