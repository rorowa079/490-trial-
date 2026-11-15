#!/usr/bin/env python3
"""Verify a signed software bundle, then unpack it. Nothing is unpacked unless the signature verifies.

    python scripts/apply_update.py vrs-2026.11.tar.gz           (expects vrs-2026.11.tar.gz.sig beside it)

The bundle is a .tar.gz of the repository made by whoever holds the signing
key, signed with ``scripts/sign_update.py file``. It is unpacked into
<data_dir>/releases/<sha384 prefix>/. Switching the service over to the new
release (stop, repoint the systemd unit, start) is left as a deliberate manual
step, and is recorded in the audit log here.

This covers the application. The operating system and bootloader are covered
by secure boot and TPM measurement, not by this script.
"""
import argparse
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vrs import crypto                                   # noqa: E402
from vrs.audit.audit_log import AuditLog                 # noqa: E402
from vrs.config import load_config                       # noqa: E402
from vrs.security.signed_update import UpdateVerifier    # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle")
    parser.add_argument("--config", help="optional override YAML")
    args = parser.parse_args()
    cfg = load_config(args.config)
    audit = AuditLog(Path(cfg["data_dir"]) / "audit.log", cfg.get("organization", ""), cfg["camera_id"])
    bundle = Path(args.bundle)
    verifier = UpdateVerifier.from_config(cfg)
    try:
        if verifier is None:
            raise crypto.IntegrityError(f"no signing public key at {cfg['updates']['public_key_file']}")
        verifier.verify_file(bundle)
    except crypto.IntegrityError as exc:
        audit.record("cli", "integrity.update_rejected", {"bundle": bundle.name, "error": str(exc)})
        print(f"REJECTED: {exc}. Nothing was unpacked.", file=sys.stderr)
        return 1
    digest = crypto.sha384_file(bundle)
    target = Path(cfg["data_dir"]) / "releases" / digest[:16]
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(bundle) as archive:
        archive.extractall(target, filter="data")        # refuses absolute paths, links out of the tree, devices
    audit.record("cli", "integrity.update_verified", {"bundle": bundle.name, "sha384": digest, "path": str(target)})
    print(f"signature verified; unpacked to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
