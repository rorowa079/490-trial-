#!/usr/bin/env python3
"""Provision a new device: keys, device certificate, evidence-vault custodian shares, first admin account.

    python scripts/init_device.py --admin alice

Run once. The custodian shares and the admin's authenticator secret are printed
a single time and stored nowhere, so write them down before closing the window.
"""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vrs.api.auth import Auth, AuthError          # noqa: E402
from vrs.config import load_config                # noqa: E402
from vrs.provision import provision_device        # noqa: E402
from vrs.security.device_identity import identity_dir   # noqa: E402
from vrs.system import System                     # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--admin", required=True, help="username of the first admin account")
    parser.add_argument("--config", help="optional override YAML")
    args = parser.parse_args()
    cfg = load_config(args.config)

    minimum = cfg["api"]["min_password_chars"]
    password = getpass.getpass(f"Password for {args.admin} ({minimum}+ characters): ")
    if len(password) < minimum or password != getpass.getpass("Again: "):
        print(f"error: passwords must match and have at least {minimum} characters; nothing was created",
              file=sys.stderr)
        return 1
    try:
        shares = provision_device(cfg)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    system = System(cfg)
    try:
        secret = system.auth.create_user(args.admin, password, "admin")
    except AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        system.shutdown()

    threshold = cfg["evidence"]["shamir_threshold"]
    print("\n=== EVIDENCE VAULT CUSTODIAN SHARES ===")
    print(f"Any {threshold} of these {len(shares)} shares open sealed footage. Give ONE to each custodian.")
    print("They are not stored on this device and cannot be shown again.\n")
    for number, share in enumerate(shares, 1):
        print(f"  Custodian {number}: {share}")
    print("\n=== AUTHENTICATOR SETUP FOR", args.admin, "===")
    print("  Secret:", secret)
    print("  URI:   ", Auth.provisioning_uri(args.admin, secret))
    print("\n=== DEVICE CERTIFICATE ===")
    print("  Signing request for your certificate authority:", identity_dir(cfg) / "device.csr")
    print("  Until the CA-signed certificate replaces device.crt, the device uses a self-signed one.")
    if args.admin and cfg["api"]["phishing_resistant_roles"]:
        print("\nSecurity keys are required: the first sign-in with the authenticator code can only enroll one.")
    print("\nDevice provisioned. Start it with:  python -m vrs.app")
    return 0


if __name__ == "__main__":
    sys.exit(main())
