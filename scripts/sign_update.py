#!/usr/bin/env python3
"""Create the update-signing key and sign models, hotlists or software bundles.

Run this on the machine of whoever is allowed to publish updates, NOT on the
device. The device only ever holds the public key.

    python scripts/sign_update.py keygen  --out ~/vrs-signing        # once
    python scripts/sign_update.py models  --key ~/vrs-signing/update_signing.key --version 2026.11
    python scripts/sign_update.py file    --key ~/vrs-signing/update_signing.key hotlist.csv

``keygen`` writes update_signing.key (private, passphrase-protected) and
update_signing.pub. Copy the .pub file to config/update_signing.pub on every
device. ``models`` writes manifest.json and manifest.json.sig next to the model
files. ``file`` writes <file>.sig next to any file (a hotlist CSV, an update
bundle). Keys are ECDSA P-384; signatures use SHA-384.
"""
import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization          # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec          # noqa: E402

from vrs import crypto                                            # noqa: E402
from vrs.security.signed_update import build_manifest             # noqa: E402

MODEL_SUFFIXES = {".pt", ".onnx", ".tflite", ".pdmodel", ".pdiparams", ".engine"}


def _passphrase(args, confirm: bool) -> bytes:
    if args.passphrase_env:
        import os
        value = os.environ.get(args.passphrase_env, "")
    else:
        value = getpass.getpass("Signing key passphrase: ")
        if confirm and value != getpass.getpass("Again: "):
            sys.exit("error: passphrases do not match")
    if len(value) < 12:
        sys.exit("error: the passphrase needs at least 12 characters")
    return value.encode()


def _load_key(args):
    return serialization.load_pem_private_key(Path(args.key).read_bytes(), _passphrase(args, False))


def keygen(args) -> int:
    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    private_path, public_path = out / "update_signing.key", out / "update_signing.pub"
    if private_path.exists():
        sys.exit(f"error: {private_path} already exists; refusing to overwrite a signing key")
    key = ec.generate_private_key(crypto.CURVE)
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_passphrase(args, True))))
    private_path.chmod(0o600)
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"private key: {private_path}   (keep off the device; back it up somewhere safe)")
    print(f"public key:  {public_path}   (copy to config/update_signing.pub on each device)")
    return 0


def models(args) -> int:
    directory = Path(args.dir)
    files = sorted(p for p in directory.iterdir() if p.suffix in MODEL_SUFFIXES)
    if not files:
        sys.exit(f"error: no model files in {directory}")
    manifest = build_manifest(files, args.version)
    (directory / "manifest.json").write_bytes(manifest)
    (directory / "manifest.json.sig").write_bytes(crypto.sign(_load_key(args), manifest) + b"\n")
    for path in files:
        print("signed:", path.name)
    print(f"wrote {directory / 'manifest.json'} and manifest.json.sig")
    return 0


def sign_file(args) -> int:
    path = Path(args.path)
    signature = path.with_name(path.name + ".sig")
    signature.write_bytes(crypto.sign(_load_key(args), path.read_bytes()) + b"\n")
    print(f"wrote {signature}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--passphrase-env", help="read the passphrase from this environment variable (for CI)")
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("keygen", help="create the signing key pair")
    cmd.add_argument("--out", required=True, help="directory for the key files (not inside the repository)")
    cmd.set_defaults(run=keygen)
    cmd = commands.add_parser("models", help="write a signed manifest for the model files")
    cmd.add_argument("--key", required=True)
    cmd.add_argument("--dir", default=str(ROOT / "src" / "vrs" / "vision" / "models"))
    cmd.add_argument("--version", required=True, help="label for this set of models, e.g. 2026.11")
    cmd.set_defaults(run=models)
    cmd = commands.add_parser("file", help="write a detached signature for one file")
    cmd.add_argument("--key", required=True)
    cmd.add_argument("path")
    cmd.set_defaults(run=sign_file)
    args = parser.parse_args()
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
