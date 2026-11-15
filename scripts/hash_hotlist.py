#!/usr/bin/env python3
"""Load a stolen-vehicle list onto the device as hashes.

    python scripts/hash_hotlist.py stolen.csv --replace

CSV columns: plate (required), case_ref, color, body_type, make, model.
Each plate is hashed in memory with the device key; only hashes are stored.
Delete the CSV from this machine afterwards, or better, pipe it in from the
agency source so it never lands on the device's disk at all:

    curl -s https://agency.example/hotlist.csv | python scripts/hash_hotlist.py -

With ``updates.require_signed_models`` on (the compliance profile), a list
loaded from a file must come with a valid signature file (<list>.csv.sig, made
by scripts/sign_update.py), and unsigned input from standard input is refused.
For an automatic, mutually authenticated feed, set ``hotlist_sync.url`` instead.
"""
import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vrs.config import load_config        # noqa: E402
from vrs.crypto import IntegrityError     # noqa: E402
from vrs.system import System             # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", help="path to the CSV, or - for standard input")
    parser.add_argument("--replace", action="store_true", help="replace the whole hotlist instead of adding to it")
    parser.add_argument("--source", default=None, help="label recorded in the audit log")
    parser.add_argument("--config", help="optional override YAML")
    args = parser.parse_args()

    cfg = load_config(args.config)
    system = System(cfg)
    try:
        if cfg["updates"]["require_signed_models"]:
            try:
                if args.csv == "-" or system.updates is None:
                    raise IntegrityError("a signed list file and an installed signing key are required")
                system.updates.verify_file(args.csv)
            except IntegrityError as exc:
                system.audit.record("cli", "hotlist.rejected", {"source": args.csv, "error": str(exc)})
                print(f"REJECTED: {exc}. The hotlist was not changed.", file=sys.stderr)
                return 1
        if args.csv == "-":
            result = system.hotlist.ingest(csv.DictReader(sys.stdin), args.source or "stdin", "cli", args.replace)
        else:
            result = system.hotlist.ingest_csv(args.csv, args.source, "cli", args.replace)
    finally:
        system.shutdown()
    print(f"stored {result['stored']} hashed entries, skipped {result['skipped']} unreadable rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
