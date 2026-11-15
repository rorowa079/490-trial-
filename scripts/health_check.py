#!/usr/bin/env python3
"""Health probe for systemd/cron: exits non-zero if the device needs attention.

Checks, without loading any keys: tamper lock, audit-chain integrity, free disk.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vrs.audit.audit_log import AuditLog      # noqa: E402
from vrs.config import load_config            # noqa: E402


def main() -> int:
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else None)
    data = Path(cfg["data_dir"])
    problems = []
    if (data / "TAMPER.lock").exists():
        problems.append("device is locked after a tamper event")
    ok, bad_seq = AuditLog(data / "audit.log").verify()
    if not ok:
        problems.append(f"audit log chain is broken at entry {bad_seq}")
    usage = shutil.disk_usage(data)
    if usage.free / usage.total < 0.10:
        problems.append(f"disk almost full ({usage.free // 2**20} MB free)")
    for problem in problems:
        print("UNHEALTHY:", problem)
    if not problems:
        print("healthy")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
