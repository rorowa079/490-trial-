#!/usr/bin/env python3
"""Report which technical controls are in force under a configuration.

    python scripts/compliance_check.py                          # the configuration the device would start with
    python scripts/compliance_check.py config/compliance.yaml   # the strict profile

Exit code 0 only if nothing fails. This reports settings, not certification:
docs/compliance_matrix.md lists what also has to be true outside the software.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vrs.compliance import posture, summary        # noqa: E402
from vrs.config import load_config                 # noqa: E402

MARK = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}


def main() -> int:
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else None)
    items = posture(cfg)
    for item in items:
        print(f"{MARK[item['status']]}  {item['control']:<17} {item['name']}: {item['detail']}")
    totals = summary(items)
    print(f"\n{totals['pass']} pass, {totals['warn']} warn, {totals['fail']} fail")
    return 1 if totals["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
