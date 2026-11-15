#!/usr/bin/env python3
"""Screen the hardware bill of materials against NDAA Section 889.

    python scripts/check_bom.py [config/hardware_bom.yaml]

Exit code 0 only if every part is cleared: none prohibited, none needing
review, none with an unknown maker or chipset. This is a screen, not a legal
determination; see src/vrs/security/supply_chain.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vrs.config import load_config                                        # noqa: E402
from vrs.security.supply_chain import check_bom, load_bom, summarize      # noqa: E402

LABELS = {"ok": "cleared", "unverified": "UNVERIFIED", "review": "REVIEW", "prohibited": "PROHIBITED"}


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(load_config()["supply_chain"]["bom_file"])
    if not path.exists():
        print(f"no bill of materials at {path}", file=sys.stderr)
        return 2
    findings = check_bom(load_bom(path))
    for finding in findings:
        print(f"{LABELS[finding['status']]:<11} {finding['name']}" + (f"  ({finding['reason']})" if finding["reason"] else ""))
    result = summarize(findings)
    print(f"\n{result['ok']} cleared, {result['unverified']} unverified, {result['review']} to review, "
          f"{result['prohibited']} prohibited")
    return 0 if result["compliant"] else 1


if __name__ == "__main__":
    sys.exit(main())
