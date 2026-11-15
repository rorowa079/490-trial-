"""Hardware supply-chain check (NDAA Section 889; NIST SP 800-53 SR-3, SR-11).

Section 889 of the FY2019 NDAA bars US federal agencies, and anyone selling to
them, from buying or using telecommunications and video-surveillance equipment
made by five named companies or their subsidiaries and affiliates. Many states
and cities apply the same rule. The restriction follows the *chips inside* a
product as well as the badge on it, which is why the bill of materials lists a
chipset for every part.

This check is a screen, not a legal determination. The lists below name the
companies in the statute and brands widely documented as theirs or as rebadged
versions of their products. Before a real procurement, check each part against
the current FAR 52.204-25 guidance and the FCC Covered List.
"""
from __future__ import annotations

from pathlib import Path

import yaml

# Named in Section 889(f)(3), with well-known subsidiaries and house brands.
PROHIBITED = {
    "huawei": "Huawei Technologies", "hisilicon": "HiSilicon (Huawei subsidiary)",
    "zte": "ZTE Corporation", "hytera": "Hytera Communications",
    "hikvision": "Hangzhou Hikvision", "ezviz": "EZVIZ (Hikvision brand)", "hiwatch": "HiWatch (Hikvision brand)",
    "dahua": "Dahua Technology", "imou": "Imou (Dahua brand)",
}
# Brands that have commonly sold rebadged hardware from the companies above: confirm the actual manufacturer.
REVIEW = {"lorex": "formerly Dahua-owned", "amcrest": "has sold Dahua-made cameras",
          "annke": "has sold Hikvision-made cameras"}
FIELDS = ("vendor", "chipset_vendor")


def check_bom(components: list[dict]) -> list[dict]:
    """Return one finding per component: status is prohibited | review | unverified | ok."""
    findings = []
    for part in components:
        text = " ".join(str(part.get(f) or "") for f in ("name", "vendor", "chipset", "chipset_vendor")).lower()
        status, reason = "ok", ""
        for needle, label in PROHIBITED.items():
            if needle in text:
                status, reason = "prohibited", f"matches {label}, named in NDAA Section 889"
                break
        else:
            for needle, label in REVIEW.items():
                if needle in text:
                    status, reason = "review", f"brand {label}; confirm who made it and which chipset it uses"
                    break
            else:
                missing = [f for f in FIELDS if str(part.get(f) or "").strip().lower() in ("", "unknown", "todo")]
                if missing:
                    status, reason = "unverified", f"fill in: {', '.join(missing)}"
        findings.append({"name": part.get("name", "(unnamed)"), "status": status, "reason": reason})
    return findings


def load_bom(path: str | Path) -> list[dict]:
    return (yaml.safe_load(Path(path).read_text()) or {}).get("components") or []


def summarize(findings: list[dict]) -> dict:
    counts = {s: sum(1 for f in findings if f["status"] == s) for s in ("prohibited", "review", "unverified", "ok")}
    counts["compliant"] = bool(findings) and counts["prohibited"] == 0 and counts["review"] == 0 \
        and counts["unverified"] == 0
    return counts
