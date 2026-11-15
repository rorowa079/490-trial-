"""Hash-to-hash hotlist matching and the evidence summary shown to reviewers.

A match here is only a *candidate*. Nothing is sent anywhere and nobody is
notified until a person has reviewed it (see alert_queue.py).
"""
from __future__ import annotations

from .hotlist_sync import ATTRIBUTES, Hotlist


def attribute_report(observed: dict, entry: dict) -> list[dict]:
    """Compare what the camera saw with what the hotlist says, attribute by attribute.

    Mismatches are reported as prominently as matches: showing a reviewer only
    the supporting evidence is how automation bias creeps in.
    """
    report = []
    for attr in ATTRIBUTES:
        seen, expected = observed.get(attr), entry.get(attr)
        if not seen or not expected:
            state = "unknown"
        else:
            state = "match" if str(seen).lower() == str(expected).lower() else "mismatch"
        report.append({"attribute": attr, "observed": seen, "expected": expected, "state": state})
    return report


def match_confidence(ocr_confidence: float, report: list[dict]) -> float:
    """OCR confidence, scaled down by attribute disagreement.

    All compared attributes agree  -> the OCR confidence is kept.
    All compared attributes differ -> the confidence is halved.
    Nothing to compare             -> the OCR confidence is used unchanged.
    """
    compared = [r for r in report if r["state"] != "unknown"]
    if not compared:
        return round(float(ocr_confidence), 3)
    agreement = sum(r["state"] == "match" for r in compared) / len(compared)
    return round(float(ocr_confidence) * (0.5 + 0.5 * agreement), 3)


class Matcher:
    def __init__(self, hotlist: Hotlist):
        self.hotlist = hotlist

    def check(self, plate_hash: str | None, observed: dict, ocr_confidence: float) -> dict | None:
        """Return a candidate match (entry, report, confidence) or None."""
        if not plate_hash:
            return None
        entry = self.hotlist.lookup(plate_hash)
        if entry is None:
            return None
        report = attribute_report(observed, entry)
        return {"entry": entry, "report": report, "confidence": match_confidence(ocr_confidence, report)}
