"""Transparency reporting and the audit export package (NIST SP 800-53 AU-6, AU-7).

Many cities and states require an agency to publish how its plate readers were
used: how many vehicles were read, how many matched a hotlist, how often the
data was searched and by whom, and what was shared. ``transparency_report``
produces those totals for any date range, and ``export_package`` bundles the
report with the audit log and its integrity proof into one zip file.

Everything here is counts and log entries. No plate, hash or image is included.
"""
from __future__ import annotations

import csv
import io
import json
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone

from .audit_log import AuditLog
from .stats import DailyStats


def _day_bounds(day_from: str, day_to: str) -> tuple[float, float]:
    try:
        start = datetime.strptime(day_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = datetime.strptime(day_to, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("dates must look like 2026-01-31") from None
    if end < start:
        raise ValueError("the end date is before the start date")
    return start.timestamp(), end.timestamp() + 86400 - 1e-3


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def transparency_report(system, day_from: str, day_to: str, generated_by: str) -> dict:
    ts_from, ts_to = _day_bounds(day_from, day_to)
    entries = system.audit.entries(None, ts_from=ts_from, ts_to=ts_to)
    actions = Counter(e["action"] for e in entries)
    searches = [e for e in entries if e["action"].startswith("search.")]
    purges = [e for e in entries if e["action"] == "purge.run"]
    counts = DailyStats(system.db).totals(day_from, day_to)
    chain_ok, bad_seq = system.audit.verify()
    retention = system.cfg["retention"]
    return {
        "organization": system.cfg.get("organization", ""),
        "camera_id": system.cfg["camera_id"],
        "period": {"from": day_from, "to": day_to, "timezone": "UTC"},
        "generated": {"at": _iso(time.time()), "by": generated_by},
        "vehicles_read": counts["reads"],
        "plates_hashed": counts["plate_reads"],
        "hotlist_hits": counts["hits"],
        "hit_rate_percent": round(100 * counts["hits"] / counts["reads"], 3) if counts["reads"] else 0.0,
        "reviews": {"confirmed": counts["approved"], "dismissed": counts["dismissed"],
                    "waiting_now": system.alerts.pending_count()},
        "searches": {
            "total": len(searches),
            "by_plate": actions["search.plate_hashed"],
            "by_description": actions["search.attributes"],
            "distinct_cases": len({e["detail"].get("case_ref") for e in searches}),
            "by_user": dict(Counter(e["actor"] for e in searches)),
        },
        "footage_unseals": {"requested": actions["unseal.requested"], "opened": actions["unseal.opened"],
                            "failed": actions["unseal.failed"]},
        "legal_holds": {"created": actions["hold.created"], "released": actions["hold.released"]},
        "hotlist": {"updates": actions["hotlist.update"], "failed_updates": actions["hotlist.sync_failed"],
                    "entries_now": system.hotlist.count()},
        "retention": {
            "clip_days": retention["clip_days"], "index_days": retention["index_days"],
            "purge_runs": len(purges),
            "clips_destroyed": sum(e["detail"].get("clips_removed", 0) for e in purges),
            "index_rows_deleted": sum(e["detail"].get("sightings_removed", 0) for e in purges),
        },
        "data_sharing": {
            "outside_recipients": 0,
            "exports": actions["audit.exported"] + actions["report.exported"],
            "note": "This device sends vehicle data to no other system. Exports contain counts and log "
                    "entries only.",
        },
        "security": {"tamper_events": actions["tamper.locked"], "failed_sign_ins": actions["login.failed"],
                     "sign_ins": actions["login.ok"]},
        "audit_log": {"entries_in_period": len(entries), "chain_intact": chain_ok, "first_bad_entry": bad_seq,
                      "head": system.audit.head()},
    }


AUDIT_COLUMNS = ("seq", "time_utc", "organization", "device", "user", "action", "case_ref", "detail", "prev_hash",
                 "hash")


def audit_csv(entries: list[dict]) -> str:
    """Audit entries (oldest first) as CSV. ``detail`` is JSON so no field is lost."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(AUDIT_COLUMNS)
    for e in sorted(entries, key=lambda e: e["seq"]):
        detail = e.get("detail") or {}
        writer.writerow([e["seq"], _iso(e["ts"]), e.get("org", ""), e.get("device", ""), e["actor"], e["action"],
                         detail.get("case_ref") or "", json.dumps(detail, sort_keys=True), e["prev_hash"], e["hash"]])
    return out.getvalue()


def export_package(system, day_from: str, day_to: str, generated_by: str, posture: list[dict]) -> bytes:
    """One zip: transparency report, audit log for the period, chain verification, compliance posture."""
    ts_from, ts_to = _day_bounds(day_from, day_to)
    report = transparency_report(system, day_from, day_to, generated_by)
    entries = system.audit.entries(None, ts_from=ts_from, ts_to=ts_to)
    readme = (
        f"Audit package for {report['organization']} / {report['camera_id']}\n"
        f"Period {day_from} to {day_to} (UTC), generated {report['generated']['at']} by {generated_by}\n\n"
        "transparency_report.json  usage totals for publication\n"
        "audit_log.csv             every logged action in the period\n"
        "audit_chain.json          result of verifying the whole hash chain, and its newest hash\n"
        "compliance_posture.json   security settings in force when this was generated\n\n"
        "Each audit entry's hash covers the entry and the hash before it, so an edited or removed\n"
        "line is detectable. No plate, plate hash or image is included in this package.\n"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", readme)
        archive.writestr("transparency_report.json", json.dumps(report, indent=2))
        archive.writestr("audit_log.csv", audit_csv(entries))
        archive.writestr("audit_chain.json", json.dumps(report["audit_log"], indent=2))
        archive.writestr("compliance_posture.json", json.dumps(posture, indent=2))
    return buffer.getvalue()
