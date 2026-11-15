"""Compliance posture: which technical controls are actually switched on.

``posture(cfg)`` inspects the configuration (and the running system, if given)
and reports each control as:

pass   in force
warn   available but relaxed in this configuration (fine for development)
fail   required for a compliant deployment and not in force

It reports settings, not certification. Passing every line does not make a
deployment CJIS- or FedRAMP-compliant: those also need assessed hardware, an
authorised hosting environment, vetted personnel and written policy. See
docs/compliance_matrix.md for the full mapping, including what code cannot do.
"""
from __future__ import annotations

import os
from pathlib import Path

from . import crypto
from .api.auth import ROLES
from .security.device_identity import certificate_info
from .security.supply_chain import check_bom, load_bom, summarize

PRIVILEGED = {"investigator", "supervisor", "admin"}


def on_encrypted_volume(path: str | Path) -> bool | None:
    """True if ``path`` is on a dm-crypt (LUKS) volume, False if it is not, None if this machine cannot tell.

    Sealed clips and review snapshots are encrypted by the application whatever
    the disk is. The index, the audit log and the device certificate key are
    ordinary files, so on the device they depend on full-disk encryption.
    """
    try:
        device = os.stat(path).st_dev
        node = Path(f"/sys/dev/block/{os.major(device)}:{os.minor(device)}").resolve(strict=True)
    except OSError:
        return None                       # not Linux, or a virtual filesystem with no block device

    def encrypted(block: Path, depth: int = 0) -> bool:
        uuid = block / "dm" / "uuid"
        if uuid.exists() and uuid.read_text().startswith("CRYPT-"):
            return True
        slaves = block / "slaves"         # e.g. an LVM volume sitting on a LUKS container
        return depth < 4 and slaves.is_dir() and any(encrypted(s.resolve(), depth + 1) for s in slaves.iterdir())

    return encrypted(node)


def _item(control: str, name: str, status: str, detail: str) -> dict:
    return {"control": control, "name": name, "status": status, "detail": detail}


def posture(cfg: dict, system=None) -> list[dict]:
    api, security, updates, retention = cfg["api"], cfg["security"], cfg["updates"], cfg["retention"]
    redaction, tls = cfg["privacy"]["redaction"], cfg["api"]["tls"]
    items = []

    fips = crypto.fips_provider_active()
    items.append(_item("SC-13", "Approved algorithms only", "pass",
                       "HMAC-SHA-256, AES-256-GCM, ECDH/ECDSA P-384, PBKDF2-HMAC-SHA-256"))
    items.append(_item("SC-13", "FIPS 140-3 validated module", "pass" if fips else "fail",
                       "OpenSSL FIPS provider is active" if fips else
                       "OpenSSL is not running a FIPS provider; needs an OS with a validated module"))

    tpm = cfg["keys"]["backend"] == "tpm"
    items.append(_item("SC-12 / SR-9", "Keys in hardware (TPM 2.0)", "pass" if tpm else "fail",
                       "device keys are sealed to the TPM" if tpm else
                       "software key files in use: development only"))
    disk = on_encrypted_volume(cfg["data_dir"])
    items.append(_item("SC-28", "Storage encrypted at rest", {True: "pass", False: "fail", None: "warn"}[disk],
                       {True: "data directory is on an encrypted (LUKS) volume",
                        False: "footage is sealed, but the index and audit log are on an unencrypted disk",
                        None: "footage is sealed; could not tell whether the disk itself is encrypted"}[disk]))
    attested = bool(security.get("require_attestation"))
    items.append(_item("SI-7", "Boot state verified at start", "pass" if attested else "fail",
                       "start is refused unless TPM measurements match" if attested else "attestation is off"))
    signed = bool(updates.get("require_signed_models")) and Path(updates["public_key_file"]).exists()
    items.append(_item("SI-7", "Signed model and software updates", "pass" if signed else "fail",
                       "unsigned or altered models are refused" if signed else
                       "signature checking is off or no signing key is installed"))
    intrusion = security.get("intrusion_gpio_pin") is not None
    items.append(_item("PE-3", "Enclosure tamper switch", "pass" if intrusion else "warn",
                       "case switch fitted" if intrusion else "no case switch configured; lens check only"))

    items.append(_item("SC-8", "TLS 1.3 for the dashboard", "pass" if tls["enabled"] else "fail",
                       "HTTPS, TLS 1.3 minimum" if tls["enabled"] else
                       "plain HTTP: acceptable only on localhost"))
    cert = certificate_info(cfg)
    if cert is None:
        items.append(_item("IA-3", "Device certificate", "fail", "no device identity has been created"))
    else:
        items.append(_item("IA-3", "Device certificate", "warn" if cert["self_signed"] else "pass",
                           "self-signed: have your CA sign device.csr" if cert["self_signed"] else
                           f"issued to {cert['subject']}"))
    sync = cfg["hotlist_sync"]
    if sync.get("url"):
        good = sync["url"].lower().startswith("https://") and sync.get("require_signature") and sync.get("ca_file")
        items.append(_item("IA-3 / SI-7", "Hotlist feed", "pass" if good else "fail",
                           "mutual TLS to a pinned CA, signed list" if good else
                           "feed must be https with a pinned CA and a required signature"))

    items.append(_item("IA-2", "Multi-factor sign-in", "pass" if api["require_mfa"] else "fail",
                       "every account needs a second factor" if api["require_mfa"] else "second factor is off"))
    key_roles = set(api.get("phishing_resistant_roles") or [])
    missing = PRIVILEGED - key_roles
    items.append(_item("IA-2", "Phishing-resistant sign-in for privileged roles", "fail" if missing else "pass",
                       f"security key not required for: {', '.join(sorted(missing))}" if missing else
                       "security key (FIDO2) required"))
    idle_ok, lock_ok = api["session_minutes"] <= 30, api["max_login_failures"] <= 5
    items.append(_item("AC-11 / AC-7", "Session timeout and lockout", "pass" if idle_ok and lock_ok else "fail",
                       f"idle sign-out {api['session_minutes']} min; lock after {api['max_login_failures']} failures"))
    items.append(_item("AC-2 / AC-6", "Separated roles", "pass", ", ".join(ROLES)))
    items.append(_item("AC-3 / AU-3", "Case number required for every search", "pass", "enforced by the API"))

    org = (cfg.get("organization") or "").strip()
    items.append(_item("AU-3", "Agency named in audit entries", "pass" if org and org != "Unnamed agency" else "warn",
                       org or "set `organization` in the configuration"))
    if system is not None:
        ok, bad = system.audit.verify()
        items.append(_item("AU-9", "Audit log integrity", "pass" if ok else "fail",
                           "hash chain intact" if ok else f"chain broken at entry {bad}"))
    else:
        items.append(_item("AU-9", "Audit log integrity", "pass", "append-only hash chain"))

    items.append(_item("SI-12", "Automatic deletion", "pass",
                       f"footage {retention['clip_days']} days, index {retention['index_days']} days, "
                       f"checked every {retention['purge_interval_minutes']} min"))
    items.append(_item("Hit confirmation", "Human review before any action", "pass", "matches wait for a reviewer"))
    faces = redaction["faces"]
    items.append(_item("PII minimisation", "Face and pedestrian blurring", "pass" if faces else "warn",
                       "faces" + (" and people" if redaction["people"] else "") + " blurred in stored images"
                       if faces else "face blurring is off"))

    bom_path = Path(cfg["supply_chain"]["bom_file"])
    if bom_path.exists():
        summary = summarize(check_bom(load_bom(bom_path)))
        status = "pass" if summary["compliant"] else ("fail" if summary["prohibited"] else "warn")
        items.append(_item("SR-3 / NDAA 889", "Hardware bill of materials", status,
                           f"{summary['ok']} cleared, {summary['unverified']} unverified, "
                           f"{summary['review']} to review, {summary['prohibited']} prohibited"))
    else:
        items.append(_item("SR-3 / NDAA 889", "Hardware bill of materials", "fail", "no bill of materials on file"))
    return items


def summary(items: list[dict]) -> dict:
    return {status: sum(1 for i in items if i["status"] == status) for status in ("pass", "warn", "fail")}
