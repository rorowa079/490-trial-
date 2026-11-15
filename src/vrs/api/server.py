"""Operator API (FastAPI). Serves the dashboard and every action behind it.

Rules this file enforces:
* Every endpoint except sign-in needs a session, and each one names the
  permission it needs. Roles map to permissions in auth.py (AC-3, AC-6).
* A session that still owes a security-key enrollment can do nothing else.
* Every search is tied to a case reference and written to the audit log.
* A typed plate is hashed in RAM and compared as a hash; the plaintext is
  never stored, logged or echoed back.
* No endpoint returns footage except an alert's review snapshot and frames
  from a completed multi-person unseal.
* Every export (audit log, report package) is itself logged.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import compliance
from ..audit import reports
from ..config import REPO_ROOT
from ..evidence.vault import UnsealError
from ..matching.alert_queue import ReviewError
from ..privacy.key_manager import KeysUnavailable
from ..privacy.scrubber import to_buffer
from ..system import System
from .auth import ROLES, AuthError


class LoginBody(BaseModel):
    username: str
    password: str
    code: str | None = None


class KeyLoginBody(BaseModel):
    challenge_id: str
    credential: dict


class KeyEnrollBody(BaseModel):
    challenge_id: str
    credential: dict
    name: str = ""


class ReviewBody(BaseModel):
    decision: str
    justification: str = ""
    observations: dict = Field(default_factory=dict)


class SearchBody(BaseModel):
    case_ref: str
    plate: str | None = None
    color: str | None = None
    make: str | None = None
    model: str | None = None
    body_type: str | None = None
    direction: str | None = None
    ts_from: float | None = None
    ts_to: float | None = None


class UnsealBody(BaseModel):
    clip_id: str
    case_ref: str
    reason: str


class ShareBody(BaseModel):
    share: str


class HoldBody(BaseModel):
    case_ref: str
    ts_start: float
    ts_end: float
    hold_days: int = 30


class UserBody(BaseModel):
    username: str
    password: str
    role: str = "reviewer"


class UserUpdateBody(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None


class UnlockBody(BaseModel):
    inspection_note: str


_CSP = ("default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'")


def create_app(system: System) -> FastAPI:
    app = FastAPI(title="Vehicle Recognition System", docs_url=None, redoc_url=None, openapi_url=None)
    tls_on = system.cfg["api"]["tls"]["enabled"]

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = _CSP
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if tls_on:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def source_of(request: Request) -> str | None:
        return request.client.host if request.client else None

    def session(authorization: str | None = Header(default=None)) -> dict:
        """Any signed-in user, including one who must still enroll a security key."""
        token = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
        user = system.auth.user_for(token)
        if user is None:
            raise HTTPException(401, "sign in required")
        user["token"] = token
        return user

    def need(*permissions: str):
        """A fully signed-in user holding at least one of ``permissions`` (any signed-in user if none given)."""
        def dependency(user: dict = Depends(session)) -> dict:
            if user["restricted"]:
                raise HTTPException(403, "enroll a security key to finish signing in")
            if permissions and not set(permissions) & set(user["permissions"]):
                raise HTTPException(403, "your role does not allow this")
            return user
        return dependency

    # ----------------------------------------------------------------- auth

    @app.post("/api/login")
    def login(body: LoginBody, request: Request):
        try:
            return system.auth.login(body.username, body.password, body.code, source_of(request))
        except AuthError as exc:
            raise HTTPException(401, str(exc))

    @app.post("/api/login/security-key")
    def login_key(body: KeyLoginBody, request: Request):
        try:
            return system.auth.login_with_key(body.challenge_id, body.credential, source_of(request))
        except AuthError as exc:
            raise HTTPException(401, str(exc))

    @app.get("/api/public")
    def public():
        """The only unauthenticated read: what the login form needs to know."""
        return {"mfa_required": system.auth.require_mfa, "locked": system.fail_closed.locked,
                "organization": system.cfg.get("organization", "")}

    @app.post("/api/logout")
    def logout(user: dict = Depends(session)):
        system.auth.logout(user["token"])
        return {"ok": True}

    @app.get("/api/me")
    def me(user: dict = Depends(session)):
        return {k: user[k] for k in ("username", "role", "permissions", "restricted", "mfa")} | {
            "security_keys": len(system.auth.list_keys(user["username"])),
            "key_required": user["role"] in system.auth.key_roles}

    # -------------------------------------------------- account: security keys

    @app.get("/api/account/keys")
    def keys(user: dict = Depends(session)):
        return system.auth.list_keys(user["username"])

    @app.post("/api/account/keys/begin")
    def key_begin(user: dict = Depends(session)):
        return system.auth.begin_key_enrollment(user["username"])

    @app.post("/api/account/keys/finish")
    def key_finish(body: KeyEnrollBody, user: dict = Depends(session)):
        try:
            return system.auth.finish_key_enrollment(user["username"], user["token"], body.challenge_id,
                                                     body.credential, body.name)
        except AuthError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/account/keys/{key_id}")
    def key_remove(key_id: str, user: dict = Depends(need())):
        try:
            system.auth.remove_keys(user["username"], user["username"], key_id)
        except AuthError as exc:
            raise HTTPException(404, str(exc))
        return {"ok": True, "note": "you have been signed out"}

    # ------------------------------------------------------------ dashboard

    @app.get("/api/status")
    def status(user: dict = Depends(need())):
        return system.status()

    @app.get("/api/live.jpg")
    def live(user: dict = Depends(need("live"))):
        jpeg = system.pipeline.live_jpeg()
        if jpeg is None:
            raise HTTPException(503, "video offline")
        return Response(jpeg, media_type="image/jpeg")

    # --------------------------------------------------------- review queue

    @app.get("/api/alerts")
    def alerts(status: str | None = "pending", user: dict = Depends(need("alerts"))):
        return system.alerts.list(None if status in (None, "", "all") else status)

    @app.get("/api/alerts/{alert_id}")
    def alert(alert_id: int, user: dict = Depends(need("alerts"))):
        found = system.alerts.get(alert_id)
        if found is None:
            raise HTTPException(404, "no such alert")
        return found

    @app.get("/api/alerts/{alert_id}/snapshot")
    def alert_snapshot(alert_id: int, user: dict = Depends(need("alerts"))):
        try:
            jpeg = system.alerts.snapshot(alert_id)
        except KeysUnavailable:
            raise HTTPException(423, "device is locked")
        if jpeg is None:
            raise HTTPException(404, "no snapshot (already reviewed or expired)")
        system.audit.record(user["username"], "alert.snapshot_viewed", {"alert_id": alert_id})
        return Response(jpeg, media_type="image/jpeg")

    @app.post("/api/alerts/{alert_id}/review")
    def review(alert_id: int, body: ReviewBody, user: dict = Depends(need("alerts"))):
        try:
            return system.alerts.review(alert_id, user["username"], body.decision, body.justification,
                                        body.observations)
        except ReviewError as exc:
            raise HTTPException(400, str(exc))

    # --------------------------------------------------------------- search

    @app.post("/api/search")
    def search(body: SearchBody, request: Request, user: dict = Depends(need("search"))):
        case_ref = body.case_ref.strip()
        if not case_ref:
            raise HTTPException(400, "a case number is required for every search")
        where, params, filters = [], [], {}
        plate_searched = False
        if body.plate and body.plate.strip():
            try:
                plate_hash = system.hasher.hash_plate(to_buffer(body.plate))     # hashed in RAM, input zeroed
            except KeysUnavailable:
                raise HTTPException(423, "device is locked")
            if plate_hash is None:
                raise HTTPException(400, "that does not look like a license plate")
            where.append("plate_hash = ?")
            params.append(plate_hash)
            plate_searched = True
        for column in ("color", "make", "model", "body_type", "direction"):
            value = getattr(body, column)
            if value and value.strip():
                where.append(f"LOWER({column}) = ?")
                params.append(value.strip().lower())
                filters[column] = value.strip().lower()
        if body.ts_from is not None:
            where.append("ts >= ?"); params.append(body.ts_from); filters["ts_from"] = body.ts_from
        if body.ts_to is not None:
            where.append("ts <= ?"); params.append(body.ts_to); filters["ts_to"] = body.ts_to
        if not where:
            raise HTTPException(400, "add at least one filter")
        rows = system.db.query(
            "SELECT id, ts, camera_id, color, body_type, make, model, damage, direction, speed_kph, clip_id"
            f" FROM sightings WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT 200", tuple(params))
        system.audit.record(user["username"], "search.plate_hashed" if plate_searched else "search.attributes", {
            "case_ref": case_ref, "filters": filters, "plate": "hashed" if plate_searched else None,
            "results": len(rows), "source": source_of(request)})
        return {"results": [dict(r) for r in rows]}

    # ---------------------------------------------------------------- audit

    @app.get("/api/audit")
    def audit(limit: int = 200, action: str | None = None, actor: str | None = None,
              user: dict = Depends(need("audit"))):
        return {"entries": system.audit.entries(min(limit, 1000), action, actor)}

    @app.get("/api/audit/verify")
    def audit_verify(user: dict = Depends(need("audit"))):
        ok, bad_seq = system.audit.verify()
        return {"ok": ok, "first_bad_seq": bad_seq, "head": system.audit.head()}

    def _period(day_from: str | None, day_to: str | None) -> tuple[str, str]:
        today = datetime.now(timezone.utc).date()
        return day_from or (today - timedelta(days=29)).isoformat(), day_to or today.isoformat()

    @app.get("/api/audit/export")
    def audit_export(day_from: str | None = None, day_to: str | None = None, user: dict = Depends(need("audit"))):
        day_from, day_to = _period(day_from, day_to)
        try:
            ts_from, ts_to = reports._day_bounds(day_from, day_to)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        entries = system.audit.entries(None, ts_from=ts_from, ts_to=ts_to)
        system.audit.record(user["username"], "audit.exported", {"from": day_from, "to": day_to,
                                                                 "entries": len(entries)})
        return Response(reports.audit_csv(entries), media_type="text/csv", headers={
            "Content-Disposition": f'attachment; filename="audit_{day_from}_{day_to}.csv"'})

    # -------------------------------------------------------------- reports

    @app.get("/api/reports/transparency")
    def transparency(day_from: str | None = None, day_to: str | None = None, user: dict = Depends(need("reports"))):
        try:
            return reports.transparency_report(system, *_period(day_from, day_to), user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/reports/export")
    def report_export(day_from: str | None = None, day_to: str | None = None, user: dict = Depends(need("reports"))):
        day_from, day_to = _period(day_from, day_to)
        try:
            package = reports.export_package(system, day_from, day_to, user["username"],
                                             compliance.posture(system.cfg, system))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        system.audit.record(user["username"], "report.exported", {"from": day_from, "to": day_to})
        return Response(package, media_type="application/zip", headers={
            "Content-Disposition": f'attachment; filename="audit_package_{day_from}_{day_to}.zip"'})

    @app.get("/api/compliance")
    def compliance_posture(user: dict = Depends(need("reports"))):
        items = compliance.posture(system.cfg, system)
        return {"items": items, "summary": compliance.summary(items), "checked_ts": time.time()}

    # --------------------------------------------------------------- unseal

    @app.get("/api/unseal")
    def unseal_list(user: dict = Depends(need("unseal", "custody"))):
        return system.unseal.list()

    @app.post("/api/unseal")
    def unseal_request(body: UnsealBody, user: dict = Depends(need("unseal"))):
        try:
            return system.unseal.get(system.unseal.request(body.clip_id, body.case_ref, body.reason, user["username"]))
        except UnsealError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/unseal/{request_id}")
    def unseal_get(request_id: int, user: dict = Depends(need("unseal", "custody"))):
        info = system.unseal.get(request_id)
        if info is None:
            raise HTTPException(404, "no such unseal request")
        return info

    @app.post("/api/unseal/{request_id}/share")
    def unseal_share(request_id: int, body: ShareBody, user: dict = Depends(need("custody"))):
        try:
            return system.unseal.submit_share(request_id, user["username"], body.share)
        except (UnsealError, ValueError) as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/unseal/{request_id}/frames/{index}")
    def unseal_frame(request_id: int, index: int, user: dict = Depends(need("unseal", "custody"))):
        try:
            jpeg = system.unseal.frame(request_id, index, user["username"])
        except UnsealError as exc:
            raise HTTPException(403, str(exc))
        return Response(jpeg, media_type="image/jpeg")

    # ---------------------------------------------------------- legal holds

    @app.get("/api/holds")
    def holds(user: dict = Depends(need("holds", "unseal", "audit"))):
        return system.holds.active()

    @app.post("/api/holds")
    def hold_create(body: HoldBody, user: dict = Depends(need("holds"))):
        try:
            return {"id": system.holds.create(body.case_ref, body.ts_start, body.ts_end, body.hold_days,
                                              user["username"])}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/holds/{hold_id}")
    def hold_release(hold_id: int, user: dict = Depends(need("holds"))):
        system.holds.release(hold_id, user["username"])
        return {"ok": True}

    # ---------------------------------------------------------------- admin

    @app.post("/api/admin/purge")
    def purge_now(user: dict = Depends(need("purge"))):
        system.audit.record(user["username"], "purge.manual", {})
        return system.purge.run()

    @app.get("/api/admin/users")
    def users(user: dict = Depends(need("users"))):
        return {"users": system.auth.list_users(), "roles": list(ROLES)}

    @app.post("/api/admin/users")
    def user_create(body: UserBody, user: dict = Depends(need("users"))):
        try:
            secret = system.auth.create_user(body.username, body.password, body.role, user["username"])
        except AuthError as exc:
            raise HTTPException(400, str(exc))
        return {"username": body.username.strip().lower(), "totp_secret": secret,
                "totp_uri": system.auth.provisioning_uri(body.username.strip().lower(), secret)}

    @app.patch("/api/admin/users/{username}")
    def user_update(username: str, body: UserUpdateBody, user: dict = Depends(need("users"))):
        try:
            return system.auth.update_user(username, user["username"], body.role, body.disabled, body.password)
        except AuthError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/admin/users/{username}/keys")
    def user_keys_reset(username: str, user: dict = Depends(need("users"))):
        """A lost security key: remove the user's keys so they can sign in with a code and enroll a new one."""
        try:
            return {"removed": system.auth.remove_keys(username, user["username"])}
        except AuthError as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/admin/unlock")
    def unlock(body: UnlockBody, user: dict = Depends(need("unlock"))):
        try:
            system.fail_closed.unlock(user["username"], body.inspection_note)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"ok": True, "note": "restart the service to reload keys and resume processing"}

    # The built dashboard, if present (npm run build in dashboard/).
    dist = Path(REPO_ROOT) / "dashboard" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")

    return app
