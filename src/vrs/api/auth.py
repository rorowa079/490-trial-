"""Accounts, roles and sign-in.

Roles (least privilege, NIST SP 800-53 AC-2 / AC-5 / AC-6)
---------------------------------------------------------
reviewer      watch the live view and review hotlist alerts. Nothing historical.
investigator  reviewer + search past sightings, request an unseal, hold a key share.
supervisor    investigator + legal holds, audit log, transparency reports.
auditor       read-only: audit log, reports, compliance posture. No vehicle data.
admin         accounts, purge, tamper unlock, legal holds, audit and reports, and
              may hold a key share. Cannot search or review: the person who runs
              the device is not the person who investigates with it.

Second factor (IA-2)
--------------------
* Security key (FIDO2 / WebAuthn): phishing-resistant. Once a user has enrolled
  one, it is the only second factor accepted for that account.
* Authenticator code (TOTP): accepted only until a key is enrolled. For roles
  listed in ``api.phishing_resistant_roles`` a TOTP sign-in yields a
  *restricted* session that can do one thing: enroll a security key.

Passwords are PBKDF2-HMAC-SHA256. Sessions live in RAM only, so a restart or a
tamper event signs everyone out.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time

from .. import crypto
from ..audit.audit_log import AuditLog
from ..db import Database

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "reviewer": frozenset({"live", "alerts"}),
    "investigator": frozenset({"live", "alerts", "search", "unseal", "custody"}),
    "supervisor": frozenset({"live", "alerts", "search", "unseal", "custody", "holds", "audit", "reports"}),
    "auditor": frozenset({"audit", "reports"}),
    "admin": frozenset({"live", "custody", "holds", "audit", "reports", "users", "purge", "unlock"}),
}
ROLES = tuple(ROLE_PERMISSIONS)
CHALLENGE_SECONDS = 300


class AuthError(Exception):
    pass


def totp_code(secret_b32: str, at: float | None = None, step: int = 30) -> str:
    """RFC 6238 time-based one-time password (6 digits, SHA-1, 30 s), as used by authenticator apps."""
    counter = int((at if at is not None else time.time()) // step)
    digest = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class Auth:
    def __init__(self, db: Database, audit: AuditLog, api_cfg: dict):
        self.db, self.audit = db, audit
        self.session_seconds = api_cfg["session_minutes"] * 60
        self.require_mfa = api_cfg["require_mfa"]
        self.max_failures = api_cfg["max_login_failures"]
        self.lockout_seconds = api_cfg["lockout_minutes"] * 60
        self.min_password = api_cfg.get("min_password_chars", 12)
        self.iterations = api_cfg.get("pbkdf2_iterations", 600_000)
        self.key_roles = set(api_cfg.get("phishing_resistant_roles") or [])
        webauthn_cfg = api_cfg.get("webauthn") or {}
        self.rp_id = webauthn_cfg.get("rp_id", "localhost")
        self.rp_name = webauthn_cfg.get("rp_name", "Vehicle Recognition System")
        self.origins = list(webauthn_cfg.get("origins") or ["http://localhost:8000"])
        self._sessions: dict[str, dict] = {}
        self._failures: dict[str, list[float]] = {}
        self._used_codes: dict[str, str] = {}          # username -> last accepted code (no replays)
        self._challenges: dict[str, dict] = {}         # pending WebAuthn ceremonies

    # ---------------------------------------------------------------- users

    def _check_password(self, password: str) -> None:
        if len(password) < self.min_password:
            raise AuthError(f"passwords need at least {self.min_password} characters")

    def create_user(self, username: str, password: str, role: str, actor: str = "system") -> str:
        """Create an account and return its TOTP secret (shown once, for the authenticator app)."""
        username = username.strip().lower()
        if not username.isalnum():
            raise AuthError("usernames are letters and digits only")
        if role not in ROLES:
            raise AuthError(f"role must be one of {', '.join(ROLES)}")
        self._check_password(password)
        if self.db.one("SELECT 1 FROM users WHERE username = ?", (username,)):
            raise AuthError("that username is taken")
        salt = secrets.token_bytes(16)
        totp_secret = base64.b32encode(secrets.token_bytes(20)).decode()
        self.db.execute(
            "INSERT INTO users (username, pw_salt, pw_hash, pw_iterations, role, totp_secret, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, salt, crypto.hash_password(password, salt, self.iterations), self.iterations, role,
             totp_secret, time.time()),
        )
        self.audit.record(actor, "user.created", {"username": username, "role": role})
        return totp_secret

    def update_user(self, username: str, actor: str, role: str | None = None, disabled: bool | None = None,
                    password: str | None = None) -> dict:
        """Change a role, disable or re-enable an account, or reset its password. Ends that user's sessions."""
        username = username.strip().lower()
        row = self.db.one("SELECT * FROM users WHERE username = ?", (username,))
        if row is None:
            raise AuthError("no such user")
        changes: dict = {}
        if role is not None and role != row["role"]:
            if role not in ROLES:
                raise AuthError(f"role must be one of {', '.join(ROLES)}")
            changes["role"] = role
        if disabled is not None and bool(disabled) != bool(row["disabled"]):
            changes["disabled"] = int(bool(disabled))
        losing_admin = row["role"] == "admin" and not row["disabled"] and (
            changes.get("role", "admin") != "admin" or changes.get("disabled"))
        if losing_admin and self.db.one(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0")["n"] <= 1:
            raise AuthError("this is the last active admin account")
        if password is not None:
            self._check_password(password)
            salt = secrets.token_bytes(16)
            self.db.execute("UPDATE users SET pw_salt = ?, pw_hash = ?, pw_iterations = ? WHERE username = ?",
                            (salt, crypto.hash_password(password, salt, self.iterations), self.iterations, username))
        for column, value in changes.items():
            self.db.execute(f"UPDATE users SET {column} = ? WHERE username = ?", (value, username))
        if changes or password is not None:
            self._end_sessions_of(username)
            self.audit.record(actor, "user.updated", {
                "username": username, **changes, **({"password_reset": True} if password is not None else {})})
        return self.get_user(username)

    def get_user(self, username: str) -> dict | None:
        row = self.db.one("SELECT username, role, disabled, created_ts FROM users WHERE username = ?", (username,))
        if row is None:
            return None
        return {**dict(row), "disabled": bool(row["disabled"]), "security_keys": len(self._keys_of(username))}

    def list_users(self) -> list[dict]:
        return [self.get_user(r["username"]) for r in self.db.query("SELECT username FROM users ORDER BY username")]

    @staticmethod
    def provisioning_uri(username: str, secret: str) -> str:
        return f"otpauth://totp/VehicleRecognition:{username}?secret={secret}&issuer=VehicleRecognition"

    # ------------------------------------------------------------- sign-in

    def _locked_out(self, username: str) -> bool:
        recent = [t for t in self._failures.get(username, []) if t > time.time() - self.lockout_seconds]
        self._failures[username] = recent
        return len(recent) >= self.max_failures

    def _fail(self, username: str, source: str | None, why: str) -> None:
        self._failures.setdefault(username, []).append(time.time())
        self.audit.record(username, "login.failed", {"source": source, "stage": why})

    def login(self, username: str, password: str, code: str | None = None, source: str | None = None) -> dict:
        """Password step. Returns a session, or a security-key challenge if the user has a key enrolled."""
        username = username.strip().lower()
        if self._locked_out(username):
            self.audit.record(username, "login.locked_out", {"source": source})
            raise AuthError("too many failed attempts; try again later")
        row = self.db.one("SELECT * FROM users WHERE username = ?", (username,))
        # Hash even for unknown users so response time does not reveal which names exist.
        salt = row["pw_salt"] if row else b"\0" * 16
        iterations = row["pw_iterations"] if row else self.iterations
        password_ok = hmac.compare_digest(crypto.hash_password(password, salt, iterations),
                                          row["pw_hash"] if row else b"\0" * 32)
        if not (row and password_ok and not row["disabled"]):
            self._fail(username, source, "password")
            raise AuthError("wrong username, password or code")

        keys = self._keys_of(username)
        if keys:                                           # a key is enrolled: nothing weaker is accepted
            challenge_id, options = self._begin_assertion(username, keys, source)
            return {"webauthn": options, "challenge_id": challenge_id}

        if self.require_mfa:
            now = time.time()
            valid = {totp_code(row["totp_secret"], now + drift) for drift in (-30, 0, 30)}
            if not (code and code in valid and self._used_codes.get(username) != code):
                self._fail(username, source, "code")
                raise AuthError("wrong username, password or code")
            self._used_codes[username] = code
        restricted = row["role"] in self.key_roles          # must enroll a key before doing anything else
        return self._start_session(row, "totp" if self.require_mfa else "none", restricted, source)

    def _start_session(self, row, mfa: str, restricted: bool, source: str | None) -> dict:
        self._failures.pop(row["username"], None)
        token = secrets.token_urlsafe(32)
        self._sessions[token] = {"username": row["username"], "role": row["role"], "mfa": mfa,
                                 "restricted": restricted, "expires": time.time() + self.session_seconds}
        self.audit.record(row["username"], "login.ok", {"mfa": mfa, "restricted": restricted, "source": source})
        return {"token": token, **self._describe(self._sessions[token])}

    @staticmethod
    def _describe(session: dict) -> dict:
        return {"username": session["username"], "role": session["role"], "mfa": session["mfa"],
                "restricted": session["restricted"],
                "permissions": [] if session["restricted"] else sorted(ROLE_PERMISSIONS[session["role"]])}

    def user_for(self, token: str | None) -> dict | None:
        session = self._sessions.get(token or "")
        if session is None:
            return None
        if session["expires"] < time.time():
            self._sessions.pop(token, None)
            return None
        session["expires"] = time.time() + self.session_seconds     # sliding expiry while active
        return self._describe(session)

    def logout(self, token: str) -> None:
        session = self._sessions.pop(token, None)
        if session:
            self.audit.record(session["username"], "logout", {})

    def _end_sessions_of(self, username: str) -> None:
        for token in [t for t, s in self._sessions.items() if s["username"] == username]:
            self._sessions.pop(token, None)

    def end_all_sessions(self) -> None:
        self._sessions.clear()
        self._challenges.clear()

    # ------------------------------------------------- security keys (FIDO2)

    def _keys_of(self, username: str) -> list:
        return self.db.query("SELECT * FROM webauthn_credentials WHERE username = ? ORDER BY created_ts", (username,))

    def list_keys(self, username: str) -> list[dict]:
        return [{"id": base64.urlsafe_b64encode(k["credential_id"]).rstrip(b"=").decode(), "name": k["name"],
                 "created_ts": k["created_ts"], "last_used_ts": k["last_used_ts"]} for k in self._keys_of(username)]

    def _new_challenge(self, kind: str, username: str, challenge: bytes) -> str:
        now = time.time()
        for stale in [c for c, v in self._challenges.items() if v["expires"] < now]:
            self._challenges.pop(stale, None)
        challenge_id = secrets.token_urlsafe(16)
        self._challenges[challenge_id] = {"kind": kind, "username": username, "challenge": challenge,
                                          "expires": now + CHALLENGE_SECONDS}
        return challenge_id

    def _take_challenge(self, challenge_id: str, kind: str, username: str | None = None) -> dict:
        pending = self._challenges.pop(challenge_id or "", None)
        if (pending is None or pending["kind"] != kind or pending["expires"] < time.time()
                or (username is not None and pending["username"] != username)):
            raise AuthError("that security-key request has expired; start again")
        return pending

    @staticmethod
    def _algorithms():
        from webauthn.helpers.cose import COSEAlgorithmIdentifier as Alg
        # ECDSA on NIST curves and RSA only. Every FIDO2 key supports ES256, and these verify under any
        # OpenSSL FIPS provider; Ed25519 (approved in FIPS 186-5) is not available in older validated modules.
        return [Alg.ECDSA_SHA_256, Alg.ECDSA_SHA_512, Alg.RSASSA_PKCS1_v1_5_SHA_256]

    def begin_key_enrollment(self, username: str) -> dict:
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                              ResidentKeyRequirement, UserVerificationRequirement)
        options = generate_registration_options(
            rp_id=self.rp_id, rp_name=self.rp_name, user_name=username,
            user_id=hashlib.sha256(username.encode()).digest()[:16],
            exclude_credentials=[PublicKeyCredentialDescriptor(id=k["credential_id"]) for k in self._keys_of(username)],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.PREFERRED),
            supported_pub_key_algs=self._algorithms(),
        )
        challenge_id = self._new_challenge("enroll", username, options.challenge)
        return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}

    def finish_key_enrollment(self, username: str, token: str | None, challenge_id: str, credential: dict,
                              name: str = "") -> dict:
        from webauthn import verify_registration_response
        from webauthn.helpers.exceptions import WebAuthnException
        pending = self._take_challenge(challenge_id, "enroll", username)
        try:
            verified = verify_registration_response(
                credential=credential, expected_challenge=pending["challenge"], expected_rp_id=self.rp_id,
                expected_origin=self.origins, require_user_verification=False,
                supported_pub_key_algs=self._algorithms())
        except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
            self.audit.record(username, "security_key.enroll_failed", {"error": str(exc)[:200]})
            raise AuthError("the security key could not be verified") from exc
        name = (name or "").strip()[:40] or f"Security key {len(self._keys_of(username)) + 1}"
        self.db.execute(
            "INSERT INTO webauthn_credentials (credential_id, username, public_key, sign_count, name, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (verified.credential_id, username, verified.credential_public_key, verified.sign_count, name, time.time()))
        self.audit.record(username, "security_key.enrolled", {"name": name})
        session = self._sessions.get(token or "")
        if session and session["username"] == username and session["restricted"]:
            session["restricted"], session["mfa"] = False, "security_key"   # proven in this session
        return {"keys": self.list_keys(username), **(self._describe(session) if session else {})}

    def remove_keys(self, username: str, actor: str, key_id: str | None = None) -> int:
        """Remove one key (``key_id``) or all of a user's keys (lost key: they fall back to TOTP and re-enroll)."""
        username = username.strip().lower()
        if key_id is None:
            removed = self.db.execute("DELETE FROM webauthn_credentials WHERE username = ?", (username,)).rowcount
        else:
            try:
                raw = base64.urlsafe_b64decode(key_id + "=" * (-len(key_id) % 4))
            except ValueError:
                raise AuthError("no such security key") from None
            removed = self.db.execute("DELETE FROM webauthn_credentials WHERE username = ? AND credential_id = ?",
                                      (username, raw)).rowcount
        if not removed:
            raise AuthError("no such security key")
        self._end_sessions_of(username)
        self.audit.record(actor, "security_key.removed", {"username": username, "count": removed})
        return removed

    def _begin_assertion(self, username: str, keys: list, source: str | None) -> tuple[str, dict]:
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
        options = generate_authentication_options(
            rp_id=self.rp_id, user_verification=UserVerificationRequirement.PREFERRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=k["credential_id"]) for k in keys])
        challenge_id = self._new_challenge("login", username, options.challenge)
        self._challenges[challenge_id]["source"] = source
        return challenge_id, json.loads(options_to_json(options))

    def login_with_key(self, challenge_id: str, credential: dict, source: str | None = None) -> dict:
        """Second step for accounts with a security key: verify the signed challenge and start the session."""
        from webauthn import verify_authentication_response
        from webauthn.helpers import base64url_to_bytes
        from webauthn.helpers.exceptions import WebAuthnException
        pending = self._take_challenge(challenge_id, "login")
        username = pending["username"]
        if self._locked_out(username):
            raise AuthError("too many failed attempts; try again later")
        try:
            raw_id = base64url_to_bytes(credential["id"])
            key = self.db.one("SELECT * FROM webauthn_credentials WHERE username = ? AND credential_id = ?",
                              (username, raw_id))
            if key is None:
                raise ValueError("unknown credential")
            verified = verify_authentication_response(
                credential=credential, expected_challenge=pending["challenge"], expected_rp_id=self.rp_id,
                expected_origin=self.origins, credential_public_key=key["public_key"],
                credential_current_sign_count=key["sign_count"], require_user_verification=False)
        except (WebAuthnException, ValueError, KeyError, TypeError):
            self._fail(username, source, "security_key")
            raise AuthError("the security key was not accepted") from None
        self.db.execute("UPDATE webauthn_credentials SET sign_count = ?, last_used_ts = ? WHERE credential_id = ?",
                        (verified.new_sign_count, time.time(), raw_id))
        row = self.db.one("SELECT * FROM users WHERE username = ?", (username,))
        if row is None or row["disabled"]:
            raise AuthError("this account is disabled")
        return self._start_session(row, "security_key", False, source)
