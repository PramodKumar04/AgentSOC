"""Local accounts, roles and sign-in sessions.

* Passwords are scrypt hashes. Session tokens are random and stored only as SHA-256
  hashes, so a copy of the database cannot be used to sign in.
* Sessions end after an idle period and after an absolute lifetime.
* Repeated failures lock the account for a while; the caller cannot tell a wrong
  password from an unknown, locked or disabled account.
* Every change to accounts is written to the audit log. Passwords and tokens never are.
* There is always at least one active administrator.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from agentsoc.audit import AuditEventType, AuditLog
from agentsoc.auth.passwords import check_policy, dummy_hash, hash_password, verify_password
from agentsoc.config import Settings
from agentsoc.exceptions import AgentSOCError
from agentsoc.store import appdb

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"


class AuthError(AgentSOCError):
    """A request that is refused; the message is safe to show."""


class LoginFailedError(AuthError):
    pass


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    role: Role
    csrf_token: str

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN


@dataclass(frozen=True)
class UserInfo:
    username: str
    role: Role
    disabled: bool
    locked: bool
    created_at: str
    password_changed_at: str


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


class AuthService:
    def __init__(self, db_path: str | Path, audit: AuditLog, settings: Settings,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.db_path = Path(db_path)
        self.audit = audit
        self.idle = timedelta(minutes=settings.session_idle_minutes)
        self.lifetime = timedelta(hours=settings.session_max_hours)
        self.max_failures = settings.login_max_failures
        self.lockout = timedelta(minutes=settings.login_lockout_minutes)
        self.now = clock or (lambda: datetime.now(UTC))
        appdb.migrate(self.db_path)

    # ------------------------------------------------------------------ accounts
    def user_count(self) -> int:
        with appdb.reader(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def _info(self, row) -> UserInfo:
        locked = bool(row["locked_until"]) and datetime.fromisoformat(
            row["locked_until"]) > self.now()
        return UserInfo(row["username"], Role(row["role"]), bool(row["disabled"]), locked,
                        row["created_at"], row["password_changed_at"])

    def list_users(self) -> list[UserInfo]:
        with appdb.reader(self.db_path) as conn:
            return [self._info(r) for r in conn.execute("SELECT * FROM users ORDER BY username")]

    def create_user(self, username: str, password: str, role: Role, *, actor: str) -> UserInfo:
        if not USERNAME_PATTERN.match(username):
            raise AuthError("Usernames are 3-32 characters: lower-case letters, digits, '.', "
                            "'_' or '-', starting with a letter or digit.")
        check_policy(password, username)
        now = _iso(self.now())
        try:
            with appdb.transaction(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, created_at, updated_at, "
                    "password_changed_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (username, hash_password(password), Role(role).value, now, now, now))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise AuthError("That username is already taken.") from None
            raise
        self.audit.append(AuditEventType.USER_CREATED, username, {"role": Role(role).value},
                          actor=actor)
        return next(u for u in self.list_users() if u.username == username)

    def _row(self, conn, username: str):
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            raise AuthError("No such user.")
        return row

    def _remaining_admins(self, conn, excluding: int) -> int:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?",
            (excluding,)).fetchone()[0]

    def update_user(self, username: str, *, role: Role | None = None,
                    disabled: bool | None = None, actor: Principal) -> UserInfo:
        if username == actor.username:
            raise AuthError("You cannot change your own role or disable your own account.")
        events = []
        with appdb.transaction(self.db_path) as conn:
            row = self._row(conn, username)
            losing_admin = row["role"] == "admin" and not row["disabled"] and (
                (role is not None and role is not Role.ADMIN) or disabled)
            if losing_admin and self._remaining_admins(conn, row["id"]) == 0:
                raise AuthError("At least one active administrator must remain.")
            now = _iso(self.now())
            if role is not None and role.value != row["role"]:
                conn.execute("UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
                             (role.value, now, row["id"]))
                events.append((AuditEventType.USER_ROLE_CHANGED, {"role": role.value}))
            if disabled is not None and disabled != bool(row["disabled"]):
                conn.execute("UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?",
                             (int(disabled), now, row["id"]))
                events.append((AuditEventType.USER_DISABLED if disabled
                               else AuditEventType.USER_ENABLED, {}))
            if events:  # a changed role or status takes effect immediately
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
        for kind, details in events:
            self.audit.append(kind, username, details, actor=actor.username)
        return next(u for u in self.list_users() if u.username == username)

    def _set_password(self, username: str, password: str) -> None:
        check_policy(password, username)
        now = _iso(self.now())
        with appdb.transaction(self.db_path) as conn:
            row = self._row(conn, username)
            conn.execute(
                "UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ?, "
                "failed_logins = 0, locked_until = NULL WHERE id = ?",
                (hash_password(password), now, now, row["id"]))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))

    def reset_password(self, username: str, password: str, *, actor: str) -> None:
        """Administrator reset: ends every session of that user."""
        self._set_password(username, password)
        self.audit.append(AuditEventType.USER_PASSWORD_RESET, username, actor=actor)

    def change_own_password(self, principal: Principal, current: str, new: str) -> str:
        """Returns a fresh session token: the old sessions are all ended."""
        with appdb.reader(self.db_path) as conn:
            row = self._row(conn, principal.username)
        if not verify_password(current, row["password_hash"]):
            raise AuthError("The current password is incorrect.")
        self._set_password(principal.username, new)
        self.audit.append(AuditEventType.PASSWORD_CHANGED, principal.username,
                          actor=principal.username)
        return self._open_session(row["id"])[0]

    # ------------------------------------------------------------------ sessions
    def _open_session(self, user_id: int) -> tuple[str, str]:
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = self.now()
        with appdb.transaction(self.db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(now),))
            conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
                (_token_hash(token), user_id, csrf, _iso(now), _iso(now),
                 _iso(now + self.lifetime)))
        return token, csrf

    def login(self, username: str, password: str) -> tuple[str, Principal]:
        """Returns (session token, principal) or raises LoginFailedError with a generic message."""
        now = self.now()
        with appdb.reader(self.db_path) as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            verify_password(password, dummy_hash())  # same work as a real check
            self.audit.append(AuditEventType.LOGIN_FAILED, "unknown-account",
                              {"reason": "unknown_user"}, actor="anonymous")
            raise LoginFailedError("Incorrect username or password.")
        locked = row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > now
        valid = verify_password(password, row["password_hash"])
        reason = ("locked" if locked else "disabled" if row["disabled"]
                  else None if valid else "bad_password")
        if reason:
            if reason == "bad_password":
                failures = row["failed_logins"] + 1
                lock_until = _iso(now + self.lockout) if failures >= self.max_failures else None
                with appdb.transaction(self.db_path) as conn:
                    conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? "
                                 "WHERE id = ?", (0 if lock_until else failures, lock_until,
                                                  row["id"]))
                if lock_until:
                    reason = "bad_password_locked"
            self.audit.append(AuditEventType.LOGIN_FAILED, username, {"reason": reason},
                              actor="anonymous")
            raise LoginFailedError("Incorrect username or password.")
        with appdb.transaction(self.db_path) as conn:
            conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
                         (row["id"],))
        token, csrf = self._open_session(row["id"])
        self.audit.append(AuditEventType.LOGIN_SUCCEEDED, username, actor=username)
        return token, Principal(row["id"], username, Role(row["role"]), csrf)

    def authenticate(self, token: str | None) -> Principal | None:
        if not token or len(token) > 128:
            return None
        now = self.now()
        with appdb.transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT s.*, u.username, u.role, u.disabled FROM sessions s "
                "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (_token_hash(token),)).fetchone()
            if row is None:
                return None
            expired = (datetime.fromisoformat(row["expires_at"]) <= now
                       or datetime.fromisoformat(row["last_seen"]) + self.idle <= now)
            if expired or row["disabled"]:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
                return None
            conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                         (_iso(now), row["token_hash"]))
        return Principal(row["user_id"], row["username"], Role(row["role"]), row["csrf_token"])

    def logout(self, token: str, principal: Principal) -> None:
        with appdb.transaction(self.db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
        self.audit.append(AuditEventType.LOGOUT, principal.username, actor=principal.username)
