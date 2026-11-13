"""Authentication and role enforcement through the real HTTP layer (no overrides)."""

import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from agentsoc.api.app import create_app
from agentsoc.api.service import Service
from agentsoc.auth.api import COOKIE, CSRF_HEADER
from agentsoc.auth.service import AuthError, AuthService, Principal, Role
from agentsoc.config import PROJECT_ROOT, get_settings

ADMIN_PW = "Admin-pass-for-tests-1"
ANALYST_PW = "Analyst-pass-for-tests-2"
PUBLIC = {"/api/health", "/api/auth/status", "/api/auth/login"}


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)

    def __call__(self):
        return self.now


@pytest.fixture
def env(tmp_path):
    svc = Service(root=tmp_path, provider_factory=lambda: (None, "LLM disabled for test"))
    clock = Clock()
    auth = AuthService(svc.app_db, svc.audit, get_settings(), clock=clock)
    auth.create_user("admin1", ADMIN_PW, Role.ADMIN, actor="cli")
    auth.create_user("analyst1", ANALYST_PW, Role.ANALYST, actor="cli")
    app = create_app(svc, serve_frontend=False, auth=auth)
    return app, svc, auth, clock


def client(app):
    return TestClient(app)


def sign_in(app, username="analyst1", password=ANALYST_PW):
    c = client(app)
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    c.headers[CSRF_HEADER] = r.json()["csrf_token"]
    return c, r


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x1", path)


class TestEveryRouteNeedsASession:
    def test_all_non_public_routes_refuse_anonymous_requests(self, env):
        app, *_ = env
        c = client(app)
        checked = 0
        for path, operations in app.openapi()["paths"].items():
            if path in PUBLIC:
                continue
            for method in operations:
                r = c.request(method.upper(), concrete(path), json={})
                assert r.status_code == 401, (method, path, r.status_code)
                checked += 1
        assert checked >= 20

    def test_forged_or_unknown_cookie_is_refused(self, env):
        app, *_ = env
        c = client(app)
        c.cookies.set(COOKIE, "not-a-real-session")
        assert c.get("/api/overview").status_code == 401

    def test_health_stays_public(self, env):
        app, *_ = env
        assert client(app).get("/api/health").status_code == 200


class TestSignIn:
    def test_cookie_is_httponly_and_strict(self, env):
        app, *_ = env
        _, r = sign_in(app)
        cookie = r.headers["set-cookie"].lower()
        assert f"{COOKIE}=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        assert "path=/" in cookie
        body = r.json()
        assert body["user"] == {"username": "analyst1", "role": "analyst"}
        assert COOKIE not in json.dumps(body) and len(body["csrf_token"]) > 20

    def test_signed_in_user_can_read(self, env):
        app, *_ = env
        c, _ = sign_in(app)
        assert c.get("/api/overview").status_code == 200
        assert c.get("/api/auth/session").json()["user"]["username"] == "analyst1"

    @pytest.mark.parametrize(("username", "password"), [
        ("analyst1", "wrong-password-123"), ("nobody", "wrong-password-123")])
    def test_failures_look_identical(self, env, username, password):
        app, *_ = env
        r = client(app).post("/api/auth/login", json={"username": username, "password": password})
        assert r.status_code == 401 and r.json() == {"detail": "Incorrect username or password."}
        assert COOKIE not in r.headers.get("set-cookie", "")

    def test_form_posts_are_refused(self, env):
        app, *_ = env
        r = client(app).post("/api/auth/login", data={"username": "analyst1",
                                                      "password": ANALYST_PW})
        assert r.status_code == 415

    def test_json_without_a_json_content_type_is_refused(self, env):
        app, *_ = env
        body = json.dumps({"username": "analyst1", "password": ANALYST_PW})
        r = client(app).post("/api/auth/login", content=body,
                             headers={"Content-Type": "text/plain"})
        assert r.status_code == 415
        assert COOKIE not in r.headers.get("set-cookie", "")

    def test_account_locks_after_repeated_failures(self, env):
        app, _, _, clock = env
        c = client(app)
        for _ in range(get_settings().login_max_failures):
            c.post("/api/auth/login", json={"username": "analyst1", "password": "bad-guess-1234"})
        locked = c.post("/api/auth/login", json={"username": "analyst1", "password": ANALYST_PW})
        assert locked.status_code == 401
        clock.now += timedelta(minutes=get_settings().login_lockout_minutes + 1)
        sign_in(app)

    def test_failures_from_one_address_are_rate_limited(self, env):
        app, *_ = env
        c = client(app)
        codes = [c.post("/api/auth/login", json={"username": f"user{i}", "password": "x" * 12}
                        ).status_code for i in range(25)]
        assert codes[:20] == [401] * 20 and set(codes[20:]) == {429}

    def test_disabled_account_cannot_sign_in(self, env):
        app, *_ = env
        admin, _ = sign_in(app, "admin1", ADMIN_PW)
        assert admin.patch("/api/admin/users/analyst1", json={"disabled": True}).status_code == 200
        r = client(app).post("/api/auth/login", json={"username": "analyst1",
                                                      "password": ANALYST_PW})
        assert r.status_code == 401


class TestSessions:
    def test_idle_timeout(self, env):
        app, _, _, clock = env
        c, _ = sign_in(app)
        clock.now += timedelta(minutes=get_settings().session_idle_minutes - 1)
        assert c.get("/api/overview").status_code == 200  # activity extends the session
        clock.now += timedelta(minutes=get_settings().session_idle_minutes + 1)
        assert c.get("/api/overview").status_code == 401

    def test_absolute_lifetime(self, env):
        app, _, _, clock = env
        c, _ = sign_in(app)
        step = timedelta(minutes=get_settings().session_idle_minutes - 1)
        end = clock.now + timedelta(hours=get_settings().session_max_hours)
        while clock.now + step < end:
            clock.now += step
            assert c.get("/api/auth/session").status_code == 200
        clock.now = end
        assert c.get("/api/auth/session").status_code == 401

    def test_logout_ends_the_session(self, env):
        app, *_ = env
        c, _ = sign_in(app)
        assert c.post("/api/auth/logout").status_code == 204
        c2 = client(app)
        c2.cookies = c.cookies
        assert c.get("/api/overview").status_code == 401

    def test_tokens_and_passwords_are_not_stored_in_clear(self, env):
        app, svc, *_ = env
        _, r = sign_in(app)
        token = re.search(f"{COOKIE}=([^;]+)", r.headers["set-cookie"])[1]
        raw = svc.app_db.read_bytes() + b"".join(
            p.read_bytes() for p in svc.app_db.parent.glob("agentsoc.db*"))
        assert token.encode() not in raw
        assert ANALYST_PW.encode() not in raw and ADMIN_PW.encode() not in raw

    def test_role_change_ends_existing_sessions(self, env):
        app, *_ = env
        analyst, _ = sign_in(app)
        admin, _ = sign_in(app, "admin1", ADMIN_PW)
        admin.patch("/api/admin/users/analyst1", json={"role": "admin"})
        assert analyst.get("/api/overview").status_code == 401


class TestCsrf:
    @pytest.mark.parametrize("header", [None, "wrong-token"])
    def test_state_changes_need_the_session_token(self, env, header):
        app, *_ = env
        c, _ = sign_in(app)
        if header is None:
            del c.headers[CSRF_HEADER]
        else:
            c.headers[CSRF_HEADER] = header
        for method, path in [("POST", "/api/incidents/INC-00002/investigate"),
                             ("POST", "/api/auth/logout"), ("POST", "/api/auth/password")]:
            assert c.request(method, path, json={}).status_code == 403, path

    def test_investigation_with_token_is_recorded_under_the_user(self, env):
        app, svc, *_ = env
        c, _ = sign_in(app)
        assert c.post("/api/incidents/INC-00002/investigate").status_code == 200
        entry = next(e for e in reversed(svc.audit.read())
                     if e.event_type.startswith("investigation."))
        assert entry.actor == "analyst1"


class TestRoles:
    def test_analyst_cannot_use_admin_routes(self, env):
        app, *_ = env
        c, _ = sign_in(app)
        assert c.get("/api/admin/users").status_code == 403
        assert c.post("/api/admin/users", json={"username": "evil", "password": "x" * 14,
                                                "role": "admin"}).status_code == 403
        assert c.patch("/api/admin/users/admin1", json={"disabled": True}).status_code == 403

    def test_admin_manages_users(self, env):
        app, *_ = env
        c, _ = sign_in(app, "admin1", ADMIN_PW)
        r = c.post("/api/admin/users", json={"username": "newbie", "password": "Fresh-start-77",
                                             "role": "analyst"})
        assert r.status_code == 201
        for secret in ("Fresh-start-77", "password_hash", "scrypt"):
            assert secret not in r.text
        assert {u["username"] for u in c.get("/api/admin/users").json()} == {
            "admin1", "analyst1", "newbie"}
        assert c.post("/api/admin/users/newbie/password",
                      json={"new_password": "Another-pass-88"}).status_code == 204
        sign_in(app, "newbie", "Another-pass-88")

    @pytest.mark.parametrize("body", [{"username": "AB", "password": "Valid-pass-123",
                                       "role": "analyst"},
                                      {"username": "okname", "password": "short",
                                       "role": "analyst"},
                                      {"username": "analyst1", "password": "Valid-pass-123",
                                       "role": "analyst"}])
    def test_invalid_new_users_are_refused(self, env, body):
        app, *_ = env
        c, _ = sign_in(app, "admin1", ADMIN_PW)
        assert c.post("/api/admin/users", json=body).status_code in (400, 422)

    def test_admin_cannot_change_themselves(self, env):
        app, *_ = env
        c, _ = sign_in(app, "admin1", ADMIN_PW)
        assert c.patch("/api/admin/users/admin1", json={"role": "analyst"}).status_code == 400

    def test_last_admin_cannot_be_removed(self, env):
        app, _, auth, _ = env
        auth.create_user("admin2", "Second-admin-pass-9", Role.ADMIN, actor="cli")
        c, _ = sign_in(app, "admin2", "Second-admin-pass-9")
        assert c.patch("/api/admin/users/admin1", json={"disabled": True}).status_code == 200
        c1, _ = sign_in(app, "admin2", "Second-admin-pass-9")
        # admin2 is now the only active admin and cannot demote itself; nobody else can either.
        assert c1.patch("/api/admin/users/admin2", json={"role": "analyst"}).status_code == 400

    def test_last_admin_guard_holds_for_any_actor(self, env):
        # Over the API the self-change rule fires first; an out-of-band actor (CLI) must still
        # be unable to remove the only active administrator.
        _, _, auth, _ = env
        cli = Principal(user_id=-1, username="cli", role=Role.ADMIN, csrf_token="")
        with pytest.raises(AuthError, match="administrator must remain"):
            auth.update_user("admin1", disabled=True, actor=cli)
        with pytest.raises(AuthError, match="administrator must remain"):
            auth.update_user("admin1", role=Role.ANALYST, actor=cli)
        assert [u.role for u in auth.list_users() if u.username == "admin1"] == [Role.ADMIN]

    def test_own_password_change_requires_the_current_one(self, env):
        app, *_ = env
        c, _ = sign_in(app)
        bad = c.post("/api/auth/password", json={"current_password": "wrong-one-12345",
                                                 "new_password": "Brand-new-pass-12"})
        assert bad.status_code == 400
        ok = c.post("/api/auth/password", json={"current_password": ANALYST_PW,
                                                "new_password": "Brand-new-pass-12"})
        assert ok.status_code == 200
        sign_in(app, "analyst1", "Brand-new-pass-12")


class TestAuditAndSecrecy:
    def test_account_events_are_audited_without_secrets(self, env):
        app, svc, *_ = env
        admin, _ = sign_in(app, "admin1", ADMIN_PW)
        admin.post("/api/admin/users", json={"username": "newbie", "password": "Fresh-start-77",
                                             "role": "analyst"})
        client(app).post("/api/auth/login",
                         json={"username": "newbie", "password": "bad-guess-9999"})
        client(app).post("/api/auth/login", json={"username": "Fresh-start-77", "password": "x"})
        admin.post("/api/auth/logout")
        types = [(e.event_type, e.actor, e.subject_id) for e in svc.audit.read()]
        assert ("user.created", "admin1", "newbie") in types
        assert ("auth.login.succeeded", "admin1", "admin1") in types
        assert ("auth.login.failed", "anonymous", "newbie") in types
        assert ("auth.logout", "admin1", "admin1") in types
        text = svc.activity_path.read_text(encoding="utf-8")
        # A password typed into the username box is never recorded.
        for secret in (ADMIN_PW, "Fresh-start-77", "bad-guess-9999"):
            assert secret not in text

    def test_security_headers(self, env):
        app, *_ = env
        r = client(app).get("/api/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["cache-control"] == "no-store"

    def test_setup_status(self, tmp_path):
        svc = Service(root=tmp_path, provider_factory=lambda: (None, "off"))
        app = create_app(svc, serve_frontend=False)
        assert client(app).get("/api/auth/status").json() == {"setup_required": True}


def test_cli_creates_the_first_admin_without_echoing_the_password(tmp_path):
    db = tmp_path / "app.db"
    env = {**os.environ, "NEW_PW": "Cli-created-pass-42", "PYTHONPATH": str(PROJECT_ROOT / "src")}
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "manage_users.py"), "--db", str(db),
           "--activity-log", str(tmp_path / "a.jsonl"), "create", "boss", "--role", "admin",
           "--password-env", "NEW_PW"]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)  # noqa: S603
    assert result.returncode == 0, result.stderr
    assert "Cli-created-pass-42" not in result.stdout + result.stderr
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT role FROM users WHERE username='boss'").fetchone() == ("admin",)
