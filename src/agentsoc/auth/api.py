"""HTTP layer for authentication: cookies, CSRF, role checks and account endpoints.

* The session token travels only in an HttpOnly, SameSite=Strict cookie.
* Every state-changing request needs the session's CSRF token in `X-CSRF-Token`. The
  browser keeps that token in memory and fetches it again from `/api/auth/session`.
* Sign-in accepts only `application/json`, which a cross-site HTML form cannot send.
* Failed sign-ins are also limited per client address, against password spraying.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections import deque
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from agentsoc.audit import set_actor
from agentsoc.auth.passwords import PasswordPolicyError
from agentsoc.auth.service import AuthError, AuthService, LoginFailedError, Principal, Role

COOKIE = "agentsoc_session"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class FailureLimiter:
    """At most `limit` failed sign-ins per client address in `window` seconds."""

    def __init__(self, limit: int = 20, window: float = 300) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str) -> deque[float]:
        hits = self._hits.setdefault(key, deque())
        cutoff = time.monotonic() - self.window
        while hits and hits[0] < cutoff:
            hits.popleft()
        return hits

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key)) >= self.limit

    def record(self, key: str) -> None:
        with self._lock:
            self._recent(key).append(time.monotonic())


def _auth(request: Request) -> AuthService:
    return request.app.state.auth


async def current_user(request: Request) -> Principal:
    """Any signed-in, active user. Binds the audit actor for the rest of the request."""
    token = request.cookies.get(COOKIE)
    principal = await run_in_threadpool(_auth(request).authenticate, token)
    if principal is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    set_actor(principal.username)
    request.state.principal = principal
    return principal


CurrentUser = Annotated[Principal, Depends(current_user)]


async def require_admin(principal: CurrentUser) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return principal


async def require_csrf(request: Request, principal: CurrentUser) -> None:
    if request.method in UNSAFE:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent, principal.csrf_token):
            raise HTTPException(status_code=403, detail="The request could not be verified. "
                                                        "Reload the page and try again.")


AdminUser = Annotated[Principal, Depends(require_admin)]


class UserView(BaseModel):
    username: str
    role: Role


class SessionView(BaseModel):
    user: UserView
    csrf_token: str


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class NewUserBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: Role


class UserPatchBody(BaseModel):
    role: Role | None = None
    disabled: bool | None = None


class ResetBody(BaseModel):
    new_password: str = Field(min_length=1, max_length=256)


class AdminUserView(BaseModel):
    username: str
    role: Role
    disabled: bool
    locked: bool
    created_at: str
    password_changed_at: str


class AuthStatus(BaseModel):
    setup_required: bool


def require_json(request: Request) -> None:
    """Runs before body validation, so a cross-site form post is refused as such (415)."""
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(status_code=415, detail="Sign-in requires a JSON request.")


def _set_cookie(response: Response, token: str, secure: bool, max_age: int) -> None:
    response.set_cookie(COOKIE, token, max_age=max_age, httponly=True, secure=secure,
                        samesite="strict", path="/")


def _refused(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def auth_router(cookie_secure: bool, session_seconds: int) -> APIRouter:
    router = APIRouter(prefix="/api")
    limiter = FailureLimiter()

    @router.get("/auth/status", response_model=AuthStatus)
    def status(request: Request) -> AuthStatus:
        return AuthStatus(setup_required=_auth(request).user_count() == 0)

    @router.post("/auth/login", response_model=SessionView, dependencies=[Depends(require_json)])
    def login(body: LoginBody, request: Request, response: Response) -> SessionView:
        client = request.client.host if request.client else "unknown"
        if limiter.blocked(client):
            raise HTTPException(status_code=429,
                                detail="Too many failed sign-in attempts. Try again later.")
        try:
            token, principal = _auth(request).login(body.username, body.password)
        except LoginFailedError as exc:
            limiter.record(client)
            raise HTTPException(status_code=401, detail=str(exc)) from None
        _set_cookie(response, token, cookie_secure, session_seconds)
        return SessionView(user=UserView(username=principal.username, role=principal.role),
                           csrf_token=principal.csrf_token)

    @router.get("/auth/session", response_model=SessionView)
    def session(principal: CurrentUser) -> SessionView:
        return SessionView(user=UserView(username=principal.username, role=principal.role),
                           csrf_token=principal.csrf_token)

    @router.post("/auth/logout", status_code=204, dependencies=[Depends(require_csrf)])
    def logout(request: Request, response: Response,
               principal: CurrentUser) -> None:
        _auth(request).logout(request.cookies.get(COOKIE, ""), principal)
        response.delete_cookie(COOKIE, path="/", httponly=True, secure=cookie_secure,
                               samesite="strict")

    @router.post("/auth/password", response_model=SessionView,
                 dependencies=[Depends(require_csrf)])
    def change_password(body: PasswordBody, request: Request, response: Response,
                        principal: CurrentUser) -> SessionView:
        try:
            token = _auth(request).change_own_password(principal, body.current_password,
                                                       body.new_password)
        except (AuthError, PasswordPolicyError) as exc:
            raise _refused(exc) from None
        _set_cookie(response, token, cookie_secure, session_seconds)
        fresh = _auth(request).authenticate(token)
        return SessionView(user=UserView(username=fresh.username, role=fresh.role),
                           csrf_token=fresh.csrf_token)

    @router.get("/admin/users", response_model=list[AdminUserView],
                dependencies=[Depends(require_admin)])
    def users(request: Request) -> list[AdminUserView]:
        return [AdminUserView(**u.__dict__) for u in _auth(request).list_users()]

    @router.post("/admin/users", response_model=AdminUserView, status_code=201,
                 dependencies=[Depends(require_csrf)])
    def create_user(body: NewUserBody, request: Request,
                    admin: AdminUser) -> AdminUserView:
        try:
            info = _auth(request).create_user(body.username, body.password, body.role,
                                              actor=admin.username)
        except (AuthError, PasswordPolicyError) as exc:
            raise _refused(exc) from None
        return AdminUserView(**info.__dict__)

    @router.patch("/admin/users/{username}", response_model=AdminUserView,
                  dependencies=[Depends(require_csrf)])
    def update_user(username: str, body: UserPatchBody, request: Request,
                    admin: AdminUser) -> AdminUserView:
        try:
            info = _auth(request).update_user(username, role=body.role, disabled=body.disabled,
                                              actor=admin)
        except AuthError as exc:
            raise _refused(exc) from None
        return AdminUserView(**info.__dict__)

    @router.post("/admin/users/{username}/password", status_code=204,
                 dependencies=[Depends(require_csrf)])
    def reset_password(username: str, body: ResetBody, request: Request,
                       admin: AdminUser) -> None:
        try:
            _auth(request).reset_password(username, body.new_password, actor=admin.username)
        except (AuthError, PasswordPolicyError) as exc:
            raise _refused(exc) from None

    return router

