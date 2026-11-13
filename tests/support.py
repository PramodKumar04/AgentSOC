"""Shared test helpers."""

from fastapi.testclient import TestClient

from agentsoc.api.app import create_app
from agentsoc.audit import set_actor
from agentsoc.auth.api import current_user
from agentsoc.auth.service import Principal, Role

TEST_CSRF = "test-csrf-token"


def signed_in_client(service, *, role: Role = Role.ANALYST,
                     username: str = "test-analyst", datasources=None) -> TestClient:
    """A client for an already signed-in user. Only the session lookup is replaced; CSRF
    checks and role checks still run. Authentication itself is tested in test_auth_api."""
    principal = Principal(user_id=1, username=username, role=role, csrf_token=TEST_CSRF)

    async def signed_in() -> Principal:
        set_actor(username)
        return principal

    app = create_app(service, serve_frontend=False, datasources=datasources)
    app.dependency_overrides[current_user] = signed_in
    return TestClient(app, headers={"X-CSRF-Token": TEST_CSRF})
