"""Shared pytest fixtures."""

import time

import jwt
import pytest

from app import create_app

ALICE = {"login": "alice", "password": "Alice-Strong-Pass-1"}


@pytest.fixture()
def app(tmp_path):
    overrides = {
        "DATABASE": str(tmp_path / "test.db"),
        # >= 32 bytes: RFC 7518 minimum for HS256, keeps PyJWT quiet.
        "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
        "JWT_SECRET": "test-jwt-secret-0123456789abcdef0123456789abcdef",
        "BCRYPT_ROUNDS": 4,  # keep the suite fast; production uses 12
        "TESTING": True,
    }
    application = create_app(overrides=overrides)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_header(client):
    response = client.post("/auth/login", json=ALICE)
    assert response.status_code == 200, response.get_data(as_text=True)
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def make_token(app, **claim_overrides):
    """Helper to mint arbitrary tokens for negative tests."""
    now = int(time.time())
    payload = {
        "sub": "1",
        "username": "alice",
        "role": "user",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
    }
    payload.update(claim_overrides)
    return jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")
