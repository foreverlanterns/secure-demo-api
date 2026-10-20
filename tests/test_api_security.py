"""Protected-resource behaviour: JWT enforcement, XSS escaping, data leakage."""

import time

import jwt

from tests.conftest import make_token


def test_data_requires_a_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401


def test_data_rejects_malformed_authorization_header(client):
    for header in (
        {"Authorization": "Basic YWxpY2U6cGFzcw=="},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Bearer a.b.c"},
    ):
        assert client.get("/api/data", headers=header).status_code == 401, header


def test_data_accepts_a_valid_token(client, auth_header):
    response = client.get("/api/data", headers=auth_header)
    assert response.status_code == 200
    body = response.get_json()
    assert body["total"] >= 2
    assert {"id", "username", "role", "created_at"} <= set(body["items"][0])


def test_expired_token_is_rejected(app, client):
    expired = make_token(app, iat=int(time.time()) - 120, exp=int(time.time()) - 60)
    response = client.get("/api/data", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_token_signed_with_another_key_is_rejected(app, client):
    forged = jwt.encode(
        {"sub": "1", "username": "alice", "exp": int(time.time()) + 60},
        "attacker-key-0123456789abcdef0123456789",
        algorithm="HS256",
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_alg_none_token_is_rejected(client):
    """Algorithm-confusion attack: an unsigned token must never be accepted."""
    unsigned = jwt.encode(
        {"sub": "1", "username": "alice", "exp": int(time.time()) + 60},
        None,
        algorithm="none",
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {unsigned}"})
    assert response.status_code == 401


def test_password_hash_never_leaves_the_service(client, auth_header):
    body = client.get("/api/data", headers=auth_header).get_data(as_text=True)
    assert "password_hash" not in body
    assert "$2b$" not in body  # bcrypt digest prefix


def test_xss_payload_is_escaped_in_responses(client, auth_header):
    payload = "<script>alert('xss')</script>"
    created = client.post(
        "/api/posts",
        headers=auth_header,
        json={"title": payload, "content": "img onerror=alert(1)"},
    )
    assert created.status_code == 201
    assert "<script>" not in created.get_data(as_text=True)

    feed = client.get("/api/posts")
    raw = feed.get_data(as_text=True)
    assert "<script>" not in raw
    assert "&lt;script&gt;" in raw


def test_post_creation_requires_authentication(client):
    response = client.post("/api/posts", json={"title": "t", "content": "c"})
    assert response.status_code == 401


def test_post_validation_rejects_empty_and_oversized_fields(client, auth_header):
    assert (
        client.post("/api/posts", headers=auth_header, json={"title": "", "content": "x"}).status_code
        == 400
    )
    assert (
        client.post(
            "/api/posts", headers=auth_header, json={"title": "t" * 500, "content": "x"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/posts", headers=auth_header, json={"title": "ok", "content": "x" * 2000}
        ).status_code
        == 400
    )


def test_control_characters_are_rejected(client, auth_header):
    response = client.post(
        "/api/posts", headers=auth_header, json={"title": "bad\x00title", "content": "x"}
    )
    assert response.status_code == 400


def test_pagination_is_clamped(client, auth_header):
    body = client.get("/api/data?per_page=100000", headers=auth_header).get_json()
    assert body["per_page"] == 50  # MAX_PAGE_SIZE

    body = client.get("/api/data?page=-5&per_page=abc", headers=auth_header).get_json()
    assert body["page"] == 1


def test_security_headers_are_present(client):
    response = client.get("/healthz")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
