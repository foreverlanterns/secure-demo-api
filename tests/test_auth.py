"""Authentication behaviour: success, failure, enumeration, brute force."""

from tests.conftest import ALICE


def test_login_success_returns_bearer_token(client):
    response = client.post("/auth/login", json=ALICE)
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].count(".") == 2  # header.payload.signature
    assert body["user"]["username"] == "alice"


def test_login_wrong_password_is_rejected(client):
    response = client.post("/auth/login", json={"login": "alice", "password": "wrong-password"})
    assert response.status_code == 401


def test_login_unknown_user_gives_same_message(client):
    """No user enumeration: identical status and wording for both failures."""
    unknown = client.post("/auth/login", json={"login": "nobody", "password": "whatever-123"})
    wrong = client.post("/auth/login", json={"login": "alice", "password": "whatever-123"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json()["error"] == wrong.get_json()["error"]


def test_sql_injection_in_login_does_not_bypass_auth(client):
    """Classic payload must be treated as a literal username, not as SQL."""
    payloads = [
        {"login": "alice' OR '1'='1", "password": "anything"},
        {"login": "alice'--", "password": "anything"},
        {"login": "admin' OR 1=1 --", "password": "x"},
    ]
    for payload in payloads:
        response = client.post("/auth/login", json=payload)
        assert response.status_code == 401, payload


def test_brute_force_is_throttled(client):
    for _ in range(5):
        client.post("/auth/login", json={"login": "alice", "password": "bad-password"})
    blocked = client.post("/auth/login", json={"login": "alice", "password": "bad-password"})
    assert blocked.status_code == 429


def test_non_json_body_is_refused(client):
    response = client.post("/auth/login", data="login=alice&password=x")
    assert response.status_code == 415


def test_oversized_body_is_refused(client):
    big = {"login": "alice", "password": "A1!" * 20_000}
    response = client.post("/auth/login", json=big)
    assert response.status_code == 413


def test_register_enforces_password_policy(client):
    weak = client.post("/auth/register", json={"username": "carol", "password": "password"})
    assert weak.status_code == 400

    good = client.post("/auth/register", json={"username": "carol", "password": "Carol-Str0ng-Pass"})
    assert good.status_code == 201

    duplicate = client.post(
        "/auth/register", json={"username": "carol", "password": "Carol-Str0ng-Pass"}
    )
    assert duplicate.status_code == 409


def test_register_rejects_malicious_username(client):
    response = client.post(
        "/auth/register", json={"username": "<script>alert(1)</script>", "password": "Str0ng-Pass!"}
    )
    assert response.status_code == 400
