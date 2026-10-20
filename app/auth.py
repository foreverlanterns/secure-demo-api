"""Authentication endpoints."""

from flask import Blueprint, current_app, jsonify, request

from .db import get_db
from .security import (
    client_ip,
    clean_str,
    create_token,
    dummy_verify,
    hash_password,
    safe_text,
    throttle,
    valid_password,
    valid_username,
    verify_password,
)

bp = Blueprint("auth", __name__, url_prefix="/auth")

# One message for every failure mode: no user enumeration through wording.
INVALID_CREDENTIALS = "invalid username or password"


def _json_body():
    """Return a dict body or None. Never trust the shape of user input."""
    if not request.is_json:
        return None
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


@bp.post("/login")
def login():
    """Authenticate a user and issue a short-lived JWT."""
    body = _json_body()
    if body is None:
        return jsonify(error="expected a JSON object body"), 415

    username = clean_str(body.get("login"), max_len=64)
    password = body.get("password")

    # Validate types/lengths before touching the database.
    if not username or not isinstance(password, str) or not (1 <= len(password) <= 128):
        return jsonify(error=INVALID_CREDENTIALS), 401

    ip = client_ip()
    if throttle.blocked(username, ip):
        return jsonify(error="too many failed attempts, try again later"), 429

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),  # parameter binding: the payload stays data, never SQL
    ).fetchone()

    if row is None:
        dummy_verify(password)  # equalise timing with the existing-user path
        throttle.record_failure(username, ip)
        return jsonify(error=INVALID_CREDENTIALS), 401

    if not verify_password(password, row["password_hash"]):
        throttle.record_failure(username, ip)
        return jsonify(error=INVALID_CREDENTIALS), 401

    throttle.reset(username, ip)
    token, ttl = create_token(row["id"], row["username"], row["role"])
    return (
        jsonify(
            access_token=token,
            token_type="Bearer",
            expires_in=ttl,
            user={"id": row["id"], "username": safe_text(row["username"]), "role": row["role"]},
        ),
        200,
    )


@bp.post("/register")
def register():
    """Create an account (bonus endpoint; demonstrates validation + hashing)."""
    body = _json_body()
    if body is None:
        return jsonify(error="expected a JSON object body"), 415

    username = body.get("username")
    password = body.get("password")

    if not valid_username(username):
        return jsonify(error="username must be 3-32 chars of letters, digits, . _ -"), 400
    if not valid_password(password, min_len=current_app.config["MIN_PASSWORD_LEN"]):
        return (
            jsonify(
                error="password must be 8-128 chars and mix at least 3 of: "
                "lowercase, uppercase, digits, symbols"
            ),
            400,
        )

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), "user"),
        )
        db.commit()
    except Exception as exc:  # sqlite3.IntegrityError: username taken
        if "UNIQUE" in str(exc).upper():
            return jsonify(error="username already exists"), 409
        raise

    return jsonify(message="user created", username=safe_text(username)), 201
