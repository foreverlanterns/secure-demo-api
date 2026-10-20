"""Security primitives: password hashing, JWT handling, output escaping,
input validation and a small in-process login throttle."""

import hashlib
import hmac
import re
import threading
import time
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request
from markupsafe import escape

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (adaptive, salted, deliberately slow)."""
    rounds = current_app.config["BCRYPT_ROUNDS"]
    digest = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))
    return digest.decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification; never raises on malformed hashes."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


_dummy_hash_cache: dict[int, bytes] = {}


def dummy_verify(password: str) -> None:
    """Burn the same CPU time as a real check when the user does not exist.

    Without this, an attacker can enumerate valid usernames by measuring
    response time (bcrypt check versus instant return).
    """
    rounds = current_app.config["BCRYPT_ROUNDS"]
    if rounds not in _dummy_hash_cache:
        _dummy_hash_cache[rounds] = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=rounds))
    bcrypt.checkpw(password.encode("utf-8"), _dummy_hash_cache[rounds])


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


def create_token(user_id: int, username: str, role: str) -> tuple[str, int]:
    """Issue a short-lived signed JWT. Returns (token, ttl_seconds)."""
    ttl = current_app.config["JWT_TTL_SECONDS"]
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    token = jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )
    return token, ttl


def decode_token(token: str) -> dict | None:
    """Verify signature, algorithm and time claims. Returns None when invalid.

    `algorithms` is pinned to the server-side choice, which blocks the classic
    "alg: none" / algorithm-confusion attacks.
    """
    try:
        return jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=[current_app.config["JWT_ALGORITHM"]],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError:
        return None


def token_required(view):
    """Middleware: every protected endpoint goes through here."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return jsonify(error="authentication required"), 401
        payload = decode_token(token.strip())
        if payload is None:
            return jsonify(error="invalid or expired token"), 401
        g.current_user = payload
        return view(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Output escaping (XSS)
# ---------------------------------------------------------------------------


def safe_text(value) -> str:
    """HTML-escape any string before it leaves the API.

    The API answers with JSON, but the same payloads get rendered by web
    front-ends and log viewers.  Escaping on output is the defence that keeps
    working regardless of which consumer is attached.
    """
    if value is None:
        return ""
    return str(escape(str(value)))


def safe_row(row, fields) -> dict:
    return {field: safe_text(row[field]) for field in fields}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_str(value, *, max_len: int) -> str | None:
    """Trim, reject control characters, enforce a hard length cap."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > max_len:
        return None
    if CONTROL_CHARS_RE.search(value):
        return None
    return value


def valid_username(value) -> bool:
    return isinstance(value, str) and bool(USERNAME_RE.match(value))


def valid_password(value, *, min_len: int) -> bool:
    """Length is the dominant factor; also require some variety."""
    if not isinstance(value, str) or len(value) < min_len or len(value) > 128:
        return False
    classes = sum(
        bool(re.search(pattern, value))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    return classes >= 3


# ---------------------------------------------------------------------------
# Login throttle (brute-force protection)
# ---------------------------------------------------------------------------


class LoginThrottle:
    """Fixed-window counter keyed by (username, client IP).

    In-process only: good enough for a single-node educational deployment.
    A real deployment would use Redis so that it survives restarts and scales.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[tuple[str, str], list[float]] = {}

    def _prune(self, key, window: float, now: float):
        stamps = [t for t in self._hits.get(key, []) if now - t < window]
        if stamps:
            self._hits[key] = stamps
        else:
            self._hits.pop(key, None)
        return stamps

    def blocked(self, username: str, ip: str) -> bool:
        window = current_app.config["LOGIN_WINDOW_SECONDS"]
        limit = current_app.config["LOGIN_MAX_ATTEMPTS"]
        key = (username.lower(), ip)
        now = time.time()
        with self._lock:
            return len(self._prune(key, window, now)) >= limit

    def record_failure(self, username: str, ip: str) -> None:
        key = (username.lower(), ip)
        now = time.time()
        with self._lock:
            self._hits.setdefault(key, []).append(now)
            # Bound memory: never let the table grow past 10k keys.
            if len(self._hits) > 10_000:
                self._hits.clear()

    def reset(self, username: str, ip: str) -> None:
        with self._lock:
            self._hits.pop((username.lower(), ip), None)


throttle = LoginThrottle()


def client_ip() -> str:
    """Best-effort client address (proxy headers are NOT trusted blindly)."""
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def sha256_fingerprint(value: str) -> str:
    """Keyed digest used only for logging identifiers, never for passwords."""
    key = current_app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
