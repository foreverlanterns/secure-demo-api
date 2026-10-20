"""Application configuration.

No secret is hard-coded: secrets come from the environment.  When an
environment variable is absent (local development), an ephemeral random secret
is generated so that nothing guessable ever ships in the repository.
"""

import os
import secrets

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def _ephemeral_or_env(name: str) -> str:
    """Return the env var, or a random per-process value for local runs."""
    value = os.environ.get(name)
    if value:
        return value
    return secrets.token_urlsafe(48)


class Config:
    # --- Flask ---
    SECRET_KEY = _ephemeral_or_env("SECRET_KEY")
    MAX_CONTENT_LENGTH = 16 * 1024  # reject request bodies > 16 KB (DoS guard)

    # --- JWT ---
    JWT_SECRET = _ephemeral_or_env("JWT_SECRET")
    JWT_ALGORITHM = "HS256"  # fixed server-side; never taken from the token
    JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", "900"))  # 15 min

    # --- Password hashing ---
    BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

    # --- Database ---
    DATABASE = os.environ.get("DATABASE", os.path.join(BASE_DIR, "app.db"))

    # --- Brute-force protection ---
    LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_WINDOW_SECONDS = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))

    # --- API limits ---
    MAX_PAGE_SIZE = 50
    MAX_TITLE_LEN = 200
    MAX_CONTENT_LEN = 1000
    MAX_USERNAME_LEN = 32
    MIN_PASSWORD_LEN = 8
