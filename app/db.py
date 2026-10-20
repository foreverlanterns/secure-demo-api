"""SQLite access layer.

Every statement in this project uses parameter binding ("?" placeholders).
User input is *never* interpolated into SQL text, which removes the whole
SQL-injection class (OWASP A03:2021 - Injection).
"""

import sqlite3

import click
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    content    TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
"""


def get_db() -> sqlite3.Connection:
    """Return one connection per request, configured safely."""
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=5,
        )
        g.db.row_factory = sqlite3.Row
        # Enforce declared foreign keys (SQLite defaults to off).
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and, in debug/demo mode, seed two demo accounts."""
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()

    from .security import hash_password

    seed = (("alice", "Alice-Strong-Pass-1", "user"), ("bob", "Bob-Strong-Pass-1", "user"))
    for username, password, role in seed:
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            continue
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
        user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        db.execute(
            "INSERT INTO posts (author_id, title, content) VALUES (?, ?, ?)",
            (user_id, f"{username}'s first post", "Hello from the secure demo API."),
        )
    db.commit()


@click.command("init-db")
def init_db_command():
    """Flask CLI: `flask --app app init-db`."""
    init_db()
    click.echo("Initialised the database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
