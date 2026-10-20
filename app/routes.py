"""Data endpoints (all of them require a valid JWT)."""

from flask import Blueprint, current_app, g, jsonify, request

from .db import get_db
from .security import clean_str, safe_text, token_required

bp = Blueprint("api", __name__, url_prefix="/api")


def _page_args():
    """Clamp pagination input so a client cannot ask for the whole table."""

    def _int(name, default, low, high):
        raw = request.args.get(name, default)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
        return max(low, min(high, value))

    page = _int("page", 1, 1, 10_000)
    per_page = _int("per_page", 20, 1, current_app.config["MAX_PAGE_SIZE"])
    return page, per_page


@bp.get("/data")
@token_required
def data():
    """Return the user directory. Requires authentication."""
    page, per_page = _page_args()
    offset = (page - 1) * per_page
    db = get_db()
    rows = db.execute(
        # Only the columns a client needs; password_hash never leaves the DB.
        "SELECT id, username, role, created_at FROM users ORDER BY id LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()

    items = [
        {
            "id": row["id"],
            "username": safe_text(row["username"]),
            "role": safe_text(row["role"]),
            "created_at": safe_text(row["created_at"]),
        }
        for row in rows
    ]
    total = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    return jsonify(page=page, per_page=per_page, total=total, items=items), 200


@bp.get("/posts")
def list_posts():
    """Public read-only feed (demonstrates output escaping on third-party text)."""
    page, per_page = _page_args()
    offset = (page - 1) * per_page
    db = get_db()
    rows = db.execute(
        """
        SELECT p.id, p.title, p.content, p.created_at, u.username AS author
        FROM posts AS p
        JOIN users AS u ON u.id = p.author_id
        ORDER BY p.id DESC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()

    items = [
        {
            "id": row["id"],
            "title": safe_text(row["title"]),
            "content": safe_text(row["content"]),
            "author": safe_text(row["author"]),
            "created_at": safe_text(row["created_at"]),
        }
        for row in rows
    ]
    return jsonify(page=page, per_page=per_page, items=items), 200


@bp.post("/posts")
@token_required
def create_post():
    """Third endpoint (own design): create a post owned by the caller."""
    if not request.is_json:
        return jsonify(error="expected a JSON object body"), 415
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="expected a JSON object body"), 400

    title = clean_str(body.get("title"), max_len=current_app.config["MAX_TITLE_LEN"])
    content = clean_str(body.get("content"), max_len=current_app.config["MAX_CONTENT_LEN"])
    if title is None:
        return jsonify(error="title is required (1-200 printable chars)"), 400
    if content is None:
        return jsonify(error="content is required (1-1000 printable chars)"), 400

    # Ownership comes from the verified token, never from the request body.
    author_id = int(g.current_user["sub"])
    db = get_db()
    cur = db.execute(
        "INSERT INTO posts (author_id, title, content) VALUES (?, ?, ?)",
        (author_id, title, content),
    )
    db.commit()

    return (
        jsonify(
            id=cur.lastrowid,
            title=safe_text(title),
            content=safe_text(content),
            author=safe_text(g.current_user["username"]),
        ),
        201,
    )


@bp.get("/me")
@token_required
def me():
    """Convenience endpoint used by the tests to prove the token payload."""
    claims = g.current_user
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, created_at FROM users WHERE id = ?",
        (int(claims["sub"]),),
    ).fetchone()
    if row is None:
        return jsonify(error="user no longer exists"), 401
    return (
        jsonify(
            id=row["id"],
            username=safe_text(row["username"]),
            role=safe_text(row["role"]),
            created_at=safe_text(row["created_at"]),
        ),
        200,
    )
