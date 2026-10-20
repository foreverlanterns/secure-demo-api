"""Application factory for the secure demo API.

Run locally:
    flask --app app run --debug
Production-style:
    waitress-serve --port 8000 app:create_app
"""

import logging

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from .config import Config
from . import db

LOG = logging.getLogger(__name__)


def create_app(config_object=Config, overrides: dict | None = None, init_database: bool = True):
    app = Flask(__name__)
    app.config.from_object(config_object)
    if overrides:
        app.config.update(overrides)

    db.init_app(app)
    if init_database:
        with app.app_context():
            db.init_db()

    from .auth import bp as auth_bp
    from .routes import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    _register_error_handlers(app)
    _register_security_headers(app)

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    return app


def _register_error_handlers(app: Flask) -> None:
    """Every error is JSON and none of them leaks internals."""

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException):
        return jsonify(error=exc.description, status=exc.code), exc.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc: Exception):
        # Log the traceback server-side, return an opaque message to the client.
        LOG.exception("unhandled error on %s %s", request.method, request.path)
        return jsonify(error="internal server error"), 500


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def set_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        # Only meaningful over TLS, ignored on plain HTTP.
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
