"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Flask application factory for CCChatShare. Wires config, the sqlite
    connection lifecycle, rate limiting, and the public/admin blueprints.
"""
# Imports
import logging

from flask import Flask

from app.config import load_config
from app.db import close_db, init_db
from app.limiter import limiter

logger = logging.getLogger(__name__)


# Functions
def create_app() -> Flask:
    """
    Input:      None
    Output:     configured Flask application instance
    Details:
        Loads config from environment, initializes the sqlite schema,
        attaches the rate limiter, and registers the public and admin
        blueprints. Called once by wsgi.py (gunicorn) or the dev server.
    """
    app = Flask(__name__)
    cfg = load_config()
    app.config.update(cfg.__dict__)
    # Flask and extensions expect the canonical uppercase keys.
    # This codebase's own modules read the lowercase dataclass fields above.
    app.config["SECRET_KEY"] = cfg.secret_key
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_content_length

    with app.app_context():
        init_db()

    app.teardown_appcontext(close_db)
    limiter.init_app(app)

    from app.routes_public import public_bp
    from app.routes_admin import admin_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)

    @app.after_request
    def _set_security_headers(response):
        """
        Input:      response -- the outgoing Flask response
        Output:     the same response, with defensive headers added
        Details:
            Chat bodies can quote arbitrary web or tool content
            (see app/render.py). A remote image URL that survives
            sanitization must not act as a read-receipt beacon.
            Another site must not embed the unlocked page.
            Strict-Transport-Security tells browsers to use HTTPS
            for this host for one year, including subdomains.
        """
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "frame-ancestors 'none'",
        )
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        return response

    logger.info("CCChatShare app created (db=%s)", cfg.db_path)
    return app
