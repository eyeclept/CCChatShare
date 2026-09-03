"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Shared pytest fixtures: a fully configured Flask app + test client
    backed by a temp sqlite file, with env vars set before create_app()
    reads them.
"""
# Imports
import pytest

from app import create_app
from app.limiter import limiter


@pytest.fixture
def app(tmp_path, monkeypatch):
    """A CCChatShare app instance backed by a throwaway sqlite file."""
    db_path = tmp_path / "ccchatshare.db"
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("CCCHATSHARE_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("CCCHATSHARE_DB_PATH", str(db_path))

    flask_app = create_app()
    flask_app.config.update(TESTING=True)

    # The limiter is a module-level singleton; reset any counters left over
    # from a previous test so lockout tests start from a clean slate.
    with flask_app.app_context():
        limiter.reset()

    yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()
