"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Environment-driven configuration for CCChatShare. Secrets come from
    the process environment. The container entrypoint loads them from a
    generated secrets file. SECRET_KEY and CCCHATSHARE_ADMIN_TOKEN are
    required. A missing secret raises RuntimeError. The process does not
    fall back to an insecure default.
"""
# Imports
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Globals
DEFAULT_DB_PATH = "/data/ccchatshare.db"
COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 180  # 180 days
MAX_CONTENT_LENGTH_BYTES = 4 * 1024 * 1024  # 4 MB


# Classes
@dataclass(frozen=True)
class Config:
    secret_key: str
    admin_api_token: str
    db_path: str
    host: str
    port: int
    cookie_max_age: int = COOKIE_MAX_AGE_SECONDS
    max_content_length: int = MAX_CONTENT_LENGTH_BYTES
    cookie_secure: bool = True


# Functions
def load_config() -> Config:
    """
    Input:      None (reads os.environ)
    Output:     Config
    Details:
        SECRET_KEY and CCCHATSHARE_ADMIN_TOKEN are required. The process
        raises RuntimeError rather than start with a blank or predictable
        secret. CCCHATSHARE_DB_PATH and PORT have container defaults.
        CCCHATSHARE_HOST defaults to 127.0.0.1 so the Flask fallback
        listens on loopback unless an operator sets a wider bind.
    """
    secret_key = os.environ.get("SECRET_KEY", "").strip()
    admin_token = os.environ.get("CCCHATSHARE_ADMIN_TOKEN", "").strip()
    if not secret_key or not admin_token:
        raise RuntimeError(
            "SECRET_KEY and CCCHATSHARE_ADMIN_TOKEN must be set in the environment "
            "(see deploy/entrypoint.sh — they are generated on first container start)"
        )

    db_path = os.environ.get("CCCHATSHARE_DB_PATH", DEFAULT_DB_PATH)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    return Config(
        secret_key=secret_key,
        admin_api_token=admin_token,
        db_path=db_path,
        host=os.environ.get("CCCHATSHARE_HOST", "127.0.0.1"),
        port=int(os.environ.get("CCCHATSHARE_PORT", "8080")),
        cookie_secure=os.environ.get("CCCHATSHARE_COOKIE_INSECURE", "") != "1",
    )
