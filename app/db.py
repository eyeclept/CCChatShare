"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    SQLite connection lifecycle and schema. WAL mode lets the Flask app
    (writer + readers) and the admin TUI (occasional writer) share one
    database file safely without a separate DB server.
"""
# Imports
import logging
import os
import sqlite3
import stat

from flask import current_app, g

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    slug              TEXT NOT NULL UNIQUE,
    title             TEXT NOT NULL,
    access_code_hash  TEXT NOT NULL,
    token_version     INTEGER NOT NULL DEFAULT 1,
    markdown          TEXT NOT NULL,
    tools_markdown    TEXT,
    created_at        TEXT NOT NULL,
    revoked           INTEGER NOT NULL DEFAULT 0,
    view_count        INTEGER NOT NULL DEFAULT 0,
    last_viewed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_chats_slug ON chats(slug);
"""


# Functions
def connect(db_path: str) -> sqlite3.Connection:
    """
    Input:      db_path -- filesystem path to the sqlite file
    Output:     sqlite3.Connection with WAL mode, row access by column name
    Details:
        Standalone connector for callers outside a Flask request context
        (the admin TUI). Flask request code should use get_db() instead so
        the connection is reused and closed per-request. After open, chmod
        the db file to 0600, WAL siblings to 0600, and the parent dir to
        0700. sqlite creates a new file as 0666 masked by umask. Host
        start paths skip the container umask 077. A chmod failure logs a
        warning and continues so a read-only bind mount does not crash.
        The parent chmod skips a sticky directory. A sticky bit marks a
        shared temp dir such as /tmp, and narrowing that to 0700 would
        lock every other user out of the whole directory.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        logger.warning("Could not chmod database file %s", db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    for suffix in ("-wal", "-shm"):
        sibling = db_path + suffix
        try:
            os.chmod(sibling, 0o600)
        except FileNotFoundError:
            logger.warning("WAL sibling missing, skipping chmod: %s", sibling)
        except OSError:
            logger.warning("Could not chmod WAL sibling %s", sibling)
    parent = os.path.dirname(db_path) or "."
    try:
        if os.stat(parent).st_mode & stat.S_ISVTX:
            logger.warning("Database directory %s is sticky, leaving its mode alone", parent)
        else:
            os.chmod(parent, 0o700)
    except OSError:
        logger.warning("Could not chmod database directory %s", parent)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def get_db() -> sqlite3.Connection:
    """
    Input:      None
    Output:     sqlite3.Connection scoped to the current Flask app context
    Details:
        Lazily opens one connection per request and caches it on flask.g.
    """
    if "db" not in g:
        g.db = connect(current_app.config["db_path"])
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    """
    Input:      _exc -- exception passed by Flask's teardown hook, unused
    Output:     None
    Details:
        Registered via app.teardown_appcontext; closes the per-request
        connection opened by get_db(), if one was opened.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """
    Input:      None
    Output:     None
    Details:
        Creates the chats table and index if they are absent. Safe to
        call on every app start. IF NOT EXISTS makes the call idempotent.
    """
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    logger.info("Schema ensured at %s", current_app.config["db_path"])
