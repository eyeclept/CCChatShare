"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Unit tests for app/models.py's Chat DAO against a throwaway in-memory
    sqlite connection, covering create/lookup/list, view recording,
    access-code regeneration (token_version bump), and revoke/delete.
"""
# Imports
import sqlite3

import pytest

from app.db import SCHEMA
from app.models import (
    create_chat,
    delete_chat,
    get_chat_by_slug,
    list_chats,
    record_view,
    regenerate_access_code,
    set_revoked,
)
from app.security import verify_access_code


@pytest.fixture
def conn():
    """In-memory sqlite connection with the app schema applied."""
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    yield connection
    connection.close()


def test_create_chat_returns_chat_and_plaintext_code(conn):
    chat, code = create_chat(conn, "Test Chat", "# hello", None)
    assert chat.title == "Test Chat"
    assert chat.markdown == "# hello"
    assert chat.tools_markdown is None
    assert chat.revoked is False
    assert chat.token_version == 1
    assert chat.view_count == 0
    assert len(code) == 8
    assert verify_access_code(code, chat.access_code_hash) is True


def test_create_chat_never_stores_plaintext_code(conn):
    _chat, code = create_chat(conn, "Test Chat", "# hello", None)
    row = conn.execute("SELECT access_code_hash FROM chats").fetchone()
    assert code not in row["access_code_hash"]


def test_get_chat_by_slug_roundtrip(conn):
    chat, _code = create_chat(conn, "Test Chat", "# hello", "tool log")
    fetched = get_chat_by_slug(conn, chat.slug)
    assert fetched is not None
    assert fetched.slug == chat.slug
    assert fetched.tools_markdown == "tool log"


def test_get_chat_by_slug_missing_returns_none(conn):
    assert get_chat_by_slug(conn, "does-not-exist") is None


def test_list_chats_newest_first(conn):
    chat_a, _ = create_chat(conn, "First", "a", None)
    conn.execute("UPDATE chats SET created_at = '2020-01-01T00:00:00' WHERE id = ?", (chat_a.id,))
    chat_b, _ = create_chat(conn, "Second", "b", None)
    conn.execute("UPDATE chats SET created_at = '2025-01-01T00:00:00' WHERE id = ?", (chat_b.id,))
    conn.commit()
    chats = list_chats(conn)
    assert [c.title for c in chats] == ["Second", "First"]


def test_record_view_increments_count_and_stamps_time(conn):
    chat, _code = create_chat(conn, "Test Chat", "# hello", None)
    assert chat.view_count == 0
    record_view(conn, chat.slug)
    record_view(conn, chat.slug)
    updated = get_chat_by_slug(conn, chat.slug)
    assert updated.view_count == 2
    assert updated.last_viewed_at is not None


def test_regenerate_access_code_bumps_token_version_and_invalidates_old_code(conn):
    chat, old_code = create_chat(conn, "Test Chat", "# hello", None)
    new_code = regenerate_access_code(conn, chat.slug)
    updated = get_chat_by_slug(conn, chat.slug)

    assert new_code is not None
    assert new_code != old_code
    assert updated.token_version == chat.token_version + 1
    assert verify_access_code(old_code, updated.access_code_hash) is False
    assert verify_access_code(new_code, updated.access_code_hash) is True


def test_regenerate_access_code_missing_slug_returns_none(conn):
    assert regenerate_access_code(conn, "does-not-exist") is None


def test_set_revoked_toggles_and_reports_success(conn):
    chat, _code = create_chat(conn, "Test Chat", "# hello", None)
    assert set_revoked(conn, chat.slug, True) is True
    assert get_chat_by_slug(conn, chat.slug).revoked is True
    assert set_revoked(conn, chat.slug, False) is True
    assert get_chat_by_slug(conn, chat.slug).revoked is False


def test_set_revoked_missing_slug_returns_false(conn):
    assert set_revoked(conn, "does-not-exist", True) is False


def test_delete_chat_removes_row(conn):
    chat, _code = create_chat(conn, "Test Chat", "# hello", None)
    assert delete_chat(conn, chat.slug) is True
    assert get_chat_by_slug(conn, chat.slug) is None


def test_delete_chat_missing_slug_returns_false(conn):
    assert delete_chat(conn, "does-not-exist") is False
