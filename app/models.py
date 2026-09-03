"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Chat data access layer. Every function takes an explicit sqlite3
    connection so it works identically from a Flask request (app/db.py's
    get_db()) and from the standalone admin TUI (app/db.py's connect()).
"""
# Imports
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from app.security import generate_access_code, generate_slug, hash_access_code

logger = logging.getLogger(__name__)

# Globals
MAX_SLUG_ATTEMPTS = 5


# Classes
@dataclass(frozen=True)
class Chat:
    id: int
    slug: str
    title: str
    access_code_hash: str
    token_version: int
    markdown: str
    tools_markdown: str | None
    created_at: str
    revoked: bool
    view_count: int
    last_viewed_at: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Chat":
        return cls(
            id=row["id"],
            slug=row["slug"],
            title=row["title"],
            access_code_hash=row["access_code_hash"],
            token_version=row["token_version"],
            markdown=row["markdown"],
            tools_markdown=row["tools_markdown"],
            created_at=row["created_at"],
            revoked=bool(row["revoked"]),
            view_count=row["view_count"],
            last_viewed_at=row["last_viewed_at"],
        )


# Functions
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_chat(
    conn: sqlite3.Connection, title: str, markdown: str, tools_markdown: str | None
) -> tuple[Chat, str]:
    """
    Input:      conn -- open sqlite connection
                title -- display title for the chat
                markdown -- rendered chat body (from export_chat.py)
                tools_markdown -- optional linked tool-call file (--full mode)
    Output:     (Chat, plaintext_access_code)
    Details:
        The function returns the plaintext access code once. Only the hash
        is stored. Slug collisions are retried. A collision is rare at
        10 characters and a 31-symbol alphabet, but the code still checks.
    """
    code = generate_access_code()
    code_hash = hash_access_code(code)
    created_at = _now()

    for _ in range(MAX_SLUG_ATTEMPTS):
        slug = generate_slug()
        try:
            cur = conn.execute(
                """
                INSERT INTO chats (slug, title, access_code_hash, markdown, tools_markdown, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (slug, title, code_hash, markdown, tools_markdown, created_at),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM chats WHERE id = ?", (cur.lastrowid,)).fetchone()
            return Chat.from_row(row), code
        except sqlite3.IntegrityError:
            logger.warning("Slug collision generating chat %r, retrying", slug)
            continue
    raise RuntimeError("Failed to allocate a unique slug after retries")


def get_chat_by_slug(conn: sqlite3.Connection, slug: str) -> Chat | None:
    """
    Input:      conn -- open sqlite connection
                slug -- chat slug
    Output:     Chat or None if no chat has that slug
    """
    row = conn.execute("SELECT * FROM chats WHERE slug = ?", (slug,)).fetchone()
    return Chat.from_row(row) if row else None


class ChatGate:
    """
    Small Chat view for the auth gate. It holds the revoked check and
    cookie verification fields. It excludes markdown, tools_markdown,
    view_count, and last_viewed_at.
    Fetching those large columns before auth was a timing side-channel.
    A revoked chat and a missing chat then differed by response time.
    This projection keeps the pre-auth query cheap and the same shape for any chat size.
    """

    __slots__ = ("id", "slug", "title", "access_code_hash", "token_version", "revoked")

    def __init__(self, id, slug, title, access_code_hash, token_version, revoked):  # noqa: A002
        self.id = id
        self.slug = slug
        self.title = title
        self.access_code_hash = access_code_hash
        self.token_version = token_version
        self.revoked = revoked


def get_chat_gate(conn: sqlite3.Connection, slug: str) -> "ChatGate | None":
    """
    Input:      conn -- open sqlite connection
                slug -- chat slug
    Output:     ChatGate or None if no chat has that slug
    Details:
        Use this for the revoked/auth check on every request; call
        get_chat_by_slug() only after that check passes and the full
        body is actually needed.
    """
    row = conn.execute(
        "SELECT id, slug, title, access_code_hash, token_version, revoked FROM chats WHERE slug = ?",
        (slug,),
    ).fetchone()
    if row is None:
        return None
    return ChatGate(
        id=row["id"],
        slug=row["slug"],
        title=row["title"],
        access_code_hash=row["access_code_hash"],
        token_version=row["token_version"],
        revoked=bool(row["revoked"]),
    )



def list_chats(conn: sqlite3.Connection) -> list[Chat]:
    """
    Input:      conn -- open sqlite connection
    Output:     all chats, newest first
    """
    rows = conn.execute("SELECT * FROM chats ORDER BY created_at DESC").fetchall()
    return [Chat.from_row(row) for row in rows]


def record_view(conn: sqlite3.Connection, slug: str) -> None:
    """
    Input:      conn -- open sqlite connection
                slug -- chat that was just successfully viewed
    Output:     None
    Details:
        Increments view_count and stamps last_viewed_at. Called once per
        unlocked page load (fresh unlock or cookie auto-login).
    """
    conn.execute(
        "UPDATE chats SET view_count = view_count + 1, last_viewed_at = ? WHERE slug = ?",
        (_now(), slug),
    )
    conn.commit()


def regenerate_access_code(conn: sqlite3.Connection, slug: str) -> str | None:
    """
    Input:      conn -- open sqlite connection
                slug -- chat to rotate
    Output:     new plaintext access code, or None if the slug does not exist
    Details:
        Bumps token_version. That invalidates every cookie issued under
        the old code (see security.verify_auth_cookie). A returning
        browser with the old cookie goes back to the unlock form.
    """
    new_code = generate_access_code()
    new_hash = hash_access_code(new_code)
    cur = conn.execute(
        "UPDATE chats SET access_code_hash = ?, token_version = token_version + 1 WHERE slug = ?",
        (new_hash, slug),
    )
    conn.commit()
    if cur.rowcount == 0:
        return None
    return new_code


def set_revoked(conn: sqlite3.Connection, slug: str, revoked: bool) -> bool:
    """
    Input:      conn -- open sqlite connection
                slug -- chat to update
                revoked -- True to hide/lock it, False to restore it
    Output:     True if a row was updated
    """
    cur = conn.execute("UPDATE chats SET revoked = ? WHERE slug = ?", (int(revoked), slug))
    conn.commit()
    return cur.rowcount > 0


def delete_chat(conn: sqlite3.Connection, slug: str) -> bool:
    """
    Input:      conn -- open sqlite connection
                slug -- chat to permanently delete
    Output:     True if a row was deleted
    """
    cur = conn.execute("DELETE FROM chats WHERE slug = ?", (slug,))
    conn.commit()
    return cur.rowcount > 0
