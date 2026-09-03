"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Admin API used by export_chat.py --online. The client pushes a
    rendered chat and gets back a slug and a one-time access code.
    Requests need a bearer token. Deploy time generates the token and
    shares it out of band with the CLI config file.
    Every pushed body is scanned for embedded secrets and redacted
    before persist. The server does not trust the client to scan first.
"""
# Imports
import hmac
import logging

from flask import Blueprint, current_app, jsonify, request

from app.db import get_db
from app.limiter import limiter
from app.models import create_chat
from app.secrets_scan import SecretsScanError, scan_and_redact

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__, url_prefix="/api")


# Functions
def _authorized() -> bool:
    """
    Input:      None (reads the Authorization header)
    Output:     True if the request carries the correct bearer token
    Details:
        Constant-time comparison via hmac.compare_digest to avoid a
        timing side-channel on the token.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth.removeprefix("Bearer ").strip()
    return hmac.compare_digest(token, current_app.config["admin_api_token"])


@admin_bp.post("/chats")
@limiter.limit("10 per hour")
def push_chat():
    """
    Input:      JSON body {"title": str, "markdown": str, "tools_markdown": str|None}
    Output:     201 {"slug": str, "access_code": str, "secrets_redacted": int}
                401 on a missing/wrong bearer token
                400 on a missing/wrong-typed required field
                413 on an oversized body (see MAX_CONTENT_LENGTH in config)
                503 if the secrets scanner cannot finish
    Details:
        Rate-limited to 10 per hour. Flask/Werkzeug enforces
        app.config["MAX_CONTENT_LENGTH"] before this view runs.
        This is the only write path into the database.
        Its only gate is a static bearer token that could leak.
        Title, markdown, and tools_markdown are all scanned before persist.
    """
    if not _authorized():
        return jsonify(error="unauthorized"), 401

    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    markdown = data.get("markdown")
    tools_markdown = data.get("tools_markdown")

    if not title or not markdown:
        return jsonify(error="title and markdown are required"), 400
    if not isinstance(markdown, str):
        return jsonify(error="markdown must be a string"), 400
    if tools_markdown is not None and not isinstance(tools_markdown, str):
        return jsonify(error="tools_markdown must be a string or null"), 400

    try:
        title, title_secret_types = scan_and_redact(title)
        markdown, md_secret_types = scan_and_redact(markdown)
        tools_markdown, tools_secret_types = scan_and_redact(tools_markdown)
    except SecretsScanError:
        logger.exception("secrets scan failed; refusing push")
        return jsonify(error="secrets scan failed"), 503
    secret_types = title_secret_types + md_secret_types + tools_secret_types

    conn = get_db()
    chat, access_code = create_chat(conn, title, markdown, tools_markdown)
    logger.info("Created chat slug=%s", chat.slug)
    if secret_types:
        logger.warning(
            "Redacted %d potential secret(s) from slug=%s, types=%s",
            len(secret_types), chat.slug, sorted(set(secret_types)),
        )
    return jsonify(slug=chat.slug, access_code=access_code, secrets_redacted=len(secret_types)), 201
