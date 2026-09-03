"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Public routes: the front page, the unlock flow, and the
    authenticated chat and tools views. The unlock flow uses the
    Flask-Limiter lockout. No route here exposes another chat's
    existence, code, or title before unlock.
"""
# Imports
import hmac
import logging
import secrets

from flask import Blueprint, abort, current_app, make_response, redirect, render_template, request, url_for

from app.db import get_db
from app.limiter import limiter, unlock_key
from app.models import get_chat_by_slug, get_chat_gate, record_view
from app.render import render_markdown
from app.security import (
    cookie_name,
    make_auth_cookie,
    verify_access_code,
    verify_auth_cookie,
)

logger = logging.getLogger(__name__)
public_bp = Blueprint("public", __name__)

# A slug is always exactly SLUG_LENGTH (10) characters (app/security.py).
# Constraining the route converter rejects malformed/oversized slugs at
# routing time, before they ever reach the rate limiter or a DB query --
# without this, an attacker could POST a multi-kilobyte garbage "slug" to
# /unlock repeatedly, parking that much key text per limiter bucket.
_SLUG_RULE = "<string(length=10):slug>"
_CSRF_COOKIE = "cc_csrf"


# Functions
def _is_unlocked(slug: str, token_version: int, access_code_hash: str) -> bool:
    """
    Input:      slug -- chat slug being requested
                token_version -- chat's current token_version
                access_code_hash -- chat's current access-code hash
    Output:     True if the request carries a still-valid auth cookie
    """
    token = request.cookies.get(cookie_name(slug))
    if not token:
        return False
    return verify_auth_cookie(
        current_app.config["secret_key"],
        token,
        slug,
        token_version,
        access_code_hash,
        current_app.config["cookie_max_age"],
    )


def _mint_csrf_token() -> str:
    """
    Input:      None
    Output:     a URL-safe random token
    Details:
        secrets.token_urlsafe(32) is unpredictable to a third-party page.
        The same value is stored in the form and in the CSRF cookie.
    """
    return secrets.token_urlsafe(32)


def _render_unlock(slug: str, title: str | None, error: str | None):
    """
    Input:      slug -- chat slug for the form action and cookie path
                title -- optional title shown on the form
                error -- optional error string shown on the form
    Output:     Flask response with unlock.html and a matching CSRF cookie
    Details:
        Double-submit CSRF: the same token is in the form and in a cookie.
        SameSite=Strict keeps a cross-site POST from sending the cookie.
        The path is scoped to one chat so tokens do not leak across chats.
    """
    token = _mint_csrf_token()
    resp = make_response(
        render_template(
            "unlock.html",
            slug=slug,
            title=title,
            error=error,
            csrf_token=token,
        )
    )
    resp.set_cookie(
        _CSRF_COOKIE,
        token,
        httponly=True,
        samesite="Strict",
        secure=current_app.config["cookie_secure"],
        path=f"/c/{slug}",
    )
    return resp


@public_bp.get("/")
def index():
    """
    Input:      None
    Output:     rendered front page
    Details:
        Does not list chats. A chat is reachable only through its own link.
    """
    return render_template("index.html")


@public_bp.get(f"/c/{_SLUG_RULE}")
def view_chat(slug: str):
    """
    Input:      slug -- chat slug from the URL
    Output:     rendered chat page, unlock form, or 404
    Details:
        A missing chat and a revoked chat both return 404.
        The handler uses the cheap ChatGate row so the two cases stay
        the same by body and by response time.
        The full row is fetched only after the revoked check and the
        auth check both pass. The real title is not shown until auth.
    """
    conn = get_db()
    gate = get_chat_gate(conn, slug)
    if gate is None or gate.revoked:
        abort(404)

    if not _is_unlocked(slug, gate.token_version, gate.access_code_hash):
        return _render_unlock(slug, None, None)

    chat = get_chat_by_slug(conn, slug)
    record_view(conn, slug)
    return render_template(
        "chat.html",
        slug=slug,
        title=chat.title,
        body_html=render_markdown(chat.markdown),
        has_tools=bool(chat.tools_markdown),
    )


@public_bp.post(f"/c/{_SLUG_RULE}/unlock")
@limiter.limit(
    "5 per 5 minutes",
    key_func=unlock_key,
    # Count only a wrong-code 200. A CSRF 400 or a 404 must not
    # spend a lockout slot, or a forged cross-site POST can lock
    # the visitor out of the share link.
    deduct_when=lambda response: response.status_code == 200,
)
def unlock_chat(slug: str):
    """
    Input:      slug -- chat slug from the URL
                form field "access_code"
                form field "csrf_token" and cookie cc_csrf
    Output:     redirect to view_chat on success, re-rendered unlock form
                with an error on a wrong code, or 400 on a CSRF miss
    Details:
        Flask-Limiter enforces 5 tries per 5 minutes per (ip, slug).
        unlock_key builds that bucket. Five wrong guesses return 429
        for the next five minutes. too_many_requests() handles the 429.
        deduct_when counts only status 200, a genuine wrong-code form.
        A CSRF 400 or a missing-chat 404 must not consume a lockout slot.
        A successful unlock (302) does not use a lockout slot.
        Without that, six correct unlocks in one window would lock the sixth.
        CSRF is checked before get_db and before verify_access_code.
    """
    form_token = request.form.get("csrf_token", "")
    cookie_token = request.cookies.get(_CSRF_COOKIE, "")
    if (
        not form_token
        or not cookie_token
        or not hmac.compare_digest(form_token, cookie_token)
    ):
        abort(400)
    conn = get_db()
    gate = get_chat_gate(conn, slug)
    if gate is None or gate.revoked:
        abort(404)

    # The access-code alphabet is uppercase only. Normalize case so a
    # desktop user who types lowercase does not burn a lockout slot on a
    # cosmetic mismatch.
    submitted = request.form.get("access_code", "").strip().upper()
    if not verify_access_code(submitted, gate.access_code_hash):
        return _render_unlock(slug, None, "Incorrect access code.")

    record_view(conn, slug)
    resp = redirect(url_for("public.view_chat", slug=slug))
    resp.set_cookie(
        cookie_name(slug),
        make_auth_cookie(
            current_app.config["secret_key"], slug, gate.token_version, gate.access_code_hash
        ),
        max_age=current_app.config["cookie_max_age"],
        httponly=True,
        secure=current_app.config["cookie_secure"],
        samesite="Lax",
        path=f"/c/{slug}",
    )
    return resp


@public_bp.get(f"/c/{_SLUG_RULE}/tools")
def view_tools(slug: str):
    """
    Input:      slug -- chat slug from the URL
    Output:     rendered tool-call detail page, or 404
    Details:
        Uses the same unlock cookie as the chat. There is no second code
        for the tools file. Auth runs before the tools-file check.
        An unauthenticated visitor always sees the unlock form.
        The form does not reveal whether the chat was exported with --full.
    """
    conn = get_db()
    gate = get_chat_gate(conn, slug)
    if gate is None or gate.revoked:
        abort(404)
    if not _is_unlocked(slug, gate.token_version, gate.access_code_hash):
        return _render_unlock(slug, None, None)

    chat = get_chat_by_slug(conn, slug)
    if not chat.tools_markdown:
        abort(404)

    return render_template(
        "chat.html",
        slug=slug,
        title=f"{chat.title} — Tool Calls",
        body_html=render_markdown(chat.tools_markdown),
        has_tools=False,
    )


@public_bp.errorhandler(404)
def not_found(_e):
    return render_template("error.html", message="Page not found."), 404


@public_bp.errorhandler(429)
def too_many_requests(_e):
    slug = request.view_args.get("slug", "") if request.view_args else ""
    resp = _render_unlock(
        slug,
        None,
        "Too many attempts. Try again in a few minutes.",
    )
    resp.status_code = 429
    return resp
