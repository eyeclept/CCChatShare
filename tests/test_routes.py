"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    End-to-end HTTP tests for the unlock flow, CSRF on the unlock POST,
    cookie auto-login, the 5-per-5-minutes lockout, revoked/missing chats,
    the response security headers, and the admin push API. Uses Flask's
    test client against a real (temp-file) sqlite db.
"""
# Imports
import json
import re

from app.db import get_db
from app.models import create_chat, set_revoked
from app.secrets_scan import SecretsScanError


def _make_chat(app, title="Test Chat", markdown="# Hello\n\nWorld.", tools_markdown=None):
    with app.app_context():
        conn = get_db()
        chat, code = create_chat(conn, title, markdown, tools_markdown)
        return chat.slug, code


def _csrf(client, slug):
    """
    Input:      client -- Flask test client
                slug -- chat whose unlock form to fetch
    Output:     the csrf_token value from the served unlock form
    Details:
        The unlock POST needs a double-submit pair: this token in the form
        and the same value in the cc_csrf cookie. The test client keeps a
        cookie jar, so fetching the form also arms the cookie for the POST
        that follows. This mirrors what a browser does.
    """
    page = client.get(f"/c/{slug}")
    match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
    assert match, "the unlock form served no csrf_token"
    return match.group(1).decode()


def _unlock(client, slug, code, **kwargs):
    """
    Input:      client -- Flask test client
                slug -- chat slug
                code -- access code to submit
                kwargs -- passed through to client.post (headers, etc.)
    Output:     the unlock response
    Details:
        Fetches a fresh CSRF token, then posts it with the access code.
    """
    data = {"access_code": code, "csrf_token": _csrf(client, slug)}
    return client.post(f"/c/{slug}/unlock", data=data, **kwargs)


def test_unknown_slug_is_404(client):
    resp = client.get("/c/does-not-exist")
    assert resp.status_code == 404


def test_view_locked_chat_shows_unlock_form(app, client):
    slug, _code = _make_chat(app)
    resp = client.get(f"/c/{slug}")
    assert resp.status_code == 200
    assert b"Access Code" in resp.data


def test_wrong_code_shows_error_and_sets_no_auth_cookie(app, client):
    slug, _code = _make_chat(app)
    resp = _unlock(client, slug, "WRONGCOD")
    assert resp.status_code == 200
    assert b"Incorrect access code" in resp.data
    # The re-rendered form carries a fresh CSRF cookie. It must not carry
    # an auth cookie: a wrong code unlocks nothing.
    assert not any(f"ccchat_auth_{slug}" in c for c in resp.headers.getlist("Set-Cookie"))


def test_correct_code_unlocks_and_sets_cookie(app, client):
    slug, code = _make_chat(app, markdown="# Hello\n\nUnique marker text.")
    resp = _unlock(client, slug, code)
    assert resp.status_code == 302
    assert any(f"ccchat_auth_{slug}" in c for c in resp.headers.getlist("Set-Cookie"))

    follow = client.get(resp.headers["Location"])
    assert follow.status_code == 200
    assert b"Unique marker text" in follow.data


def test_cookie_auto_login_skips_unlock_form(app, client):
    slug, code = _make_chat(app)
    _unlock(client, slug, code)
    resp = client.get(f"/c/{slug}")
    assert resp.status_code == 200
    assert b"Access Code" not in resp.data


def test_view_count_increments_on_each_unlocked_view(app, client):
    slug, code = _make_chat(app)
    _unlock(client, slug, code)
    client.get(f"/c/{slug}")
    client.get(f"/c/{slug}")
    with app.app_context():
        conn = get_db()
        row = conn.execute("SELECT view_count FROM chats WHERE slug = ?", (slug,)).fetchone()
    # The unlock POST records one view. _csrf and the two GETs below add
    # three more: the locked _csrf GET renders the form and records nothing.
    assert row["view_count"] == 3


def test_revoked_chat_is_404_even_with_correct_code(app, client):
    slug, code = _make_chat(app)
    # Arm the CSRF pair while the chat is still readable, so the 404 below
    # is the revoke check firing and not a CSRF rejection.
    token = _csrf(client, slug)
    with app.app_context():
        conn = get_db()
        set_revoked(conn, slug, True)
    resp = client.post(f"/c/{slug}/unlock", data={"access_code": code, "csrf_token": token})
    assert resp.status_code == 404


def test_unlock_rejects_missing_csrf_token(app, client):
    slug, code = _make_chat(app)
    resp = client.post(f"/c/{slug}/unlock", data={"access_code": code})
    assert resp.status_code == 400
    assert not any(f"ccchat_auth_{slug}" in c for c in resp.headers.getlist("Set-Cookie"))


def test_unlock_rejects_mismatched_csrf_token(app, client):
    slug, code = _make_chat(app)
    _csrf(client, slug)  # arms the cc_csrf cookie
    resp = client.post(
        f"/c/{slug}/unlock",
        data={"access_code": code, "csrf_token": "not-the-cookie-value"},
    )
    assert resp.status_code == 400
    assert not any(f"ccchat_auth_{slug}" in c for c in resp.headers.getlist("Set-Cookie"))


def test_csrf_rejection_does_not_consume_lockout_budget(app, client):
    # A forged cross-site POST carries no matching CSRF cookie. If those
    # 400s counted against the 5-per-5-minutes budget, a third-party page
    # could lock the real visitor out of the share link. They must not.
    slug, code = _make_chat(app)
    for _ in range(8):
        forged = client.post(f"/c/{slug}/unlock", data={"access_code": "WRONGCOD"})
        assert forged.status_code == 400

    assert _unlock(client, slug, code).status_code == 302


def test_locked_view_serves_matching_csrf_cookie_and_form_token(app, client):
    slug, _code = _make_chat(app)
    resp = client.get(f"/c/{slug}")
    match = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data)
    assert match
    set_cookie = next(c for c in resp.headers.getlist("Set-Cookie") if "cc_csrf" in c)
    assert match.group(1).decode() in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert f"Path=/c/{slug}" in set_cookie


def test_five_wrong_attempts_then_locked_out(app, client):
    slug, _code = _make_chat(app)
    for _ in range(5):
        resp = _unlock(client, slug, "WRONGCOD")
        assert resp.status_code == 200

    locked = _unlock(client, slug, "WRONGCOD")
    assert locked.status_code == 429
    assert b"Too many attempts" in locked.data


def test_lockout_does_not_affect_a_different_chat(app, client):
    slug_a, _code_a = _make_chat(app, title="Chat A")
    slug_b, code_b = _make_chat(app, title="Chat B")

    for _ in range(5):
        _unlock(client, slug_a, "WRONGCOD")
    locked = _unlock(client, slug_a, "WRONGCOD")
    assert locked.status_code == 429

    still_open = _unlock(client, slug_b, code_b)
    assert still_open.status_code == 302


def test_lockout_is_scoped_per_client_ip_not_shared_globally(app, client):
    # Regression test for the audit finding: the limiter must key on the
    # real visitor IP (Cf-Connecting-Ip when present), not a constant
    # proxy-hop address. Otherwise one anonymous attacker's five wrong
    # guesses lock out every other visitor of the same link.
    slug, code = _make_chat(app)
    attacker = {"Cf-Connecting-Ip": "203.0.113.1"}
    for _ in range(5):
        _unlock(client, slug, "WRONGCOD", headers=attacker)
    attacker_locked = _unlock(client, slug, "WRONGCOD", headers=attacker)
    assert attacker_locked.status_code == 429

    victim_still_open = _unlock(
        client, slug, code, headers={"Cf-Connecting-Ip": "203.0.113.2"}
    )
    assert victim_still_open.status_code == 302


def test_successful_unlocks_do_not_consume_lockout_budget(app, client):
    # Regression test: a shared link must survive more than 5 correct
    # unlocks within one window. Only failed attempts should count
    # against the 5-per-5-minutes budget.
    slug, code = _make_chat(app)
    for _ in range(8):
        # Drop the auth cookie so each pass is a fresh visitor arriving at
        # the locked form, not the same browser reusing its unlock.
        client.delete_cookie(f"ccchat_auth_{slug}", path=f"/c/{slug}")
        resp = _unlock(client, slug, code)
        assert resp.status_code == 302


def test_unlock_accepts_lowercase_access_code(app, client):
    slug, code = _make_chat(app)
    resp = _unlock(client, slug, code.lower())
    assert resp.status_code == 302


def test_unlock_cookie_is_secure_and_scoped_to_chat_path(app, client):
    slug, code = _make_chat(app)
    resp = _unlock(client, slug, code)
    set_cookie = next(
        c for c in resp.headers.getlist("Set-Cookie") if f"ccchat_auth_{slug}" in c
    )
    assert "Secure" in set_cookie
    assert f"Path=/c/{slug}" in set_cookie


def test_security_headers_on_every_response(client):
    # An internet-exposed share link must not be downgradeable to http,
    # embeddable in a frame, or content-type sniffable.
    resp = client.get("/")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


def test_tools_route_requires_unlock_and_404s_without_tools(app, client):
    # No tools file, unauthenticated: shows the unlock form, not a 404.
    # Whether a chat was exported with --full must not be disclosed
    # before the visitor is authenticated.
    slug, code = _make_chat(app, tools_markdown=None)
    locked_resp = client.get(f"/c/{slug}/tools")
    assert locked_resp.status_code == 200
    assert b"Access Code" in locked_resp.data

    _unlock(client, slug, code)
    unlocked_resp = client.get(f"/c/{slug}/tools")
    assert unlocked_resp.status_code == 404

    slug2, code2 = _make_chat(app, tools_markdown="tool call log")
    locked_resp2 = client.get(f"/c/{slug2}/tools")
    assert locked_resp2.status_code == 200
    assert b"Access Code" in locked_resp2.data

    _unlock(client, slug2, code2)
    unlocked_resp2 = client.get(f"/c/{slug2}/tools")
    assert unlocked_resp2.status_code == 200
    assert b"tool call log" in unlocked_resp2.data


def test_admin_api_requires_bearer_token(client):
    resp = client.post("/api/chats", json={"title": "X", "markdown": "y"})
    assert resp.status_code == 401


def test_admin_api_rejects_wrong_token(client):
    resp = client.post(
        "/api/chats",
        json={"title": "X", "markdown": "y"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_admin_api_creates_chat_and_is_immediately_unlockable(client):
    resp = client.post(
        "/api/chats",
        json={"title": "Pushed Chat", "markdown": "# Pushed\n\ncontent", "tools_markdown": None},
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 201
    body = json.loads(resp.data)
    assert "slug" in body and "access_code" in body

    unlock = _unlock(client, body["slug"], body["access_code"])
    assert unlock.status_code == 302


def test_admin_api_requires_title_and_markdown(client):
    resp = client.post(
        "/api/chats",
        json={"title": "", "markdown": ""},
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 400


def test_admin_api_rejects_non_string_markdown(client):
    resp = client.post(
        "/api/chats",
        json={"title": "X", "markdown": {"a": 1}},
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 400


def test_admin_api_rejects_non_string_tools_markdown(client):
    resp = client.post(
        "/api/chats",
        json={"title": "X", "markdown": "ok", "tools_markdown": [1, 2]},
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 400


def test_admin_api_redacts_embedded_secret_and_reports_count(app, client):
    resp = client.post(
        "/api/chats",
        json={
            "title": "Secret Test",
            "markdown": "AWS key: AKIAIOSFODNN7EXAMPLE\n\nnothing else sensitive here.",
        },
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 201
    body = json.loads(resp.data)
    assert body["secrets_redacted"] >= 1

    with app.app_context():
        conn = get_db()
        row = conn.execute(
            "SELECT markdown FROM chats WHERE slug = ?", (body["slug"],)
        ).fetchone()
    assert "AKIAIOSFODNN7EXAMPLE" not in row["markdown"]
    assert "REDACTED" in row["markdown"]


def test_admin_api_redacts_a_secret_in_the_title(app, client):
    # The title reaches the page heading, the browser tab title and the
    # admin TUI table. It goes through the same scanner as the body.
    resp = client.post(
        "/api/chats",
        json={
            "title": "Deploy notes AKIAIOSFODNN7EXAMPLE",
            "markdown": "nothing sensitive here.",
        },
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 201
    body = json.loads(resp.data)
    assert body["secrets_redacted"] >= 1

    with app.app_context():
        conn = get_db()
        row = conn.execute(
            "SELECT title FROM chats WHERE slug = ?", (body["slug"],)
        ).fetchone()
    assert "AKIAIOSFODNN7EXAMPLE" not in row["title"]
    assert "REDACTED" in row["title"]


def test_admin_api_fails_closed_when_the_scanner_raises(app, client, monkeypatch):
    # A scanner crash must refuse the push. Persisting an unscanned body
    # would publish the secret the scanner exists to remove.
    def _boom(_text):
        raise SecretsScanError("scan unavailable")

    monkeypatch.setattr("app.routes_admin.scan_and_redact", _boom)
    resp = client.post(
        "/api/chats",
        json={"title": "Should not persist", "markdown": "body"},
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert resp.status_code == 503

    with app.app_context():
        conn = get_db()
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM chats WHERE title = ?", ("Should not persist",)
        ).fetchone()
    assert count["n"] == 0
