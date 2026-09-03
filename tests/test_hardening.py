"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Module-level contracts added by the 2026-08 security audit and recorded
    in Assist/audit/security-findings.md: private permissions on the sqlite
    file, a loopback default for the dev-server bind, a markdown renderer
    that degrades instead of raising, and a secrets scanner that fails
    closed instead of returning "no hits" after a crash.
"""
# Imports
import os
import stat

import pytest

from app.config import load_config
from app.db import connect
from app.render import render_markdown
from app.secrets_scan import SecretsScanError, _quoted_pass_hits


def test_connect_makes_the_database_private(tmp_path):
    # The file holds every chat body and every access-code hash. A start
    # path that skips the container umask must still produce 0600.
    db_path = tmp_path / "ccchatshare.db"
    conn = connect(str(db_path))
    conn.close()

    assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o700


def test_connect_leaves_a_sticky_directory_alone(tmp_path):
    # A sticky bit marks a shared temp dir. Narrowing it to 0700 would
    # lock every other user out of the whole directory.
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    db_path = shared / "ccchatshare.db"

    conn = connect(str(db_path))
    conn.close()

    assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600
    assert os.stat(shared).st_mode & stat.S_ISVTX
    assert stat.S_IMODE(os.stat(shared).st_mode) == 0o1777


def test_connect_survives_a_chmod_failure(tmp_path, monkeypatch, caplog):
    # A read-only bind mount must not take the app down.
    db_path = tmp_path / "ccchatshare.db"

    def _refuse(*_args, **_kwargs):
        raise PermissionError("read-only file system")

    monkeypatch.setattr(os, "chmod", _refuse)
    with caplog.at_level("WARNING"):
        conn = connect(str(db_path))
    conn.close()

    assert "Could not chmod" in caplog.text


def test_load_config_defaults_host_to_loopback(monkeypatch, tmp_path):
    # The dev-server fallback in wsgi.py must not listen on every
    # interface unless an operator asks for that explicitly.
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("CCCHATSHARE_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("CCCHATSHARE_DB_PATH", str(tmp_path / "ccchatshare.db"))
    monkeypatch.delenv("CCCHATSHARE_HOST", raising=False)

    assert load_config().host == "127.0.0.1"

    monkeypatch.setenv("CCCHATSHARE_HOST", "0.0.0.0")
    assert load_config().host == "0.0.0.0"


def test_render_markdown_degrades_to_escaped_text_on_failure(monkeypatch, caplog):
    # Stored content is already persisted. A parse failure must not turn
    # every GET of that chat into a 500, and must not emit live HTML.
    def _boom(*_args, **_kwargs):
        raise AssertionError("html.parser blew up")

    monkeypatch.setattr("app.render.markdown_lib.markdown", _boom)
    with caplog.at_level("ERROR"):
        out = render_markdown("<script>alert(1)</script> body text")

    assert out.startswith("<pre>")
    assert out.endswith("</pre>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "body text" in out
    assert "Markdown or bleach failed" in caplog.text


def test_render_markdown_still_sanitizes_on_the_normal_path():
    out = render_markdown("# Title\n\n<script>alert(1)</script>\n\nplain text.")
    assert "<h1" in out
    assert "<script>" not in out
    assert "plain text." in out


def test_quoted_pass_hits_raises_instead_of_reporting_no_hits(monkeypatch):
    # "The scan crashed" must never be indistinguishable from "the text is
    # clean", or a failure publishes an unredacted body.
    def _boom(*_args, **_kwargs):
        raise RuntimeError("detect-secrets unavailable")

    monkeypatch.setattr(
        "app.secrets_scan.SecretsCollection.scan_file", _boom, raising=True
    )
    with pytest.raises(SecretsScanError):
        _quoted_pass_hits("AWS key: AKIAIOSFODNN7EXAMPLE\n")


def test_quoted_pass_hits_removes_its_temp_file_on_failure(monkeypatch):
    seen = {}
    real_unlink = os.unlink

    def _record(path):
        seen["path"] = path
        return real_unlink(path)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("detect-secrets unavailable")

    monkeypatch.setattr("app.secrets_scan.SecretsCollection.scan_file", _boom, raising=True)
    monkeypatch.setattr("app.secrets_scan.os.unlink", _record)
    with pytest.raises(SecretsScanError):
        _quoted_pass_hits("some text\n")

    assert "path" in seen
    assert not os.path.exists(seen["path"])
