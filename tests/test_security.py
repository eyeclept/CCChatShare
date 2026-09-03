"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Unit tests for app/security.py: code/slug generation, hashing, and the
    signed auth cookie's scoping rules (wrong slug, wrong token_version,
    expiry, tampering must all fail closed).
"""
# Imports
import time

from app.security import (
    ACCESS_CODE_LENGTH,
    SLUG_LENGTH,
    generate_access_code,
    generate_slug,
    hash_access_code,
    make_auth_cookie,
    verify_access_code,
    verify_auth_cookie,
)

SECRET = "test-secret-key"


def test_generate_slug_length_and_alphabet():
    slug = generate_slug()
    assert len(slug) == SLUG_LENGTH
    allowed = set("abcdefghjkmnpqrstuvwxyz23456789")
    assert set(slug) <= allowed


def test_generate_access_code_length_and_alphabet():
    code = generate_access_code()
    assert len(code) == ACCESS_CODE_LENGTH
    allowed = set("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
    assert set(code) <= allowed


def test_generate_functions_are_random():
    assert len({generate_slug() for _ in range(20)}) == 20
    assert len({generate_access_code() for _ in range(20)}) == 20


def test_hash_and_verify_access_code_roundtrip():
    code = "AB3D9KMP"
    code_hash = hash_access_code(code)
    assert code_hash != code
    assert verify_access_code(code, code_hash) is True


def test_verify_access_code_rejects_wrong_code():
    code_hash = hash_access_code("AB3D9KMP")
    assert verify_access_code("WRONGCOD", code_hash) is False


CODE_HASH = "scrypt:32768:8:1$dummysalt$dummyhash"
OTHER_CODE_HASH = "scrypt:32768:8:1$othersalt$otherhash"


def test_auth_cookie_roundtrip_succeeds():
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    assert verify_auth_cookie(SECRET, token, "myslug1234", 1, CODE_HASH, max_age=3600) is True


def test_auth_cookie_rejects_wrong_slug():
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    assert verify_auth_cookie(SECRET, token, "otherslug1", 1, CODE_HASH, max_age=3600) is False


def test_auth_cookie_rejects_stale_token_version():
    # Simulates an access-code regeneration bumping token_version. Old
    # cookies must stop working even though their signature is still valid.
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    assert verify_auth_cookie(SECRET, token, "myslug1234", 2, CODE_HASH, max_age=3600) is False


def test_auth_cookie_rejects_changed_access_code_hash():
    # Simulates a SECRET_KEY leak: the attacker can sign a cookie but
    # does not know the current access_code_hash, so the fingerprint
    # embedded at signing time must not match a chat whose code changed.
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    assert verify_auth_cookie(SECRET, token, "myslug1234", 1, OTHER_CODE_HASH, max_age=3600) is False


def test_auth_cookie_rejects_tampered_token():
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    tampered = token[:-1] + ("a" if token[-1] != "a" else "b")
    assert verify_auth_cookie(SECRET, tampered, "myslug1234", 1, CODE_HASH, max_age=3600) is False


def test_auth_cookie_rejects_expired_token():
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    time.sleep(2.2)
    assert verify_auth_cookie(SECRET, token, "myslug1234", 1, CODE_HASH, max_age=1) is False


def test_auth_cookie_rejects_wrong_secret_key():
    token = make_auth_cookie(SECRET, "myslug1234", 1, CODE_HASH)
    assert (
        verify_auth_cookie("different-secret", token, "myslug1234", 1, CODE_HASH, max_age=3600)
        is False
    )
