"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Slug and access-code generation, access-code hashing, and the signed
    cookie that lets a returning browser skip the access code.
    This is a low-stakes shared-link system. The rate limiter
    (app/limiter.py) is the main brute-force control for the 8-character
    code, not hash cost. The stored hash is werkzeug's default scrypt
    (N=32768, r=8, p=1). That KDF is slow on purpose.
"""
# Imports
import hashlib
import logging
import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

# Globals
# Unambiguous alphabet: no 0/O, 1/I/L to keep codes readable when read aloud
# or copied by hand.
_SLUG_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
SLUG_LENGTH = 10
ACCESS_CODE_LENGTH = 8
COOKIE_SALT = "ccchatshare-auth-v1"


# Functions
def generate_slug() -> str:
    """
    Input:      None
    Output:     10-char random slug (public, part of the share URL)
    Details:
        Uses secrets.choice (CSPRNG) over an unambiguous alphabet.
    """
    return "".join(secrets.choice(_SLUG_ALPHABET) for _ in range(SLUG_LENGTH))


def generate_access_code() -> str:
    """
    Input:      None
    Output:     8-char random access code (secret, shown to the sharer once)
    Details:
        Uses secrets.choice (CSPRNG) over an unambiguous alphabet.
    """
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(ACCESS_CODE_LENGTH))


def hash_access_code(code: str) -> str:
    """
    Input:      code -- plaintext access code
    Output:     salted hash string safe to store in sqlite
    """
    return generate_password_hash(code)


def verify_access_code(code: str, code_hash: str) -> bool:
    """
    Input:      code -- plaintext access code submitted by a visitor
                code_hash -- stored hash for the target chat
    Output:     True if they match
    Details:
        werkzeug's check_password_hash is constant-time.
    """
    return check_password_hash(code_hash, code)


def code_hash_fingerprint(access_code_hash: str) -> str:
    """
    Input:      access_code_hash -- the chat's stored password hash
    Output:     a short, non-reversible fingerprint of that hash
    Details:
        The signed cookie payload includes this fingerprint.
        A leaked SECRET_KEY alone cannot forge a cookie for a chat
        whose access code the attacker does not know.
        The attacker would also need the current access_code_hash.
        token_version-only binding did not require that hash.
        sha256 is used so the cookie never carries the real hash.
    """
    return hashlib.sha256(access_code_hash.encode("utf-8")).hexdigest()[:16]


def make_auth_cookie(
    secret_key: str, slug: str, token_version: int, access_code_hash: str
) -> str:
    """
    Input:      secret_key -- app SECRET_KEY
                slug -- chat slug the cookie authorizes
                token_version -- chat's current token_version
                access_code_hash -- chat's current access-code hash
    Output:     signed, timestamped token string to store as a cookie value
    Details:
        token_version is bumped whenever an access code is regenerated.
        That invalidates every previously issued cookie for that chat
        without a server-side session or revocation table.
        The access_code_hash fingerprint is extra for that purpose.
        A SECRET_KEY leak alone, without the database, does not let an
        attacker forge a valid cookie for a chat.
    """
    serializer = URLSafeTimedSerializer(secret_key, salt=COOKIE_SALT)
    return serializer.dumps({
        "slug": slug,
        "token_version": token_version,
        "cfp": code_hash_fingerprint(access_code_hash),
    })


def verify_auth_cookie(
    secret_key: str,
    token: str,
    slug: str,
    token_version: int,
    access_code_hash: str,
    max_age: int,
) -> bool:
    """
    Input:      secret_key -- app SECRET_KEY
                token -- cookie value presented by the browser
                slug -- chat slug being requested
                token_version -- chat's current token_version
                access_code_hash -- chat's current access-code hash
                max_age -- max cookie age in seconds
    Output:     True only if the signature is valid, unexpired, and the
                slug, token_version, and access-code fingerprint all
                match the chat being viewed
    Details:
        Rejects a mismatched slug, token_version, or fingerprint
        even when the signature is valid.
        A cookie for another chat must not grant access.
        An old version of this chat's code must not grant access.
        A cookie forged from a leaked SECRET_KEY without the current
        access_code_hash must not grant access.
    """
    serializer = URLSafeTimedSerializer(secret_key, salt=COOKIE_SALT)
    try:
        data = serializer.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return False
    except Exception:
        logger.exception("Unexpected error verifying auth cookie for slug=%s", slug)
        return False
    return (
        data.get("slug") == slug
        and data.get("token_version") == token_version
        and data.get("cfp") == code_hash_fingerprint(access_code_hash)
    )


def cookie_name(slug: str) -> str:
    """
    Input:      slug -- chat slug
    Output:     cookie name scoped to that chat, e.g. "ccchat_auth_<slug>"
    Details:
        One cookie per viewed chat, so unlocking chat A never implies
        access to chat B. Clearing one chat's cookie does not affect
        others.
    """
    return f"ccchat_auth_{slug}"
