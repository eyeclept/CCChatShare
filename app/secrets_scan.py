"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Scans chat markdown for embedded secrets and redacts them before
    persist. Secrets include API keys, passwords, tokens, and private
    keys. The scan uses detect-secrets (Yelp), not a custom regex set.

    Two passes are required.

    1. detect-secrets file-scan plugins (AWS, GitHub, Slack, Stripe,
       JWT, private key, plus the quoted-value keyword regex).
       This must go through SecretsCollection.scan_file().
       The adhoc string API (detect_secrets.core.scan.scan_line)
       skips entropy-limit filtering. That API flags most English
       words as a "Base64 High Entropy String". A five-sentence
       paragraph produced 20+ false positives during implementation.
       The file-scan path applies each plugin's real limits.

    2. detect-secrets config-filetype keyword regex for unquoted
       KEY=value and KEY: value. Applied by hand. Markdown-typed
       content only gets the quotes-required regex by default.
       That miss is common when someone pastes raw .env text.
"""
# Imports
import logging
import os
import re
import tempfile

from detect_secrets import SecretsCollection
from detect_secrets.plugins import keyword
from detect_secrets.settings import default_settings

logger = logging.getLogger(__name__)

# Globals
REDACTION_MARKER = "[REDACTED:{}]"
PRIVATE_KEY_MARKER = "[REDACTED: private key material removed]"
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


# Classes
class SecretsScanError(Exception):
    """
    Input:      message -- why the file-scan pass could not finish
    Output:     None
    Details:
        Raised when detect-secrets cannot complete a file-scan pass.
        Callers must refuse persist. Returning no hits would store
        unredacted secrets.
    """


# Functions
def _quoted_pass_hits(text: str) -> list[tuple[int, str, str]]:
    """
    Input:      text -- markdown to scan
    Output:     list of (1-indexed line_number, secret_value, detector type).
                Raises SecretsScanError if detect-secrets cannot finish.
    Details:
        Writes text to a temp .md file, since SecretsCollection.scan_file()
        is the only codepath that applies each plugin's real entropy/regex
        limits (see module docstring).
        A detect-secrets exception is logged and raised as SecretsScanError
        so callers refuse persist.
    """
    fd, path = tempfile.mkstemp(suffix=".md")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        secrets = SecretsCollection()
        with default_settings():
            secrets.scan_file(path)
        return [
            (secret.line_number, secret.secret_value, secret.type)
            for _filename, secret in secrets
            if secret.secret_value
        ]
    except Exception as exc:
        logger.exception("detect-secrets file-scan pass failed")
        raise SecretsScanError("detect-secrets file-scan pass failed") from exc
    finally:
        os.unlink(path)


def _unquoted_env_pass_hits(text: str) -> list[tuple[int, str, str]]:
    """
    Input:      text -- markdown to scan
    Output:     list of (1-indexed line_number, secret_value, "Secret Keyword")
    Details:
        Catches .env-style unquoted assignments pasted into a chat.
        Uses detect-secrets CONFIG_DENYLIST_REGEX_TO_GROUP, the regex
        set it ships for .env, .ini, and .toml files. Applied line by
        line, even when this content is markdown.
    """
    hits = []
    for i, line in enumerate(text.split("\n"), start=1):
        for regex, group in keyword.CONFIG_DENYLIST_REGEX_TO_GROUP.items():
            match = regex.search(line)
            if match:
                hits.append((i, match.group(group), "Secret Keyword"))
    return hits


def scan_and_redact(text: str | None) -> tuple[str | None, list[str]]:
    """
    Input:      text -- markdown to scan (chat body or tool-call log),
                may be None
    Output:     (redacted_text, [detector type strings found]).
                Each detected secret value is replaced with a
                "[REDACTED:<type>]" marker. PEM private-key blocks are
                replaced as a whole between their BEGIN/END markers.
                Line-by-line replace is not used, because only the
                BEGIN line reliably matches the plugin.
    Details:
        Never returns or logs the actual secret values. Only the
        detector type is kept, so an audit log cannot recreate the
        leak it reports.
        A failed file-scan pass raises SecretsScanError rather than
        returning the original text.
    """
    if not text:
        return text, []

    found_types: list[str] = []

    if _PEM_BLOCK_RE.search(text):
        pre_hits = _quoted_pass_hits(text)
        if any(typ == "Private Key" for _ln, _val, typ in pre_hits):
            text = _PEM_BLOCK_RE.sub(PRIVATE_KEY_MARKER, text)
            found_types.append("Private Key")

    hits = _quoted_pass_hits(text) + _unquoted_env_pass_hits(text)
    hits = [(ln, val, typ) for ln, val, typ in hits if typ != "Private Key"]
    if not hits:
        return text, found_types

    lines = text.split("\n")
    by_line: dict[int, list[tuple[str, str]]] = {}
    for ln, val, typ in hits:
        by_line.setdefault(ln, []).append((val, typ))
        found_types.append(typ)

    for ln, pairs in by_line.items():
        idx = ln - 1
        if idx < 0 or idx >= len(lines):
            continue
        line = lines[idx]
        # Longest value first, so a short match nested inside a longer one
        # does not get partially replaced before the full one is handled.
        for val, typ in sorted(pairs, key=lambda p: -len(p[0])):
            if val and val in line:
                line = line.replace(val, REDACTION_MARKER.format(typ))
        lines[idx] = line

    return "\n".join(lines), found_types
