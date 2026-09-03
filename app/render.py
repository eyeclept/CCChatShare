"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Markdown -> sanitized HTML for chat bodies. Chat content is exported
    from someone's own Claude conversation, but conversations can quote
    arbitrary web/tool content, so output is still sanitized before being
    shown to a second person via a shared link.
"""
# Imports
import html
import logging

import bleach
import markdown as markdown_lib

logger = logging.getLogger(__name__)

# Globals
_MD_EXTENSIONS = ["fenced_code", "tables", "sane_lists", "nl2br"]

_ALLOWED_TAGS = sorted(
    bleach.sanitizer.ALLOWED_TAGS
    | {
        "p", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "br",
        "table", "thead", "tbody", "tr", "th", "td",
        "img", "span", "div",
    }
)
_ALLOWED_ATTRS = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    "a": ["href", "title", "id", "name"],
    "img": ["src", "alt", "title"],
    "code": ["class"],
    "div": ["id", "class"],
    "span": ["id", "class"],
}


# Functions
def render_markdown(text: str) -> str:
    """
    Input:      text -- raw markdown (chat export or tools export)
    Output:     sanitized HTML string safe to render with Jinja's |safe
    Details:
        python-markdown leaves raw HTML in place. export_chat.py --full
        emits `<a id="tool-N"></a>` anchors that need that pass-through.
        bleach then strips anything not on the allow-list before the
        HTML reaches a second viewer's browser.

        html5lib (used by bleach.clean) has known foreign-content bugs.
        Some math or table mixes make the tree builder drop trailing
        content without raising. That is content loss, not an XSS escape.
        The security audit confirmed those payloads stay neutralized.
        The dropped tail is still gone. Log a warning when output shrinks
        far more than tag stripping would explain. A mangled chat then
        shows up in the logs.

        A parse failure in markdown or bleach must not 500 a GET of
        already-stored chat content. Log the exception and return the
        raw text HTML-escaped inside a pre tag. Escape happens outside
        bleach because bleach is one of the calls that may have failed.
    """
    try:
        html_out = markdown_lib.markdown(text, extensions=_MD_EXTENSIONS)
        cleaned = bleach.clean(html_out, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)
    except Exception:
        logger.exception("Markdown or bleach failed while rendering chat body")
        return "<pre>" + html.escape(text) + "</pre>"
    if len(html_out) > 200 and len(cleaned) < len(html_out) * 0.3:
        logger.warning(
            "Sanitized output is %d%% of pre-sanitization length (%d -> %d chars); "
            "possible html5lib foreign-content truncation, not just tag stripping",
            round(100 * len(cleaned) / len(html_out)),
            len(html_out),
            len(cleaned),
        )
    return cleaned
