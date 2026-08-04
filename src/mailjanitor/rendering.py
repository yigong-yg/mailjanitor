"""Context-safe rendering for attacker-controlled metadata."""

from __future__ import annotations

import re
import unicodedata
from typing import Final

_DOMAIN_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59}))(?![A-Za-z0-9-])"
)
_SCHEME_PATTERN: Final = re.compile(r"(?i)\b(?:https?|ftp|mailto):")
_BIDI_CLASSES: Final = frozenset(
    {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
)
_MARKDOWN_SPECIAL: Final = re.compile(r"([\\`*{}\[\]()<>#+\-.!_|])")
_MAX_DISPLAY_LENGTH: Final = 4096
_MAX_ADDRESS_LENGTH: Final = 320


def safe_display_text(value: str, *, maximum: int = 512) -> str:
    """Bound, expose controls, and defang links without interpreting content."""
    if type(value) is not str:
        raise TypeError("display value must be a string")
    if not 1 <= maximum <= _MAX_DISPLAY_LENGTH:
        raise ValueError("display maximum must be between 1 and 4096")

    normalized = unicodedata.normalize("NFC", value)
    truncated = len(normalized) > maximum
    bounded = normalized[:maximum]
    visible = "".join(_visible_character(character) for character in bounded)
    defanged = _SCHEME_PATTERN.sub(lambda match: match.group(0)[:-1] + "[:]", visible)
    defanged = _DOMAIN_PATTERN.sub(_defang_match, defanged)
    return f"{defanged}…" if truncated else defanged


def safe_markdown_cell(value: str, *, maximum: int = 512) -> str:
    """Render one non-clickable, non-structural Markdown table cell."""
    displayed = safe_display_text(value, maximum=maximum)
    return _MARKDOWN_SPECIAL.sub(r"\\\1", displayed)


def redact_address(value: str) -> str:
    """Return a minimally identifying, defanged address for reports."""
    if type(value) is not str:
        raise TypeError("address must be a string")
    if len(value) > _MAX_ADDRESS_LENGTH or value.count("@") != 1:
        return "[invalid-address]"
    local, domain = value.rsplit("@", maxsplit=1)
    if (
        not local
        or _DOMAIN_PATTERN.fullmatch(domain) is None
        or any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in local
        )
    ):
        return "[invalid-address]"
    first = local[0] if local[0].isascii() and local[0].isalnum() else ""
    local_hint = f"{first}…" if first and len(local) > 1 else "…"
    return f"{local_hint}@{domain.replace('.', '[.]')}"


def spreadsheet_safe(value: str, *, maximum: int = 512) -> str:
    """Prevent formula execution when a display value is exported as a cell."""
    displayed = safe_display_text(value, maximum=maximum)
    if displayed.startswith(("=", "+", "-", "@")):
        return f"'{displayed}"
    return displayed


def _visible_character(character: str) -> str:
    category = unicodedata.category(character)
    bidi = unicodedata.bidirectional(character)
    if category in {"Cc", "Cs"} or bidi in _BIDI_CLASSES:
        return f"⟦U+{ord(character):04X}⟧"
    return character


def _defang_match(match: re.Match[str]) -> str:
    return match.group(1).replace(".", "[.]")
