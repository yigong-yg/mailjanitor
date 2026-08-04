"""Tests for safe presentation of hostile mailbox strings."""

from __future__ import annotations

from typing import Any, cast

import pytest

from mailjanitor.rendering import (
    redact_address,
    safe_display_text,
    safe_markdown_cell,
    spreadsheet_safe,
)


def test_links_are_defanged_and_never_left_clickable() -> None:
    rendered = safe_display_text("Review https://login.example.invalid/path now")

    assert "https[:]//" in rendered
    assert "example[.]invalid" in rendered
    assert "https://" not in rendered


def test_punycode_domain_is_defanged() -> None:
    rendered = safe_display_text("login.xn--bcher-kva.example")

    assert "login[.]xn--bcher-kva[.]example" in rendered


@pytest.mark.parametrize(
    "character",
    ["\n", "\0", "\u202e", "\u200b", "\u00ad", "\u2060", "\ufeff"],
)
def test_control_and_bidi_characters_are_made_visible(character: str) -> None:
    rendered = safe_display_text(f"before{character}after")

    assert "⟦U+" in rendered
    assert character not in rendered


def test_invisible_characters_cannot_hide_a_defanged_domain() -> None:
    rendered = safe_display_text("micro\u200bsoft.com")

    assert "microsoft.com" not in rendered
    assert "\u27e6U+200B\u27e7" in rendered


def test_output_is_bounded_before_expansion() -> None:
    assert safe_display_text("abcdef", maximum=3) == "abc…"


def test_markdown_table_syntax_is_escaped() -> None:
    rendered = safe_markdown_cell("[click](https://example.invalid) | next")

    assert "\\[click\\]" in rendered
    assert "\\|" in rendered
    assert "https://" not in rendered


def test_addresses_are_redacted_and_defanged() -> None:
    assert redact_address("owner@example.invalid") == "o…@example[.]invalid"
    assert redact_address("malformed") == "[invalid-address]"


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_spreadsheet_formula_prefixes_are_neutralized(prefix: str) -> None:
    assert spreadsheet_safe(f"{prefix}SUM(A1:A2)").startswith("'")


def test_display_rejects_non_string_and_invalid_bound() -> None:
    with pytest.raises(TypeError, match="string"):
        safe_display_text(cast("Any", b"not text"))
    with pytest.raises(ValueError, match="between"):
        safe_display_text("text", maximum=0)


def test_address_redaction_rejects_non_string_and_empty_parts() -> None:
    with pytest.raises(TypeError, match="string"):
        redact_address(cast("Any", None))
    assert redact_address("@example.invalid") == "[invalid-address]"
    assert redact_address("owner@") == "[invalid-address]"
    assert redact_address("owner@invalid domain.example") == "[invalid-address]"
    assert redact_address("o\nwner@example.invalid") == "[invalid-address]"
    assert redact_address(f"owner@{'a' * 320}.invalid") == "[invalid-address]"


def test_non_formula_spreadsheet_value_is_unchanged() -> None:
    assert spreadsheet_safe("ordinary value") == "ordinary value"
