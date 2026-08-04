"""Tests for integrity-grade canonical JSON."""

from __future__ import annotations

from collections import UserDict

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mailjanitor.canonical import (
    CanonicalizationError,
    canonical_bytes,
    canonical_digest,
)


def test_canonical_encoding_is_key_order_independent() -> None:
    left = {"z": [3, True, None], "a": "value"}
    right = {"a": "value", "z": [3, True, None]}

    assert canonical_bytes(left) == b'{"a":"value","z":[3,true,null]}'
    assert canonical_bytes(left) == canonical_bytes(right)
    assert canonical_digest(left) == canonical_digest(right)


@pytest.mark.parametrize(
    "value",
    [
        1.25,
        {1: "not-a-string-key"},
        ("tuple",),
        UserDict({"custom": "mapping"}),
        "\ud800",
        1 << 53,
    ],
)
def test_unsupported_values_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_excessive_depth_is_rejected() -> None:
    value: object = None
    for _ in range(34):
        value = [value]

    with pytest.raises(CanonicalizationError, match="depth"):
        canonical_bytes(value)


@given(st.dictionaries(st.text(), st.integers(-(1 << 53) + 1, (1 << 53) - 1)))
def test_repeated_encoding_is_byte_stable(value: dict[str, int]) -> None:
    assert canonical_bytes(value) == canonical_bytes(dict(reversed(value.items())))
