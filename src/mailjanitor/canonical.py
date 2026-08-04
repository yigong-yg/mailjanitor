"""Canonical JSON primitives used by integrity-bound artifacts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Final, cast

import rfc8785

type JsonScalar = bool | int | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

_MAX_DEPTH: Final = 32
# A sealed snapshot may contain up to 500 messages.  Even when every message
# uses the maximum category and header cardinality, its canonical structure
# remains below one hundred thousand nodes.  Keep this budget aligned with
# ``domain.MAX_MESSAGES_PER_SNAPSHOT`` so a domain-valid snapshot cannot fail
# merely because the canonicalizer has a smaller structural limit.
MAX_CANONICAL_NODES: Final = 100_000
_MAX_STRING_BYTES: Final = 1_048_576
_MAX_SAFE_INTEGER: Final = (1 << 53) - 1


class CanonicalizationError(ValueError):
    """Raised when a value is outside mailjanitor's canonical JSON profile."""


def canonical_bytes(value: object) -> bytes:
    """Return RFC 8785 bytes after validating the restricted artifact profile.

    Artifact schemas intentionally exclude floats, non-string mapping keys,
    custom containers, excessive nesting, and integers that cannot be
    represented exactly by interoperable JSON implementations.
    """
    _validate(value, depth=0, budget=[MAX_CANONICAL_NODES])
    try:
        return rfc8785.dumps(cast("JsonValue", value))
    except (rfc8785.CanonicalizationError, UnicodeError) as exc:
        raise CanonicalizationError("value cannot be canonically encoded") from exc


def canonical_digest(value: object) -> str:
    """Return a lowercase, algorithm-labelled SHA-256 content digest."""
    return f"sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def _validate(value: object, *, depth: int, budget: list[int]) -> None:
    if depth > _MAX_DEPTH:
        raise CanonicalizationError("canonical value exceeds maximum depth")
    budget[0] -= 1
    if budget[0] < 0:
        raise CanonicalizationError("canonical value exceeds maximum node count")

    if value is None or type(value) in {bool, int, str}:
        _validate_scalar(value)
        return
    if type(value) is list:
        _validate_list(value, depth=depth, budget=budget)
        return
    if type(value) is dict:
        _validate_dict(value, depth=depth, budget=budget)
        return

    if isinstance(value, (float, Mapping, Sequence)):
        raise CanonicalizationError(
            "canonical profile accepts only built-in dict/list containers and no floats"
        )
    raise CanonicalizationError(
        f"unsupported canonical value type: {type(value).__name__}"
    )


def _validate_scalar(value: object) -> None:
    if type(value) is int and abs(value) > _MAX_SAFE_INTEGER:
        raise CanonicalizationError("integer exceeds interoperable JSON range")
    if type(value) is not str:
        return
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("string contains an invalid surrogate") from exc
    if len(encoded) > _MAX_STRING_BYTES:
        raise CanonicalizationError("canonical string exceeds maximum length")


def _validate_list(value: list[object], *, depth: int, budget: list[int]) -> None:
    for item in value:
        _validate(item, depth=depth + 1, budget=budget)


def _validate_dict(
    value: dict[object, object], *, depth: int, budget: list[int]
) -> None:
    for key, item in value.items():
        if type(key) is not str:
            raise CanonicalizationError("canonical mapping keys must be strings")
        _validate(key, depth=depth + 1, budget=budget)
        _validate(item, depth=depth + 1, budget=budget)
