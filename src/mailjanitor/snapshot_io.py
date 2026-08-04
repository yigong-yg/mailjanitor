"""Strict, bounded import/export for protected metadata snapshots."""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Final, cast

from mailjanitor.canonical import JsonValue, canonical_bytes
from mailjanitor.domain import (
    MAX_SNAPSHOT_BYTES,
    HeaderMetadata,
    HeaderName,
    Importance,
    MailboxItemRef,
    MailboxProfileRef,
    MailboxSnapshot,
    MessageMetadata,
    ProviderKind,
)

_MAX_SAFE_INTEGER: Final = (1 << 53) - 1
_MAX_SAFE_INTEGER_DIGITS: Final = 16
# ``datetime.fromisoformat`` also accepts basic format, a space separator, and a
# comma fraction.  Those spellings parse to the same instant, so accepting them
# would let textually different files share one snapshot digest.  Match only the
# exact spelling the exporter emits.
_CANONICAL_UTC_RE: Final = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z"
)
_NOFOLLOW_FLAG: Final = getattr(os, "O_NOFOLLOW", 0)
_OPEN_FLAGS: Final = (
    os.O_RDONLY
    | _NOFOLLOW_FLAG
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOINHERIT", 0)
)

_SNAPSHOT_KEYS: Final = frozenset(
    {
        "schema_version",
        "snapshot_id",
        "profile",
        "as_of",
        "adapter_version",
        "capability_digest",
        "scope_folder_ids",
        "messages",
        "rejected_record_count",
        "complete",
    }
)
_PROFILE_KEYS: Final = frozenset({"provider", "profile_id"})
_MESSAGE_KEYS: Final = frozenset(
    {
        "ref",
        "sender_address",
        "sender_domain",
        "sender_display_name",
        "subject",
        "received_at",
        "is_read",
        "has_attachments",
        "is_flagged",
        "importance",
        "categories",
        "attachment_count",
        "headers",
    }
)
_REF_KEYS: Final = frozenset({"profile", "provider_id", "folder_id", "change_token"})
_HEADER_KEYS: Final = frozenset({"name", "value"})


class SnapshotFormatError(ValueError):
    """Raised when an input is not the exact metadata-only snapshot schema."""


def load_snapshot(path: Path) -> MailboxSnapshot:
    """Read one regular local file without following links or contacting a provider."""
    raw = _read_regular_file(path)
    return snapshot_from_bytes(raw)


def snapshot_from_bytes(raw: bytes) -> MailboxSnapshot:
    """Parse a bounded UTF-8 JSON snapshot with duplicate-key detection."""
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotFormatError("snapshot exceeds maximum byte size")
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_int=_bounded_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except SnapshotFormatError:
        raise
    except (RecursionError, ValueError) as exc:
        raise SnapshotFormatError("snapshot is not valid UTF-8 JSON") from exc
    try:
        return _snapshot(_mapping(parsed, "snapshot", _SNAPSHOT_KEYS))
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, SnapshotFormatError):
            raise
        raise SnapshotFormatError("snapshot violates the metadata schema") from exc


def snapshot_bytes(snapshot: MailboxSnapshot) -> bytes:
    """Return canonical bytes suitable for protected local state."""
    if not isinstance(snapshot, MailboxSnapshot):
        raise TypeError("snapshot must be a MailboxSnapshot")
    encoded = canonical_bytes(snapshot.as_canonical_dict())
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise SnapshotFormatError("snapshot exceeds maximum byte size")
    return encoded


def _read_regular_file(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        if not _NOFOLLOW_FLAG and stat.S_ISLNK(os.lstat(path).st_mode):
            raise SnapshotFormatError(
                "snapshot path must be a readable regular non-link file"
            )
        descriptor = os.open(path, _OPEN_FLAGS)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise SnapshotFormatError(
                "snapshot path must be a readable regular non-link file"
            )
        if file_status.st_size > MAX_SNAPSHOT_BYTES:
            raise SnapshotFormatError("snapshot exceeds maximum byte size")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
    except SnapshotFormatError:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotFormatError(
            "snapshot path must be a readable regular non-link file"
        ) from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotFormatError("snapshot exceeds maximum byte size")
    return raw


def _snapshot(value: dict[str, object]) -> MailboxSnapshot:
    schema_version = _integer(value["schema_version"], "schema_version")
    profile = _profile(value["profile"])
    messages = tuple(_message(item) for item in _array(value["messages"], "messages"))
    return MailboxSnapshot(
        schema_version=schema_version,
        snapshot_id=_string(value["snapshot_id"], "snapshot_id"),
        profile=profile,
        as_of=_utc(value["as_of"], "as_of"),
        adapter_version=_string(value["adapter_version"], "adapter_version"),
        capability_digest=_string(value["capability_digest"], "capability_digest"),
        scope_folder_ids=_string_tuple(value["scope_folder_ids"], "scope_folder_ids"),
        messages=messages,
        rejected_record_count=_integer(
            value["rejected_record_count"], "rejected_record_count"
        ),
        complete=_boolean(value["complete"], "complete"),
    )


def _profile(value: object) -> MailboxProfileRef:
    mapped = _mapping(value, "profile", _PROFILE_KEYS)
    return MailboxProfileRef(
        provider=ProviderKind(_string(mapped["provider"], "provider")),
        profile_id=_string(mapped["profile_id"], "profile_id"),
    )


def _message(value: object) -> MessageMetadata:
    mapped = _mapping(value, "message", _MESSAGE_KEYS)
    raw_count = mapped["attachment_count"]
    attachment_count = (
        None if raw_count is None else _integer(raw_count, "attachment_count")
    )
    return MessageMetadata(
        ref=_item_ref(mapped["ref"]),
        sender_address=_string(mapped["sender_address"], "sender_address"),
        sender_domain=_string(mapped["sender_domain"], "sender_domain"),
        sender_display_name=_string(
            mapped["sender_display_name"], "sender_display_name"
        ),
        subject=_string(mapped["subject"], "subject"),
        received_at=_utc(mapped["received_at"], "received_at"),
        is_read=_boolean(mapped["is_read"], "is_read"),
        has_attachments=_boolean(mapped["has_attachments"], "has_attachments"),
        is_flagged=_boolean(mapped["is_flagged"], "is_flagged"),
        importance=Importance(_string(mapped["importance"], "importance")),
        categories=_string_tuple(mapped["categories"], "categories"),
        attachment_count=attachment_count,
        headers=tuple(_header(item) for item in _array(mapped["headers"], "headers")),
    )


def _item_ref(value: object) -> MailboxItemRef:
    mapped = _mapping(value, "message ref", _REF_KEYS)
    raw_token = mapped["change_token"]
    return MailboxItemRef(
        profile=_profile(mapped["profile"]),
        provider_id=_string(mapped["provider_id"], "provider_id"),
        folder_id=_string(mapped["folder_id"], "folder_id"),
        change_token=(
            None if raw_token is None else _string(raw_token, "change_token")
        ),
    )


def _header(value: object) -> HeaderMetadata:
    mapped = _mapping(value, "header", _HEADER_KEYS)
    return HeaderMetadata(
        name=HeaderName(_string(mapped["name"], "header name")),
        value=_string(mapped["value"], "header value"),
    )


def _mapping(
    value: object,
    name: str,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict:
        raise SnapshotFormatError(f"{name} must be an object")
    mapped = cast("dict[str, object]", value)
    if frozenset(mapped) != keys:
        raise SnapshotFormatError(f"{name} has missing or unknown fields")
    return mapped


def _array(value: object, name: str) -> list[object]:
    if type(value) is not list:
        raise SnapshotFormatError(f"{name} must be an array")
    return cast("list[object]", value)


def _string(value: object, name: str) -> str:
    if type(value) is not str:
        raise SnapshotFormatError(f"{name} must be a string")
    return value


def _boolean(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise SnapshotFormatError(f"{name} must be a boolean")
    return value


def _integer(value: object, name: str) -> int:
    if type(value) is not int:
        raise SnapshotFormatError(f"{name} must be an integer")
    return value


def _bounded_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > _MAX_SAFE_INTEGER_DIGITS:
        raise SnapshotFormatError("snapshot integer exceeds interoperable JSON range")
    parsed = int(value)
    if abs(parsed) > _MAX_SAFE_INTEGER:
        raise SnapshotFormatError("snapshot integer exceeds interoperable JSON range")
    return parsed


def _string_tuple(value: object, name: str) -> tuple[str, ...]:
    return tuple(_string(item, name) for item in _array(value, name))


def _utc(value: object, name: str) -> datetime:
    text = _string(value, name)
    if _CANONICAL_UTC_RE.fullmatch(text) is None:
        raise SnapshotFormatError(f"{name} must be canonical UTC")
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise SnapshotFormatError(f"{name} is not a timestamp") from exc


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotFormatError("snapshot contains a duplicate object key")
        result[key] = value
    return result


def _reject_number(value: str) -> JsonValue:
    raise SnapshotFormatError(f"unsupported JSON number: {value}")
