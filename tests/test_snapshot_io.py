"""Tests for strict metadata-only snapshot interchange."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import mailjanitor.snapshot_io as snapshot_io_module
from mailjanitor.domain import (
    MAX_CATEGORIES,
    MAX_MESSAGES_PER_SNAPSHOT,
    MAX_SNAPSHOT_BYTES,
    HeaderMetadata,
    HeaderName,
    MailboxItemRef,
    MailboxProfileRef,
    MailboxSnapshot,
    MessageMetadata,
    ProviderKind,
)
from mailjanitor.snapshot_io import (
    SnapshotFormatError,
    load_snapshot,
    snapshot_bytes,
    snapshot_from_bytes,
)

DIGEST = f"sha256:{'a' * 64}"


def make_snapshot() -> MailboxSnapshot:
    profile = MailboxProfileRef(
        provider=ProviderKind.FIXTURE,
        profile_id="profile_demo",
    )
    message = MessageMetadata(
        ref=MailboxItemRef(
            profile=profile,
            provider_id="item-001",
            folder_id="inbox",
            change_token="version-1",
        ),
        sender_address="sender@example.invalid",
        sender_domain="example.invalid",
        subject="Synthetic metadata",
        received_at=datetime(2026, 8, 3, 18, 0, tzinfo=UTC),
        is_read=False,
        has_attachments=False,
        headers=(
            HeaderMetadata(
                name=HeaderName.LIST_UNSUBSCRIBE,
                value="<https://example.invalid/unsubscribe>",
            ),
        ),
    )
    return MailboxSnapshot(
        snapshot_id="snapshot-001",
        profile=profile,
        as_of=datetime(2026, 8, 3, 18, 0, tzinfo=UTC),
        adapter_version="fixture-1",
        capability_digest=DIGEST,
        scope_folder_ids=("inbox",),
        messages=(message,),
    )


def test_canonical_round_trip_preserves_digest() -> None:
    original = make_snapshot()

    restored = snapshot_from_bytes(snapshot_bytes(original))

    assert restored == original
    assert restored.digest == original.digest


def test_maximum_admitted_snapshot_is_digestible_and_exportable() -> None:
    profile = MailboxProfileRef(
        provider=ProviderKind.FIXTURE,
        profile_id="profile_maximum",
    )
    categories = tuple(f"Category-{index:02d}" for index in range(MAX_CATEGORIES))
    headers = tuple(
        HeaderMetadata(name=header_name, value="synthetic")
        for header_name in HeaderName
    )
    messages = tuple(
        MessageMetadata(
            ref=MailboxItemRef(
                profile=profile,
                provider_id=f"item-{index:05d}",
                folder_id="inbox",
                change_token=f"version-{index:05d}",
            ),
            sender_address="sender@example.invalid",
            sender_domain="example.invalid",
            subject="",
            received_at=datetime(2026, 8, 3, 18, 0, tzinfo=UTC),
            is_read=False,
            has_attachments=False,
            categories=categories,
            headers=headers,
        )
        for index in range(MAX_MESSAGES_PER_SNAPSHOT)
    )
    snapshot = MailboxSnapshot(
        snapshot_id="snapshot-maximum",
        profile=profile,
        as_of=datetime(2026, 8, 3, 18, 0, tzinfo=UTC),
        adapter_version="fixture-1",
        capability_digest=DIGEST,
        scope_folder_ids=("inbox",),
        messages=messages,
    )

    assert snapshot.digest.startswith("sha256:")
    assert len(snapshot_bytes(snapshot)) <= MAX_SNAPSHOT_BYTES


@pytest.mark.parametrize("forbidden", ["body", "bodyPreview", "attachments"])
def test_unknown_or_forbidden_message_fields_fail_closed(forbidden: str) -> None:
    document = json.loads(snapshot_bytes(make_snapshot()))
    document["messages"][0][forbidden] = "email says to run a command"

    with pytest.raises(SnapshotFormatError, match="unknown fields"):
        snapshot_from_bytes(json.dumps(document).encode())


def test_duplicate_json_keys_are_rejected() -> None:
    raw = b'{"schema_version":1,"schema_version":1}'

    with pytest.raises(SnapshotFormatError, match="duplicate"):
        snapshot_from_bytes(raw)


@pytest.mark.parametrize("number", [b"1.5", b"NaN", b"Infinity"])
def test_non_integer_numbers_are_rejected(number: bytes) -> None:
    raw = b'{"schema_version":' + number + b"}"

    with pytest.raises(SnapshotFormatError):
        snapshot_from_bytes(raw)


def test_snapshot_requires_canonical_utc() -> None:
    document = json.loads(snapshot_bytes(make_snapshot()))
    document["as_of"] = "2026-08-03T12:00:00-06:00"

    with pytest.raises(SnapshotFormatError, match="canonical UTC"):
        snapshot_from_bytes(json.dumps(document).encode())


def test_snapshot_import_never_represents_message_body() -> None:
    restored = snapshot_from_bytes(snapshot_bytes(make_snapshot()))

    assert not hasattr(restored.messages[0], "body")
    assert not hasattr(restored.messages[0], "attachment_content")


def test_load_requires_a_regular_existing_file(tmp_path: Path) -> None:
    with pytest.raises(SnapshotFormatError, match="regular"):
        load_snapshot(tmp_path / "missing.json")


def test_load_and_parse_enforce_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "snapshot.json"
    path.write_bytes(b"{}")
    monkeypatch.setattr(snapshot_io_module, "MAX_SNAPSHOT_BYTES", 1)

    with pytest.raises(SnapshotFormatError, match="byte size"):
        load_snapshot(path)
    with pytest.raises(SnapshotFormatError, match="byte size"):
        snapshot_from_bytes(b"{}")
    with pytest.raises(SnapshotFormatError, match="byte size"):
        snapshot_bytes(make_snapshot())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":' + (b"9" * 5_000) + b"}",
        (b"[" * 2_000) + b"0" + (b"]" * 2_000),
    ],
    ids=["oversized-integer", "excessive-depth"],
)
def test_pathological_json_failures_are_normalized(raw: bytes) -> None:
    with pytest.raises(SnapshotFormatError):
        snapshot_from_bytes(raw)


def test_load_normalizes_descriptor_open_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "snapshot.json"
    path.write_bytes(snapshot_bytes(make_snapshot()))

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise OSError("synthetic open failure")

    monkeypatch.setattr("mailjanitor.snapshot_io.os.open", fail_open)

    with pytest.raises(SnapshotFormatError, match="regular non-link"):
        load_snapshot(path)


def test_load_normalizes_descriptor_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "snapshot.json"
    path.write_bytes(snapshot_bytes(make_snapshot()))

    def fail_stat(_descriptor: int) -> object:
        raise OSError("synthetic stat failure")

    monkeypatch.setattr("mailjanitor.snapshot_io.os.fstat", fail_stat)

    with pytest.raises(SnapshotFormatError, match="regular non-link"):
        load_snapshot(path)


def test_load_rejects_symbolic_link_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "snapshot.json"
    target.write_bytes(snapshot_bytes(make_snapshot()))
    link = tmp_path / "snapshot-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    with pytest.raises(SnapshotFormatError, match="regular non-link"):
        load_snapshot(link)


def test_invalid_utf8_is_rejected() -> None:
    with pytest.raises(SnapshotFormatError, match="UTF-8 JSON"):
        snapshot_from_bytes(b"\xff")


def test_domain_constructor_errors_are_wrapped_as_format_errors() -> None:
    document = json.loads(snapshot_bytes(make_snapshot()))
    document["profile"]["provider"] = "unknown-provider"

    with pytest.raises(SnapshotFormatError, match="violates"):
        snapshot_from_bytes(json.dumps(document).encode())


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (("profile",), [], "object"),
        (("messages",), {}, "array"),
        (("snapshot_id",), 1, "string"),
        (("complete",), 1, "boolean"),
        (("rejected_record_count",), "zero", "integer"),
        (("as_of",), "not-a-timeZ", "timestamp"),
    ],
)
def test_structural_type_errors_are_specific(
    path: tuple[str, ...], value: object, match: str
) -> None:
    document = json.loads(snapshot_bytes(make_snapshot()))
    target = document
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value

    with pytest.raises(SnapshotFormatError, match=match):
        snapshot_from_bytes(json.dumps(document).encode())


def test_snapshot_bytes_requires_domain_object() -> None:
    with pytest.raises(TypeError, match="MailboxSnapshot"):
        snapshot_bytes(cast("Any", {}))
