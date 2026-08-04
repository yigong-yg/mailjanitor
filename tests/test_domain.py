"""Security and determinism tests for immutable domain values."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta, timezone

import pytest

import mailjanitor.domain as domain_module
from mailjanitor.domain import (
    ActionType,
    ApprovedMailboxCommand,
    FolderRef,
    HeaderMetadata,
    HeaderName,
    MailboxItemRef,
    MailboxProfileRef,
    MailboxSnapshot,
    MessageMetadata,
    MoveMessage,
    ProviderKind,
    SetCategory,
    SetReadState,
    normalize_domain,
)

DIGEST = f"sha256:{'a' * 64}"
OTHER_DIGEST = f"sha256:{'b' * 64}"
NOW = datetime(2026, 8, 3, 18, 0, tzinfo=UTC)


def make_profile(profile_id: str = "profile_demo") -> MailboxProfileRef:
    return MailboxProfileRef(
        provider=ProviderKind.FIXTURE,
        profile_id=profile_id,
    )


def make_ref(
    item_id: str = "item-001",
    *,
    profile: MailboxProfileRef | None = None,
    folder_id: str = "inbox",
) -> MailboxItemRef:
    return MailboxItemRef(
        profile=profile or make_profile(),
        provider_id=item_id,
        folder_id=folder_id,
        change_token="version-1",
    )


def make_message(item_id: str = "item-001", **changes: object) -> MessageMetadata:
    values: dict[str, object] = {
        "ref": make_ref(item_id),
        "sender_address": "alerts@security.example.invalid",
        "sender_domain": "security.example.invalid",
        "sender_display_name": "Example Security",
        "subject": "Synthetic security notice",
        "received_at": NOW,
        "is_read": False,
        "has_attachments": False,
        "headers": (
            HeaderMetadata(
                name=HeaderName.LIST_UNSUBSCRIBE,
                value="<https://example.invalid/u>",
            ),
        ),
    }
    values.update(changes)
    return MessageMetadata(**values)  # type: ignore[arg-type]


def test_metadata_schema_has_no_body_or_attachment_content_fields() -> None:
    modelled = {field.name.casefold() for field in fields(MessageMetadata)}

    assert "body" not in modelled
    assert "body_preview" not in modelled
    assert "html_body" not in modelled
    assert "attachment_names" not in modelled
    assert "attachment_content" not in modelled


def test_metadata_is_immutable_and_normalizes_domain_and_time() -> None:
    mountain = timezone(timedelta(hours=-6))
    message = make_message(
        sender_address="Owner@BÜCHER.Example",
        sender_domain="BÜCHER.Example",
        received_at=datetime(2026, 8, 3, 12, 0, tzinfo=mountain),
    )

    assert message.sender_domain == "xn--bcher-kva.example"
    assert message.received_at == NOW
    with pytest.raises(FrozenInstanceError):
        message.subject = "changed"  # type: ignore[misc]


def test_domain_normalization_accepts_unicode_and_ascii_idna_forms() -> None:
    assert normalize_domain("b\u00fccher.example") == "xn--bcher-kva.example"
    assert normalize_domain("xn--bcher-kva.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("domain", ["ex\u200dample.com", "\ufeffexample.com"])
def test_domain_normalization_rejects_unicode_format_characters(domain: str) -> None:
    with pytest.raises(ValueError, match="format character"):
        normalize_domain(domain)


@pytest.mark.parametrize(
    "domain",
    ["fa\u00df.example", "\uff45xample.com", "example\u3002com"],
)
def test_domain_normalization_rejects_compatibility_mappings(domain: str) -> None:
    with pytest.raises(ValueError, match="round-trip"):
        normalize_domain(domain)


@pytest.mark.parametrize("hostile", ["line\nbreak", "nul\0byte", "right\u202eto-left"])
def test_hostile_control_text_is_rejected(hostile: str) -> None:
    with pytest.raises(ValueError, match="control"):
        make_message(subject=hostile)


def test_unknown_header_is_outside_closed_allowlist() -> None:
    with pytest.raises(ValueError, match="valid HeaderName"):
        HeaderName("x-agent-command")


@pytest.mark.parametrize(
    ("has_attachments", "count"),
    [(False, 1), (True, 0), (True, -1), (False, -1)],
)
def test_attachment_flag_and_count_must_agree(
    has_attachments: bool, count: int
) -> None:
    with pytest.raises(ValueError, match="attachment"):
        make_message(has_attachments=has_attachments, attachment_count=count)


def test_snapshot_digest_is_stable_under_input_order() -> None:
    first = make_message("item-001")
    second = make_message("item-002")
    common = {
        "snapshot_id": "snapshot-001",
        "profile": make_profile(),
        "as_of": NOW,
        "adapter_version": "1.0",
        "capability_digest": DIGEST,
        "scope_folder_ids": ("inbox",),
    }

    left = MailboxSnapshot(messages=(second, first), **common)  # type: ignore[arg-type]
    right = MailboxSnapshot(messages=(first, second), **common)  # type: ignore[arg-type]

    assert left.messages == (first, second)
    assert left.digest == right.digest


def test_snapshot_rejects_an_oversized_canonical_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(domain_module, "MAX_SNAPSHOT_BYTES", 1)

    with pytest.raises(ValueError, match="canonical byte size"):
        MailboxSnapshot(
            snapshot_id="snapshot-001",
            profile=make_profile(),
            as_of=NOW,
            adapter_version="1.0",
            capability_digest=DIGEST,
            scope_folder_ids=("inbox",),
            messages=(make_message(),),
        )


def test_cross_profile_snapshot_item_is_rejected() -> None:
    message = make_message(ref=make_ref(profile=make_profile("profile_other")))

    with pytest.raises(ValueError, match="snapshot profile"):
        MailboxSnapshot(
            snapshot_id="snapshot-001",
            profile=make_profile(),
            as_of=NOW,
            adapter_version="1.0",
            capability_digest=DIGEST,
            scope_folder_ids=("inbox",),
            messages=(message,),
        )


def test_state_fingerprint_excludes_display_content() -> None:
    original = make_message(subject="One synthetic subject")
    changed_display = make_message(subject="Different synthetic subject")
    changed_state = make_message(is_read=True)

    assert original.state_fingerprint == changed_display.state_fingerprint
    assert original.state_fingerprint != changed_state.state_fingerprint


def make_command(action: SetReadState | SetCategory) -> ApprovedMailboxCommand:
    return ApprovedMailboxCommand(
        action_id="action-001",
        proposal_digest=DIGEST,
        approval_digest=OTHER_DIGEST,
        line_digest=DIGEST,
        approval_id="approval-001",
        mailbox_ref=f"mbx_{'1' * 32}",
        target=make_ref(),
        expected_state_fingerprint=DIGEST,
        action=action,
        idempotency_key=OTHER_DIGEST,
    )


def test_typed_commands_have_closed_action_resolution() -> None:
    read = make_command(SetReadState(is_read=True))
    add = make_command(SetCategory(category="Review", present=True))
    remove = make_command(SetCategory(category="Review", present=False))

    assert read.action_type is ActionType.SET_READ_STATE
    assert add.action_type is ActionType.ADD_CATEGORY
    assert remove.action_type is ActionType.REMOVE_CATEGORY


def test_move_action_requires_exact_destination() -> None:
    with pytest.raises(ValueError, match="exact resource"):
        MoveMessage(destination=FolderRef(profile=make_profile(), folder_id="*"))


def test_domain_normalization_refuses_single_label_domains() -> None:
    with pytest.raises(ValueError, match="fully qualified"):
        normalize_domain("localhost")
