"""Contract tests for the narrow provider ports."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mailjanitor.domain import (
    ActionType,
    MailboxItemRef,
    MailboxProfileRef,
    MessageMetadata,
    ProviderKind,
)
from mailjanitor.ports import (
    AdapterIdentity,
    CurrentItemState,
    MailboxAdapterError,
    MetadataPage,
    MetadataPageRequest,
    ProviderErrorCode,
    ReaderCapabilities,
    WriterCapabilities,
    WriteResult,
    WriteStatus,
)

DIGEST = f"sha256:{'a' * 64}"


def make_profile(profile_id: str = "profile_demo") -> MailboxProfileRef:
    return MailboxProfileRef(
        provider=ProviderKind.FIXTURE,
        profile_id=profile_id,
    )


def make_ref(*, profile: MailboxProfileRef | None = None) -> MailboxItemRef:
    return MailboxItemRef(
        profile=profile or make_profile(),
        provider_id="item-001",
        folder_id="inbox",
        change_token="version-1",
    )


def make_message(*, profile: MailboxProfileRef | None = None) -> MessageMetadata:
    return MessageMetadata(
        ref=make_ref(profile=profile),
        sender_address="sender@example.invalid",
        sender_domain="example.invalid",
        subject="Synthetic message",
        received_at=datetime(2026, 8, 3, 18, 0, tzinfo=UTC),
        is_read=False,
        has_attachments=False,
    )


def test_capabilities_bind_to_exact_profile_and_account() -> None:
    identity = AdapterIdentity(profile=make_profile(), account_fingerprint=DIGEST)

    reader = ReaderCapabilities(
        identity=identity,
        strong_change_tokens=True,
        stable_item_ids=True,
    )
    writer = WriterCapabilities(
        identity=identity,
        supported_actions=frozenset({ActionType.MOVE_MESSAGE}),
        strong_preconditions=True,
    )

    assert reader.identity is writer.identity
    assert reader.provider is ProviderKind.FIXTURE
    assert writer.supported_actions == {ActionType.MOVE_MESSAGE}


def test_writer_cannot_advertise_empty_action_set() -> None:
    identity = AdapterIdentity(profile=make_profile(), account_fingerprint=DIGEST)

    with pytest.raises(ValueError, match="at least one typed action"):
        WriterCapabilities(
            identity=identity,
            supported_actions=frozenset(),
            strong_preconditions=True,
        )


def test_page_rejects_cross_profile_items() -> None:
    with pytest.raises(ValueError, match="page profile"):
        MetadataPage(
            profile=make_profile(),
            items=(make_message(profile=make_profile("profile_other")),),
        )


@pytest.mark.parametrize("cursor", ["$filter=body", "line\nbreak", "*", ""])
def test_raw_query_or_wildcard_cursors_are_unrepresentable(cursor: str) -> None:
    with pytest.raises(ValueError, match="cursor"):
        MetadataPageRequest(
            profile=make_profile(),
            folder_ids=("inbox",),
            cursor=cursor,
        )


def test_normalized_adapter_error_contains_no_provider_text() -> None:
    error = MailboxAdapterError(ProviderErrorCode.PERMISSION_DENIED)

    assert error.code is ProviderErrorCode.PERMISSION_DENIED
    assert str(error) == "permission_denied"


def test_current_state_requires_only_reconciliation_fields() -> None:
    state = CurrentItemState(ref=make_ref(), is_read=False)

    assert state.ref.provider_id == "item-001"
    assert state.state_fingerprint.startswith("sha256:")
    assert not hasattr(state, "subject")
    assert not hasattr(state, "body")


def test_successful_write_requires_resulting_reference() -> None:
    with pytest.raises(ValueError, match="resulting reference"):
        WriteResult(status=WriteStatus.SUCCEEDED)


def test_unknown_write_has_explicit_normalized_code() -> None:
    result = WriteResult(
        status=WriteStatus.OUTCOME_UNKNOWN,
        error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
    )

    assert result.status is WriteStatus.OUTCOME_UNKNOWN
    assert result.new_ref is None
