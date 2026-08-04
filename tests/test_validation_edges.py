"""Negative-path coverage for the core's fail-closed constructors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from mailjanitor.domain import (
    MAX_FOLDERS_PER_SNAPSHOT,
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
from mailjanitor.ports import (
    AdapterIdentity,
    CurrentItemState,
    MailboxAdapterError,
    MetadataPage,
    MetadataPageRequest,
    ProviderErrorCode,
    ReaderCapabilities,
    Reconciliation,
    ReconciliationStatus,
    WriterCapabilities,
    WriteResult,
    WriteStatus,
)

DIGEST = f"sha256:{'a' * 64}"
OTHER_DIGEST = f"sha256:{'b' * 64}"
NOW = datetime(2026, 8, 3, 18, 0, tzinfo=UTC)


def profile(profile_id: str = "profile_demo") -> MailboxProfileRef:
    return MailboxProfileRef(
        provider=ProviderKind.FIXTURE,
        profile_id=profile_id,
    )


def item_ref(*, item_profile: MailboxProfileRef | None = None) -> MailboxItemRef:
    return MailboxItemRef(
        profile=item_profile or profile(),
        provider_id="item-001",
        folder_id="inbox",
        change_token="version-1",
    )


def message() -> MessageMetadata:
    return MessageMetadata(
        ref=item_ref(),
        sender_address="sender@example.invalid",
        sender_domain="example.invalid",
        subject="Synthetic",
        received_at=NOW,
        is_read=False,
        has_attachments=False,
    )


def snapshot() -> MailboxSnapshot:
    return MailboxSnapshot(
        snapshot_id="snapshot-001",
        profile=profile(),
        as_of=NOW,
        adapter_version="fixture-1",
        capability_digest=DIGEST,
        scope_folder_ids=("inbox",),
        messages=(message(),),
    )


def command() -> ApprovedMailboxCommand:
    return ApprovedMailboxCommand(
        action_id="action-001",
        proposal_digest=DIGEST,
        approval_digest=OTHER_DIGEST,
        line_digest=DIGEST,
        approval_id="approval-001",
        mailbox_ref=f"mbx_{'1' * 32}",
        target=item_ref(),
        expected_state_fingerprint=DIGEST,
        action=SetReadState(is_read=True),
        idempotency_key=OTHER_DIGEST,
    )


@pytest.mark.parametrize(
    ("factory", "error_type", "match"),
    [
        (
            lambda: MailboxProfileRef(
                provider=cast("Any", "fixture"), profile_id="profile_demo"
            ),
            TypeError,
            "ProviderKind",
        ),
        (lambda: profile("bad token"), ValueError, "opaque token"),
        (
            lambda: FolderRef(profile=cast("Any", object()), folder_id="inbox"),
            TypeError,
            "MailboxProfileRef",
        ),
        (
            lambda: FolderRef(profile=profile(), folder_id=" inbox"),
            ValueError,
            "whitespace",
        ),
        (
            lambda: MailboxItemRef(
                profile=cast("Any", object()),
                provider_id="item-001",
                folder_id="inbox",
            ),
            TypeError,
            "MailboxProfileRef",
        ),
        (
            lambda: HeaderMetadata(
                name=cast("Any", "list-unsubscribe"), value="present"
            ),
            TypeError,
            "allowlisted",
        ),
        (
            lambda: replace(message(), ref=cast("Any", object())),
            TypeError,
            "MailboxItemRef",
        ),
        (
            lambda: replace(message(), subject="x" * 999),
            ValueError,
            "exceeds",
        ),
        (
            lambda: replace(message(), received_at=cast("Any", "not-a-time")),
            TypeError,
            "datetime",
        ),
        (
            lambda: replace(
                message(),
                received_at=datetime(2026, 8, 3),  # noqa: DTZ001 - invalid fixture
            ),
            ValueError,
            "timezone-aware",
        ),
        (
            lambda: replace(message(), is_read=cast("Any", 1)),
            TypeError,
            "bool",
        ),
        (
            lambda: replace(message(), importance=cast("Any", "high")),
            TypeError,
            "Importance",
        ),
        (
            lambda: replace(message(), sender_address="malformed"),
            ValueError,
            "one @",
        ),
        (
            lambda: replace(
                message(),
                sender_address="sender@other.invalid",
                sender_domain="example.invalid",
            ),
            ValueError,
            "do not agree",
        ),
        (
            lambda: replace(message(), attachment_count=cast("Any", "one")),
            TypeError,
            "attachment_count",
        ),
        (
            lambda: replace(snapshot(), schema_version=2),
            ValueError,
            "schema_version",
        ),
        (
            lambda: replace(snapshot(), profile=cast("Any", object())),
            TypeError,
            "MailboxProfileRef",
        ),
        (
            lambda: replace(snapshot(), rejected_record_count=cast("Any", "one")),
            TypeError,
            "rejected_record_count",
        ),
        (
            lambda: replace(snapshot(), rejected_record_count=-1),
            ValueError,
            "negative",
        ),
        (
            lambda: replace(
                snapshot(),
                scope_folder_ids=tuple(
                    f"folder-{index}" for index in range(MAX_FOLDERS_PER_SNAPSHOT + 1)
                ),
            ),
            ValueError,
            "too many scope folders",
        ),
        (
            lambda: MoveMessage(destination=cast("Any", object())),
            TypeError,
            "FolderRef",
        ),
        (
            lambda: SetReadState(is_read=cast("Any", 1)),
            TypeError,
            "bool",
        ),
        (
            lambda: SetCategory(category="Review", present=cast("Any", 1)),
            TypeError,
            "bool",
        ),
        (
            lambda: replace(command(), proposal_digest="invalid"),
            ValueError,
            "sha256",
        ),
        (
            lambda: replace(command(), mailbox_ref="owner@example.invalid"),
            ValueError,
            "pseudonym",
        ),
        (
            lambda: replace(command(), target=cast("Any", object())),
            TypeError,
            "MailboxItemRef",
        ),
        (
            lambda: replace(command(), action=cast("Any", object())),
            TypeError,
            "supported typed action",
        ),
        (
            lambda: replace(
                command(),
                action=MoveMessage(
                    destination=FolderRef(
                        profile=profile("profile_other"), folder_id="archive"
                    )
                ),
            ),
            ValueError,
            "share a mailbox profile",
        ),
        (
            lambda: normalize_domain(f"{'a' * 64}.example"),
            ValueError,
            "IDNA",
        ),
        (
            lambda: normalize_domain("bad_.example"),
            ValueError,
            "invalid label",
        ),
    ],
)
def test_domain_invalid_values_fail_closed(
    factory: Callable[[], object],
    error_type: type[BaseException],
    match: str,
) -> None:
    with pytest.raises(error_type, match=match):
        factory()


def identity() -> AdapterIdentity:
    return AdapterIdentity(profile=profile(), account_fingerprint=DIGEST)


def page_request() -> MetadataPageRequest:
    return MetadataPageRequest(profile=profile(), folder_ids=("inbox",))


def current_state() -> CurrentItemState:
    return CurrentItemState(ref=item_ref(), is_read=False)


@pytest.mark.parametrize(
    ("factory", "error_type", "match"),
    [
        (
            lambda: AdapterIdentity(
                profile=cast("Any", object()), account_fingerprint=DIGEST
            ),
            TypeError,
            "MailboxProfileRef",
        ),
        (
            lambda: ReaderCapabilities(
                identity=cast("Any", object()),
                strong_change_tokens=True,
                stable_item_ids=True,
            ),
            TypeError,
            "AdapterIdentity",
        ),
        (
            lambda: ReaderCapabilities(
                identity=identity(),
                strong_change_tokens=cast("Any", 1),
                stable_item_ids=True,
            ),
            TypeError,
            "bool",
        ),
        (
            lambda: ReaderCapabilities(
                identity=identity(),
                strong_change_tokens=True,
                stable_item_ids=True,
                supported_headers=cast("Any", (HeaderName.LIST_UNSUBSCRIBE,)),
            ),
            TypeError,
            "frozenset",
        ),
        (
            lambda: WriterCapabilities(
                identity=cast("Any", object()),
                supported_actions=frozenset({ActionType.SET_READ_STATE}),
                strong_preconditions=True,
            ),
            TypeError,
            "AdapterIdentity",
        ),
        (
            lambda: WriterCapabilities(
                identity=identity(),
                supported_actions=cast("Any", (ActionType.SET_READ_STATE,)),
                strong_preconditions=True,
            ),
            TypeError,
            "frozenset",
        ),
        (
            lambda: WriterCapabilities(
                identity=identity(),
                supported_actions=frozenset({ActionType.SET_READ_STATE}),
                strong_preconditions=cast("Any", 1),
            ),
            TypeError,
            "bool",
        ),
        (
            lambda: replace(page_request(), profile=cast("Any", object())),
            TypeError,
            "MailboxProfileRef",
        ),
        (
            lambda: replace(page_request(), folder_ids=()),
            ValueError,
            "non-empty",
        ),
        (
            lambda: replace(page_request(), folder_ids=("inbox", "inbox")),
            ValueError,
            "unique",
        ),
        (
            lambda: replace(page_request(), page_size=0),
            ValueError,
            "1 through 500",
        ),
        (
            lambda: replace(
                page_request(), headers=cast("Any", [HeaderName.LIST_UNSUBSCRIBE])
            ),
            TypeError,
            "tuple",
        ),
        (
            lambda: replace(
                page_request(),
                headers=(HeaderName.LIST_UNSUBSCRIBE, HeaderName.LIST_UNSUBSCRIBE),
            ),
            ValueError,
            "unique",
        ),
        (
            lambda: MetadataPage(profile=cast("Any", object()), items=(message(),)),
            TypeError,
            "MailboxProfileRef",
        ),
        (
            lambda: MetadataPage(profile=profile(), items=cast("Any", [message()])),
            TypeError,
            "tuple",
        ),
        (
            lambda: MetadataPage(
                profile=profile(),
                items=(message(),),
                rejected_record_count=cast("Any", "one"),
            ),
            TypeError,
            "rejected_record_count",
        ),
        (
            lambda: MetadataPage(
                profile=profile(), items=(message(),), rejected_record_count=-1
            ),
            ValueError,
            "negative",
        ),
        (
            lambda: CurrentItemState(ref=cast("Any", object()), is_read=False),
            TypeError,
            "MailboxItemRef",
        ),
        (
            lambda: CurrentItemState(ref=item_ref(), is_read=cast("Any", 1)),
            TypeError,
            "bool",
        ),
        (
            lambda: MailboxAdapterError(cast("Any", "not-found")),
            TypeError,
            "ProviderErrorCode",
        ),
        (
            lambda: WriteResult(status=cast("Any", "succeeded")),
            TypeError,
            "WriteStatus",
        ),
        (
            lambda: WriteResult(
                status=WriteStatus.SUCCEEDED, new_ref=cast("Any", object())
            ),
            TypeError,
            "MailboxItemRef",
        ),
        (
            lambda: WriteResult(
                status=WriteStatus.DEFINITE_FAILURE,
                error_code=cast("Any", "not-found"),
            ),
            TypeError,
            "ProviderErrorCode",
        ),
        (
            lambda: WriteResult(
                status=WriteStatus.SUCCEEDED,
                new_ref=item_ref(),
                error_code=ProviderErrorCode.CONFLICT,
            ),
            ValueError,
            "successful result",
        ),
        (
            lambda: WriteResult(status=WriteStatus.DEFINITE_FAILURE),
            ValueError,
            "requires an error_code",
        ),
        (
            lambda: WriteResult(
                status=WriteStatus.DEFINITE_FAILURE,
                new_ref=item_ref(),
                error_code=ProviderErrorCode.CONFLICT,
            ),
            ValueError,
            "cannot assert",
        ),
        (
            lambda: Reconciliation(status=cast("Any", "unknown")),
            TypeError,
            "ReconciliationStatus",
        ),
        (
            lambda: Reconciliation(
                status=ReconciliationStatus.NOT_PRESENT,
                current=cast("Any", object()),
            ),
            TypeError,
            "CurrentItemState",
        ),
        (
            lambda: Reconciliation(
                status=ReconciliationStatus.NOT_PRESENT,
                error_code=cast("Any", "not-found"),
            ),
            TypeError,
            "ProviderErrorCode",
        ),
        (
            lambda: Reconciliation(status=ReconciliationStatus.DESIRED_STATE_PRESENT),
            ValueError,
            "requires current state",
        ),
        (
            lambda: Reconciliation(
                status=ReconciliationStatus.DESIRED_STATE_PRESENT,
                current=current_state(),
                error_code=ProviderErrorCode.INVALID_RESPONSE,
            ),
            ValueError,
            "cannot contain an error",
        ),
        (
            lambda: Reconciliation(status=ReconciliationStatus.NOT_PRESENT),
            ValueError,
            "requires current state or an error",
        ),
        (
            lambda: Reconciliation(status=ReconciliationStatus.UNKNOWN),
            ValueError,
            "requires an error",
        ),
        (
            lambda: Reconciliation(
                status=ReconciliationStatus.UNKNOWN,
                current=current_state(),
                error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
            ),
            ValueError,
            "cannot contain current state",
        ),
    ],
)
def test_port_invalid_values_fail_closed(
    factory: Callable[[], object],
    error_type: type[BaseException],
    match: str,
) -> None:
    with pytest.raises(error_type, match=match):
        factory()


def test_capability_provider_properties_are_identity_derived() -> None:
    reader = ReaderCapabilities(
        identity=identity(),
        strong_change_tokens=True,
        stable_item_ids=True,
    )
    writer = WriterCapabilities(
        identity=identity(),
        supported_actions=frozenset({ActionType.SET_READ_STATE}),
        strong_preconditions=True,
    )

    assert reader.provider is ProviderKind.FIXTURE
    assert writer.provider is ProviderKind.FIXTURE
