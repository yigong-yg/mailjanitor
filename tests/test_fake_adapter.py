from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from mailjanitor.adapters.fake import (
    FakeMailbox,
    FakeMailboxError,
    FakeOperation,
    FakeWriteMode,
)
from mailjanitor.domain import (
    ActionType,
    ApprovedMailboxCommand,
    FolderRef,
    HeaderMetadata,
    HeaderName,
    MailboxItemRef,
    MailboxProfileRef,
    MessageMetadata,
    MoveMessage,
    ProviderKind,
    SetCategory,
    SetReadState,
)
from mailjanitor.ports import (
    AdapterIdentity,
    MailboxReader,
    MailboxWriter,
    MetadataPageRequest,
    ProviderErrorCode,
    ReconciliationStatus,
    WriteStatus,
)

PROFILE = MailboxProfileRef(
    provider=ProviderKind.FIXTURE,
    profile_id="profile_alpha",
)
OTHER_PROFILE = MailboxProfileRef(
    provider=ProviderKind.FIXTURE,
    profile_id="profile_beta",
)
IDENTITY = AdapterIdentity(
    profile=PROFILE,
    account_fingerprint=f"sha256:{'a' * 64}",
)
MAILBOX_REF = f"mbx_{'1' * 32}"
OTHER_MAILBOX_REF = f"mbx_{'2' * 32}"
INBOX = "folder-inbox"
ARCHIVE = "folder-archive"
EXISTING_CATEGORY = "Synthetic Existing"
AUTH_HEADER = HeaderMetadata(
    name=HeaderName.AUTHENTICATION_RESULTS,
    value="alpha.example; synthetic=pass",
)


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _message(
    provider_id: str = "item-001",
    *,
    day: int = 1,
    folder_id: str = INBOX,
    profile: MailboxProfileRef = PROFILE,
    is_read: bool = False,
    categories: tuple[str, ...] = (EXISTING_CATEGORY,),
    headers: tuple[HeaderMetadata, ...] = (),
) -> MessageMetadata:
    return MessageMetadata(
        ref=MailboxItemRef(
            profile=profile,
            provider_id=provider_id,
            folder_id=folder_id,
            change_token=f"fixture-token-{provider_id}",
        ),
        sender_address=f"sender-{provider_id}@alpha.example",
        sender_domain="alpha.example",
        sender_display_name="Synthetic Sender",
        subject=f"Synthetic notification {provider_id}",
        received_at=datetime(2026, 1, day, 12, tzinfo=UTC),
        is_read=is_read,
        has_attachments=False,
        attachment_count=0,
        categories=categories,
        headers=headers,
    )


def _mailbox(
    messages: tuple[MessageMetadata, ...] | None = None,
    *,
    supported_headers: frozenset[HeaderName] = frozenset(),
    supported_actions: frozenset[ActionType] = frozenset(ActionType),
    injected_writes: dict[str, FakeWriteMode] | None = None,
) -> FakeMailbox:
    return FakeMailbox(
        identity=IDENTITY,
        mailbox_ref=MAILBOX_REF,
        messages=messages if messages is not None else (_message(),),
        folder_ids=(INBOX, ARCHIVE),
        supported_headers=supported_headers,
        supported_actions=supported_actions,
        injected_writes=injected_writes,
    )


def _command(
    message: MessageMetadata,
    action: MoveMessage | SetReadState | SetCategory,
    *,
    key_character: str = "b",
    target: MailboxItemRef | None = None,
    expected_fingerprint: str | None = None,
    mailbox_ref: str = MAILBOX_REF,
) -> ApprovedMailboxCommand:
    return ApprovedMailboxCommand(
        action_id=f"action_{key_character}",
        proposal_digest=_digest("3"),
        approval_digest=_digest("4"),
        line_digest=_digest("5"),
        approval_id=f"approval_{key_character}",
        mailbox_ref=mailbox_ref,
        target=target if target is not None else message.ref,
        expected_state_fingerprint=(
            expected_fingerprint
            if expected_fingerprint is not None
            else message.state_fingerprint
        ),
        action=action,
        idempotency_key=_digest(key_character),
    )


def _assert_error(
    caught: pytest.ExceptionInfo[FakeMailboxError],
    code: ProviderErrorCode,
) -> None:
    assert caught.value.code is code
    assert str(caught.value) == code.value


def test_ports_and_capabilities_are_exactly_profile_bound() -> None:
    mailbox = _mailbox()
    reader: MailboxReader = mailbox.reader
    writer: MailboxWriter = mailbox.writer

    assert isinstance(reader, MailboxReader)
    assert isinstance(writer, MailboxWriter)
    reader_capabilities = reader.capabilities(PROFILE)
    writer_capabilities = writer.capabilities(PROFILE)
    assert reader_capabilities.identity == IDENTITY
    assert reader_capabilities.strong_change_tokens is True
    assert reader_capabilities.stable_item_ids is True
    assert writer_capabilities.identity == IDENTITY
    assert writer_capabilities.strong_preconditions is True
    assert writer_capabilities.supported_actions == frozenset(ActionType)

    with pytest.raises(FakeMailboxError) as reader_error:
        reader.capabilities(OTHER_PROFILE)
    with pytest.raises(FakeMailboxError) as writer_error:
        writer.capabilities(OTHER_PROFILE)
    _assert_error(reader_error, ProviderErrorCode.WRONG_ACCOUNT)
    _assert_error(writer_error, ProviderErrorCode.WRONG_ACCOUNT)


def test_metadata_pages_are_newest_first_bounded_and_deterministic() -> None:
    messages = (
        _message("item-001", day=1),
        _message("item-002", day=3),
        _message("item-003", day=2),
        _message("item-004", day=4, folder_id=ARCHIVE),
    )
    mailbox = _mailbox(messages)
    request = MetadataPageRequest(
        profile=PROFILE,
        folder_ids=(INBOX,),
        page_size=2,
    )

    first = mailbox.reader.read_page(request)
    assert [item.ref.provider_id for item in first.items] == [
        "item-002",
        "item-003",
    ]
    assert first.next_cursor is not None
    second = mailbox.reader.read_page(replace(request, cursor=first.next_cursor))
    assert [item.ref.provider_id for item in second.items] == ["item-001"]
    assert second.next_cursor is None

    repeated = mailbox.reader.read_page(request)
    assert repeated.items == first.items
    assert mailbox.operation_count(FakeOperation.READ_PAGE) == 3


def test_page_projection_is_metadata_only_and_headers_are_explicit() -> None:
    message = _message(headers=(AUTH_HEADER,))
    mailbox = _mailbox(
        (message,),
        supported_headers=frozenset({HeaderName.AUTHENTICATION_RESULTS}),
    )
    base_request = MetadataPageRequest(
        profile=PROFILE,
        folder_ids=(INBOX,),
        page_size=10,
    )

    without_headers = mailbox.reader.read_page(base_request).items[0]
    with_headers = mailbox.reader.read_page(
        replace(base_request, headers=(HeaderName.AUTHENTICATION_RESULTS,))
    ).items[0]
    assert without_headers.headers == ()
    assert with_headers.headers == (AUTH_HEADER,)
    assert not hasattr(with_headers, "body")
    assert not hasattr(with_headers, "body_preview")
    assert not hasattr(with_headers, "attachments")

    unsupported = replace(
        base_request,
        headers=(HeaderName.LIST_UNSUBSCRIBE,),
    )
    with pytest.raises(FakeMailboxError) as caught:
        mailbox.reader.read_page(unsupported)
    _assert_error(caught, ProviderErrorCode.UNSUPPORTED)


def test_cursor_is_scoped_to_the_exact_request() -> None:
    mailbox = _mailbox((_message("item-001"), _message("item-002", day=2)))
    request = MetadataPageRequest(
        profile=PROFILE,
        folder_ids=(INBOX,),
        page_size=1,
    )
    cursor = mailbox.reader.read_page(request).next_cursor
    assert cursor is not None

    with pytest.raises(FakeMailboxError) as caught:
        mailbox.reader.read_page(
            MetadataPageRequest(
                profile=PROFILE,
                folder_ids=(INBOX,),
                page_size=2,
                cursor=cursor,
            )
        )
    _assert_error(caught, ProviderErrorCode.INVALID_RESPONSE)


def test_page_and_current_reads_reject_wrong_or_missing_targets() -> None:
    mailbox = _mailbox()
    with pytest.raises(FakeMailboxError) as wrong_profile:
        mailbox.reader.read_page(
            MetadataPageRequest(
                profile=OTHER_PROFILE,
                folder_ids=(INBOX,),
            )
        )
    _assert_error(wrong_profile, ProviderErrorCode.WRONG_ACCOUNT)

    with pytest.raises(FakeMailboxError) as missing_folder:
        mailbox.reader.read_page(
            MetadataPageRequest(
                profile=PROFILE,
                folder_ids=("folder-missing",),
            )
        )
    _assert_error(missing_folder, ProviderErrorCode.NOT_FOUND)

    missing_ref = replace(_message().ref, provider_id="item-missing")
    assert mailbox.reader.read_current(missing_ref) is None
    with pytest.raises(FakeMailboxError) as wrong_current:
        mailbox.reader.read_current(replace(missing_ref, profile=OTHER_PROFILE))
    _assert_error(wrong_current, ProviderErrorCode.WRONG_ACCOUNT)


def test_page_cursor_remains_stable_while_current_state_changes() -> None:
    newest = _message("item-newest", day=2)
    later_page_item = _message("item-later-page", day=1)
    mailbox = _mailbox((newest, later_page_item))
    request = MetadataPageRequest(
        profile=PROFILE,
        folder_ids=(INBOX,),
        page_size=1,
    )
    first = mailbox.reader.read_page(request)
    assert first.next_cursor is not None

    command = _command(
        later_page_item,
        MoveMessage(destination=FolderRef(profile=PROFILE, folder_id=ARCHIVE)),
    )
    assert mailbox.writer.execute_one(command).status is WriteStatus.SUCCEEDED

    second = mailbox.reader.read_page(replace(request, cursor=first.next_cursor))
    assert second.items[0].ref == later_page_item.ref
    current = mailbox.reader.read_current(later_page_item.ref)
    assert current is not None
    assert current.ref.folder_id == ARCHIVE


@pytest.mark.parametrize(
    "action",
    [
        MoveMessage(destination=FolderRef(profile=PROFILE, folder_id=ARCHIVE)),
        SetReadState(is_read=True),
        SetCategory(category="Synthetic Added", present=True),
        SetCategory(category=EXISTING_CATEGORY, present=False),
    ],
    ids=["move", "read", "add-category", "remove-category"],
)
def test_each_typed_write_is_applied_once_and_replay_is_idempotent(
    action: MoveMessage | SetReadState | SetCategory,
) -> None:
    message = _message()
    mailbox = _mailbox((message,))
    command = _command(message, action)

    first = mailbox.writer.execute_one(command)
    current_after_first = mailbox.reader.read_current(message.ref)
    second = mailbox.writer.execute_one(command)
    current_after_second = mailbox.reader.read_current(message.ref)

    assert first.status is WriteStatus.SUCCEEDED
    assert second == first
    assert current_after_first == current_after_second
    assert current_after_first is not None
    assert current_after_first.ref.change_token != message.ref.change_token
    assert mailbox.provider_dispatch_count(command.idempotency_key) == 1
    execute_calls = [
        call for call in mailbox.trace if call.operation is FakeOperation.EXECUTE_ONE
    ]
    assert execute_calls[-1].idempotent_replay is True
    assert execute_calls[-1].write_dispatched is False

    if isinstance(action, MoveMessage):
        assert current_after_first.ref.folder_id == ARCHIVE
    elif isinstance(action, SetReadState):
        assert current_after_first.is_read is True
    elif action.present:
        assert "Synthetic Added" in current_after_first.categories
    else:
        assert EXISTING_CATEGORY not in current_after_first.categories


def test_already_desired_command_succeeds_without_provider_dispatch() -> None:
    message = _message(is_read=True)
    mailbox = _mailbox((message,))
    command = _command(message, SetReadState(is_read=True))

    result = mailbox.writer.execute_one(command)

    assert result.status is WriteStatus.SUCCEEDED
    assert result.new_ref == message.ref
    assert mailbox.provider_dispatch_count(command.idempotency_key) == 0


@pytest.mark.parametrize(
    ("target", "fingerprint"),
    [
        (
            replace(_message().ref, change_token="fixture-token-stale"),
            _message().state_fingerprint,
        ),
        (_message().ref, _digest("f")),
    ],
    ids=["change-token", "state-fingerprint"],
)
def test_stale_preconditions_fail_without_dispatch(
    target: MailboxItemRef,
    fingerprint: str,
) -> None:
    message = _message()
    mailbox = _mailbox((message,))
    command = _command(
        message,
        SetReadState(is_read=True),
        target=target,
        expected_fingerprint=fingerprint,
    )

    result = mailbox.writer.execute_one(command)

    assert result.status is WriteStatus.DEFINITE_FAILURE
    assert result.error_code is ProviderErrorCode.STALE_ITEM
    assert mailbox.provider_dispatch_count(command.idempotency_key) == 0
    current = mailbox.reader.read_current(message.ref)
    assert current is not None
    assert current.ref == message.ref
    assert current.is_read is message.is_read
    assert current.categories == message.categories


def test_wrong_mailbox_binding_fails_closed() -> None:
    message = _message()
    mailbox = _mailbox((message,))
    wrong_ref_command = _command(
        message,
        SetReadState(is_read=True),
        target=replace(message.ref, profile=OTHER_PROFILE),
    )
    wrong_mailbox_command = _command(
        message,
        SetReadState(is_read=True),
        key_character="c",
        mailbox_ref=OTHER_MAILBOX_REF,
    )

    for command in (wrong_ref_command, wrong_mailbox_command):
        result = mailbox.writer.execute_one(command)
        assert result.status is WriteStatus.DEFINITE_FAILURE
        assert result.error_code is ProviderErrorCode.WRONG_ACCOUNT
        assert mailbox.provider_dispatch_count(command.idempotency_key) == 0


def test_missing_target_destination_and_capability_fail_closed() -> None:
    message = _message()
    mailbox = _mailbox(
        (message,),
        supported_actions=frozenset({ActionType.MOVE_MESSAGE}),
    )
    missing_target = _command(
        message,
        MoveMessage(destination=FolderRef(profile=PROFILE, folder_id=ARCHIVE)),
        target=replace(message.ref, provider_id="item-missing"),
    )
    missing_destination = _command(
        message,
        MoveMessage(destination=FolderRef(profile=PROFILE, folder_id="folder-missing")),
        key_character="c",
    )
    unsupported = _command(
        message,
        SetReadState(is_read=True),
        key_character="d",
    )

    expected = (
        (missing_target, ProviderErrorCode.NOT_FOUND),
        (missing_destination, ProviderErrorCode.NOT_FOUND),
        (unsupported, ProviderErrorCode.UNSUPPORTED),
    )
    for command, error_code in expected:
        result = mailbox.writer.execute_one(command)
        assert result.status is WriteStatus.DEFINITE_FAILURE
        assert result.error_code is error_code
        assert mailbox.provider_dispatch_count(command.idempotency_key) == 0


def test_injected_definite_failure_is_not_applied_or_redispatched() -> None:
    message = _message()
    key = _digest("b")
    mailbox = _mailbox(
        (message,),
        injected_writes={key: FakeWriteMode.DEFINITE_FAILURE},
    )
    command = _command(message, SetReadState(is_read=True))

    first = mailbox.writer.execute_one(command)
    second = mailbox.writer.execute_one(command)
    current = mailbox.reader.read_current(message.ref)

    assert first.status is WriteStatus.DEFINITE_FAILURE
    assert first.error_code is ProviderErrorCode.PROVIDER_UNAVAILABLE
    assert second == first
    assert current is not None
    assert current.is_read is False
    assert mailbox.provider_dispatch_count(key) == 1


@pytest.mark.parametrize(
    ("mode", "expected_read", "expected_status"),
    [
        (
            FakeWriteMode.OUTCOME_UNKNOWN_APPLIED,
            True,
            ReconciliationStatus.DESIRED_STATE_PRESENT,
        ),
        (
            FakeWriteMode.OUTCOME_UNKNOWN_NOT_APPLIED,
            False,
            ReconciliationStatus.NOT_PRESENT,
        ),
        (
            FakeWriteMode.OUTCOME_UNKNOWN_INDETERMINATE,
            False,
            ReconciliationStatus.UNKNOWN,
        ),
    ],
)
def test_outcome_unknown_never_blindly_retries_and_reconciles(
    mode: FakeWriteMode,
    expected_read: bool,
    expected_status: ReconciliationStatus,
) -> None:
    message = _message(categories=())
    key = _digest("b")
    mailbox = _mailbox((message,), injected_writes={key: mode})
    command = _command(message, SetReadState(is_read=True))

    first = mailbox.writer.execute_one(command)
    second = mailbox.writer.execute_one(command)
    current = mailbox.reader.read_current(message.ref)
    reconciliation = mailbox.writer.reconcile(command)

    assert first.status is WriteStatus.OUTCOME_UNKNOWN
    assert first.error_code is ProviderErrorCode.OUTCOME_UNKNOWN
    assert second == first
    assert current is not None
    assert current.is_read is expected_read
    assert reconciliation.status is expected_status
    assert mailbox.provider_dispatch_count(key) == 1
    if expected_status is ReconciliationStatus.UNKNOWN:
        assert reconciliation.error_code is ProviderErrorCode.OUTCOME_UNKNOWN


def test_idempotency_key_cannot_be_reused_for_a_different_command() -> None:
    message = _message(categories=())
    mailbox = _mailbox((message,))
    first_command = _command(message, SetReadState(is_read=True))
    conflicting_command = _command(
        message,
        SetCategory(category="Synthetic Added", present=True),
    )

    assert mailbox.writer.execute_one(first_command).status is WriteStatus.SUCCEEDED
    conflict = mailbox.writer.execute_one(conflicting_command)
    reconciliation = mailbox.writer.reconcile(conflicting_command)

    assert conflict.status is WriteStatus.DEFINITE_FAILURE
    assert conflict.error_code is ProviderErrorCode.CONFLICT
    assert reconciliation.status is ReconciliationStatus.UNKNOWN
    assert reconciliation.error_code is ProviderErrorCode.CONFLICT
    assert mailbox.provider_dispatch_count(first_command.idempotency_key) == 1


def test_call_trace_is_ordered_immutable_and_content_free() -> None:
    message = _message()
    mailbox = _mailbox((message,))
    command = _command(message, SetReadState(is_read=True))

    mailbox.reader.capabilities(PROFILE)
    mailbox.reader.read_current(message.ref)
    mailbox.writer.execute_one(command)
    mailbox.writer.reconcile(command)
    trace = mailbox.trace

    assert isinstance(trace, tuple)
    assert [call.sequence for call in trace] == list(range(1, len(trace) + 1))
    assert [call.operation for call in trace] == [
        FakeOperation.READER_CAPABILITIES,
        FakeOperation.READ_CURRENT,
        FakeOperation.EXECUTE_ONE,
        FakeOperation.RECONCILE,
    ]
    assert not hasattr(trace[0], "subject")
    assert not hasattr(trace[0], "sender_address")


def test_fixture_constructor_rejects_cross_profile_or_unadvertised_data() -> None:
    cross_profile = _message(profile=OTHER_PROFILE)
    with pytest.raises(FakeMailboxError) as caught:
        _mailbox((cross_profile,))
    _assert_error(caught, ProviderErrorCode.WRONG_ACCOUNT)

    with pytest.raises(ValueError, match="unsupported metadata header"):
        _mailbox((_message(headers=(AUTH_HEADER,)),))

    graph_identity = AdapterIdentity(
        profile=MailboxProfileRef(
            provider=ProviderKind.GRAPH,
            profile_id="profile_graph",
        ),
        account_fingerprint=_digest("e"),
    )
    with pytest.raises(ValueError, match="fixture profile"):
        FakeMailbox(
            identity=graph_identity,
            mailbox_ref=MAILBOX_REF,
            messages=(),
            folder_ids=(INBOX,),
        )
