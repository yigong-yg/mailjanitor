"""Deterministic, entirely synthetic mailbox ports for offline testing.

The fake has no provider client, network path, generic request escape hatch,
message body, or attachment object.  Reader and writer objects share explicit
in-memory state while retaining their distinct capability contracts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from mailjanitor.domain import (
    ActionType,
    ApprovedMailboxCommand,
    HeaderName,
    MailboxItemRef,
    MailboxProfileRef,
    MessageMetadata,
    MoveMessage,
    ProviderKind,
    SetCategory,
    SetReadState,
    validate_digest,
    validate_opaque_id,
)
from mailjanitor.ports import (
    AdapterIdentity,
    CurrentItemState,
    MailboxReader,
    MailboxWriter,
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

_MAILBOX_REF_PATTERN = re.compile(r"mbx_[0-9a-f]{32,64}\Z")


class FakeWriteMode(StrEnum):
    """A deterministic write outcome injected for one idempotency key."""

    DEFINITE_FAILURE = "definite_failure"
    OUTCOME_UNKNOWN_APPLIED = "outcome_unknown_applied"
    OUTCOME_UNKNOWN_NOT_APPLIED = "outcome_unknown_not_applied"
    OUTCOME_UNKNOWN_INDETERMINATE = "outcome_unknown_indeterminate"


class FakeOperation(StrEnum):
    """Content-free operation names used by the fake call trace."""

    READER_CAPABILITIES = "reader_capabilities"
    WRITER_CAPABILITIES = "writer_capabilities"
    READ_PAGE = "read_page"
    READ_CURRENT = "read_current"
    EXECUTE_ONE = "execute_one"
    RECONCILE = "reconcile"


@dataclass(frozen=True, slots=True)
class FakeCall:
    """Immutable record of one fake adapter invocation."""

    sequence: int
    operation: FakeOperation
    profile: MailboxProfileRef
    provider_id: str | None = None
    idempotency_key: str | None = None
    write_dispatched: bool = False
    idempotent_replay: bool = False
    write_status: WriteStatus | None = None
    reconciliation_status: ReconciliationStatus | None = None
    error_code: ProviderErrorCode | None = None


class FakeMailboxError(RuntimeError):
    """Normalized read-side failure raised by the synthetic adapter."""

    def __init__(self, code: ProviderErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class _PageState:
    profile: MailboxProfileRef
    folder_ids: tuple[str, ...]
    page_size: int
    headers: tuple[HeaderName, ...]
    items: tuple[MessageMetadata, ...]
    offset: int
    snapshot_number: int


class _FakeMailboxState:
    def __init__(
        self,
        *,
        identity: AdapterIdentity,
        mailbox_ref: str,
        messages: Iterable[MessageMetadata],
        folder_ids: Iterable[str],
        supported_headers: frozenset[HeaderName],
        supported_actions: frozenset[ActionType],
        injected_writes: Mapping[str, FakeWriteMode] | None,
    ) -> None:
        if identity.profile.provider is not ProviderKind.FIXTURE:
            raise ValueError("fake adapter requires a fixture profile")
        if _MAILBOX_REF_PATTERN.fullmatch(mailbox_ref) is None:
            raise ValueError("mailbox_ref must be a synthetic mailbox pseudonym")

        folders = frozenset(
            validate_opaque_id("folder_id", folder_id) for folder_id in folder_ids
        )
        if not folders:
            raise ValueError("fake adapter requires at least one folder")

        indexed: dict[str, MessageMetadata] = {}
        for message in messages:
            self._validate_seed_message(
                message,
                identity=identity,
                folder_ids=folders,
                supported_headers=supported_headers,
            )
            if message.ref.provider_id in indexed:
                raise ValueError("fake messages contain a duplicate provider id")
            indexed[message.ref.provider_id] = message

        faults = dict(injected_writes or {})
        for idempotency_key in faults:
            validate_digest("idempotency_key", idempotency_key)

        self.identity = identity
        self.mailbox_ref = mailbox_ref
        self.folder_ids = folders
        self.messages = indexed
        self.reader_capabilities = ReaderCapabilities(
            identity=identity,
            strong_change_tokens=True,
            stable_item_ids=True,
            attachment_count_without_enumeration=True,
            supported_headers=supported_headers,
        )
        self.writer_capabilities = WriterCapabilities(
            identity=identity,
            supported_actions=supported_actions,
            strong_preconditions=True,
        )
        self.injected_writes = faults
        self.commands_by_key: dict[str, ApprovedMailboxCommand] = {}
        self.results_by_key: dict[str, WriteResult] = {}
        self.cursors: dict[str, _PageState] = {}
        self.calls: list[FakeCall] = []
        self.next_change_number = 1
        self.next_snapshot_number = 1

    @staticmethod
    def _validate_seed_message(
        message: MessageMetadata,
        *,
        identity: AdapterIdentity,
        folder_ids: frozenset[str],
        supported_headers: frozenset[HeaderName],
    ) -> None:
        if message.ref.profile != identity.profile:
            raise FakeMailboxError(ProviderErrorCode.WRONG_ACCOUNT)
        if message.ref.folder_id not in folder_ids:
            raise ValueError("fake message references an undeclared folder")
        if message.ref.change_token is None:
            raise ValueError("fake messages require strong synthetic change tokens")
        if any(header.name not in supported_headers for header in message.headers):
            raise ValueError("fake message uses an unsupported metadata header")

    def require_profile(self, profile: MailboxProfileRef) -> None:
        if profile != self.identity.profile:
            raise FakeMailboxError(ProviderErrorCode.WRONG_ACCOUNT)

    def record(
        self,
        *,
        operation: FakeOperation,
        profile: MailboxProfileRef,
        provider_id: str | None = None,
        idempotency_key: str | None = None,
        write_dispatched: bool = False,
        idempotent_replay: bool = False,
        write_status: WriteStatus | None = None,
        reconciliation_status: ReconciliationStatus | None = None,
        error_code: ProviderErrorCode | None = None,
    ) -> None:
        self.calls.append(
            FakeCall(
                sequence=len(self.calls) + 1,
                operation=operation,
                profile=profile,
                provider_id=provider_id,
                idempotency_key=idempotency_key,
                write_dispatched=write_dispatched,
                idempotent_replay=idempotent_replay,
                write_status=write_status,
                reconciliation_status=reconciliation_status,
                error_code=error_code,
            )
        )

    def current(self, provider_id: str) -> CurrentItemState | None:
        message = self.messages.get(provider_id)
        if message is None:
            return None
        return CurrentItemState.from_metadata(message)

    def ordered_messages(
        self,
        *,
        folder_ids: tuple[str, ...],
        headers: tuple[HeaderName, ...],
    ) -> tuple[MessageMetadata, ...]:
        requested_headers = frozenset(headers)
        selected = [
            replace(
                message,
                headers=tuple(
                    header
                    for header in message.headers
                    if header.name in requested_headers
                ),
            )
            for message in self.messages.values()
            if message.ref.folder_id in folder_ids
        ]
        selected.sort(
            key=lambda message: (message.ref.provider_id, message.ref.folder_id)
        )
        selected.sort(key=lambda message: message.received_at, reverse=True)
        return tuple(selected)

    def next_change_token(self) -> str:
        token = f"fixture-change-{self.next_change_number:08d}"
        self.next_change_number += 1
        return token

    def remember(
        self,
        command: ApprovedMailboxCommand,
        result: WriteResult,
    ) -> None:
        self.commands_by_key[command.idempotency_key] = command
        self.results_by_key[command.idempotency_key] = result


class FakeMailboxReader:
    """Metadata-only reader implementing :class:`MailboxReader`."""

    def __init__(self, state: _FakeMailboxState) -> None:
        self._state = state

    def capabilities(self, profile: MailboxProfileRef) -> ReaderCapabilities:
        self._state.record(
            operation=FakeOperation.READER_CAPABILITIES,
            profile=profile,
        )
        self._state.require_profile(profile)
        return self._state.reader_capabilities

    def read_page(self, request: MetadataPageRequest) -> MetadataPage:
        self._state.record(
            operation=FakeOperation.READ_PAGE,
            profile=request.profile,
        )
        self._state.require_profile(request.profile)
        if any(
            folder_id not in self._state.folder_ids for folder_id in request.folder_ids
        ):
            raise FakeMailboxError(ProviderErrorCode.NOT_FOUND)
        if any(
            header not in self._state.reader_capabilities.supported_headers
            for header in request.headers
        ):
            raise FakeMailboxError(ProviderErrorCode.UNSUPPORTED)

        page_state = self._resolve_page(request)
        stop = min(page_state.offset + request.page_size, len(page_state.items))
        next_cursor = None
        if stop < len(page_state.items):
            next_cursor = self._store_cursor(page_state, offset=stop)
        return MetadataPage(
            profile=request.profile,
            items=page_state.items[page_state.offset : stop],
            next_cursor=next_cursor,
        )

    def read_current(self, ref: MailboxItemRef) -> CurrentItemState | None:
        self._state.record(
            operation=FakeOperation.READ_CURRENT,
            profile=ref.profile,
            provider_id=ref.provider_id,
        )
        self._state.require_profile(ref.profile)
        return self._state.current(ref.provider_id)

    def _resolve_page(self, request: MetadataPageRequest) -> _PageState:
        if request.cursor is not None:
            state = self._state.cursors.get(request.cursor)
            if state is None or not self._cursor_matches(state, request):
                raise FakeMailboxError(ProviderErrorCode.INVALID_RESPONSE)
            return state

        snapshot_number = self._state.next_snapshot_number
        self._state.next_snapshot_number += 1
        return _PageState(
            profile=request.profile,
            folder_ids=request.folder_ids,
            page_size=request.page_size,
            headers=request.headers,
            items=self._state.ordered_messages(
                folder_ids=request.folder_ids,
                headers=request.headers,
            ),
            offset=0,
            snapshot_number=snapshot_number,
        )

    @staticmethod
    def _cursor_matches(state: _PageState, request: MetadataPageRequest) -> bool:
        return (
            state.profile == request.profile
            and state.folder_ids == request.folder_ids
            and state.page_size == request.page_size
            and state.headers == request.headers
        )

    def _store_cursor(self, state: _PageState, *, offset: int) -> str:
        token = f"fixture-cursor-{state.snapshot_number:08d}-{offset:08d}"
        self._state.cursors[token] = replace(state, offset=offset)
        return token


class FakeMailboxWriter:
    """One-command writer implementing :class:`MailboxWriter`."""

    def __init__(self, state: _FakeMailboxState) -> None:
        self._state = state

    def capabilities(self, profile: MailboxProfileRef) -> WriterCapabilities:
        self._state.record(
            operation=FakeOperation.WRITER_CAPABILITIES,
            profile=profile,
        )
        self._state.require_profile(profile)
        return self._state.writer_capabilities

    def execute_one(self, command: ApprovedMailboxCommand) -> WriteResult:
        replay = self._replayed_result(command)
        if replay is not None:
            return replay

        message, failure = self._preflight(command)
        if failure is not None:
            self._state.remember(command, failure)
            self._record_write(command, result=failure, dispatched=False)
            return failure
        if message is None:  # pragma: no cover - _preflight invariant
            raise AssertionError("preflight returned neither state nor failure")

        if self._desired_state_present(message, command):
            result = WriteResult(
                status=WriteStatus.SUCCEEDED,
                new_ref=message.ref,
            )
            self._state.remember(command, result)
            self._record_write(command, result=result, dispatched=False)
            return result

        mode = self._state.injected_writes.get(command.idempotency_key)
        result = self._execute_mode(message, command, mode)
        self._state.remember(command, result)
        self._record_write(command, result=result, dispatched=True)
        return result

    def reconcile(self, command: ApprovedMailboxCommand) -> Reconciliation:
        result = self._reconciliation(command)
        self._state.record(
            operation=FakeOperation.RECONCILE,
            profile=command.target.profile,
            provider_id=command.target.provider_id,
            idempotency_key=command.idempotency_key,
            reconciliation_status=result.status,
            error_code=result.error_code,
        )
        return result

    def _replayed_result(
        self,
        command: ApprovedMailboxCommand,
    ) -> WriteResult | None:
        previous_command = self._state.commands_by_key.get(command.idempotency_key)
        if previous_command is None:
            return None
        if previous_command != command:
            result = self._failure(ProviderErrorCode.CONFLICT)
        else:
            result = self._state.results_by_key[command.idempotency_key]
        self._record_write(
            command,
            result=result,
            dispatched=False,
            replayed=True,
        )
        return result

    def _preflight(
        self,
        command: ApprovedMailboxCommand,
    ) -> tuple[MessageMetadata | None, WriteResult | None]:
        if (
            command.target.profile != self._state.identity.profile
            or command.mailbox_ref != self._state.mailbox_ref
        ):
            return None, self._failure(ProviderErrorCode.WRONG_ACCOUNT)
        if command.action_type not in self._state.writer_capabilities.supported_actions:
            return None, self._failure(ProviderErrorCode.UNSUPPORTED)

        message = self._state.messages.get(command.target.provider_id)
        if message is None:
            return None, self._failure(ProviderErrorCode.NOT_FOUND)
        if (
            message.ref != command.target
            or message.state_fingerprint != command.expected_state_fingerprint
        ):
            return None, self._failure(ProviderErrorCode.STALE_ITEM)
        if (
            isinstance(command.action, MoveMessage)
            and command.action.destination.folder_id not in self._state.folder_ids
        ):
            return None, self._failure(ProviderErrorCode.NOT_FOUND)
        return message, None

    def _execute_mode(
        self,
        message: MessageMetadata,
        command: ApprovedMailboxCommand,
        mode: FakeWriteMode | None,
    ) -> WriteResult:
        if mode is FakeWriteMode.DEFINITE_FAILURE:
            return self._failure(ProviderErrorCode.PROVIDER_UNAVAILABLE)
        if mode is FakeWriteMode.OUTCOME_UNKNOWN_APPLIED:
            self._apply(message, command)
            return self._unknown()
        if mode in {
            FakeWriteMode.OUTCOME_UNKNOWN_NOT_APPLIED,
            FakeWriteMode.OUTCOME_UNKNOWN_INDETERMINATE,
        }:
            return self._unknown()
        updated = self._apply(message, command)
        return WriteResult(status=WriteStatus.SUCCEEDED, new_ref=updated.ref)

    def _reconciliation(self, command: ApprovedMailboxCommand) -> Reconciliation:
        previous_command = self._state.commands_by_key.get(command.idempotency_key)
        if previous_command is not None and previous_command != command:
            return Reconciliation(
                status=ReconciliationStatus.UNKNOWN,
                error_code=ProviderErrorCode.CONFLICT,
            )
        if (
            command.target.profile != self._state.identity.profile
            or command.mailbox_ref != self._state.mailbox_ref
        ):
            return Reconciliation(
                status=ReconciliationStatus.UNKNOWN,
                error_code=ProviderErrorCode.WRONG_ACCOUNT,
            )
        if (
            self._state.injected_writes.get(command.idempotency_key)
            is FakeWriteMode.OUTCOME_UNKNOWN_INDETERMINATE
        ):
            return Reconciliation(
                status=ReconciliationStatus.UNKNOWN,
                error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
            )

        message = self._state.messages.get(command.target.provider_id)
        if message is None:
            return Reconciliation(
                status=ReconciliationStatus.NOT_PRESENT,
                error_code=ProviderErrorCode.NOT_FOUND,
            )
        current = CurrentItemState.from_metadata(message)
        if self._desired_state_present(message, command):
            return Reconciliation(
                status=ReconciliationStatus.DESIRED_STATE_PRESENT,
                current=current,
            )
        return Reconciliation(
            status=ReconciliationStatus.NOT_PRESENT,
            current=current,
        )

    def _apply(
        self,
        message: MessageMetadata,
        command: ApprovedMailboxCommand,
    ) -> MessageMetadata:
        new_ref = replace(
            message.ref,
            change_token=self._state.next_change_token(),
        )
        action = command.action
        if isinstance(action, MoveMessage):
            new_ref = replace(new_ref, folder_id=action.destination.folder_id)
            updated = replace(message, ref=new_ref)
        elif isinstance(action, SetReadState):
            updated = replace(message, ref=new_ref, is_read=action.is_read)
        else:
            updated = replace(
                message,
                ref=new_ref,
                categories=self._updated_categories(message, action),
            )
        self._state.messages[message.ref.provider_id] = updated
        return updated

    @staticmethod
    def _updated_categories(
        message: MessageMetadata,
        action: SetCategory,
    ) -> tuple[str, ...]:
        category = action.category.casefold()
        if action.present:
            return (*message.categories, action.category)
        return tuple(
            value for value in message.categories if value.casefold() != category
        )

    @staticmethod
    def _desired_state_present(
        message: MessageMetadata,
        command: ApprovedMailboxCommand,
    ) -> bool:
        action = command.action
        if isinstance(action, MoveMessage):
            return message.ref.folder_id == action.destination.folder_id
        if isinstance(action, SetReadState):
            return message.is_read is action.is_read
        category_present = any(
            value.casefold() == action.category.casefold()
            for value in message.categories
        )
        return category_present is action.present

    @staticmethod
    def _failure(error_code: ProviderErrorCode) -> WriteResult:
        return WriteResult(
            status=WriteStatus.DEFINITE_FAILURE,
            error_code=error_code,
        )

    @staticmethod
    def _unknown() -> WriteResult:
        return WriteResult(
            status=WriteStatus.OUTCOME_UNKNOWN,
            error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
        )

    def _record_write(
        self,
        command: ApprovedMailboxCommand,
        *,
        result: WriteResult,
        dispatched: bool,
        replayed: bool = False,
    ) -> None:
        self._state.record(
            operation=FakeOperation.EXECUTE_ONE,
            profile=command.target.profile,
            provider_id=command.target.provider_id,
            idempotency_key=command.idempotency_key,
            write_dispatched=dispatched,
            idempotent_replay=replayed,
            write_status=result.status,
            error_code=result.error_code,
        )


class FakeMailbox:
    """Convenience harness exposing paired reader/writer fake ports."""

    def __init__(
        self,
        *,
        identity: AdapterIdentity,
        mailbox_ref: str,
        messages: Iterable[MessageMetadata],
        folder_ids: Iterable[str],
        supported_headers: frozenset[HeaderName] = frozenset(),
        supported_actions: frozenset[ActionType] = frozenset(ActionType),
        injected_writes: Mapping[str, FakeWriteMode] | None = None,
    ) -> None:
        state = _FakeMailboxState(
            identity=identity,
            mailbox_ref=mailbox_ref,
            messages=messages,
            folder_ids=folder_ids,
            supported_headers=supported_headers,
            supported_actions=supported_actions,
            injected_writes=injected_writes,
        )
        self._state = state
        self._reader = FakeMailboxReader(state)
        self._writer = FakeMailboxWriter(state)

    @property
    def reader(self) -> MailboxReader:
        """Return the metadata-only reader port."""
        return self._reader

    @property
    def writer(self) -> MailboxWriter:
        """Return the one-command writer port."""
        return self._writer

    @property
    def trace(self) -> tuple[FakeCall, ...]:
        """Return an immutable snapshot of the content-free call trace."""
        return tuple(self._state.calls)

    def operation_count(self, operation: FakeOperation) -> int:
        """Count invocations of one fake port operation."""
        return sum(call.operation is operation for call in self._state.calls)

    def provider_dispatch_count(self, idempotency_key: str | None = None) -> int:
        """Count simulated provider writes, optionally for one idempotency key."""
        return sum(
            call.operation is FakeOperation.EXECUTE_ONE
            and call.write_dispatched
            and (idempotency_key is None or call.idempotency_key == idempotency_key)
            for call in self._state.calls
        )


__all__ = [
    "FakeCall",
    "FakeMailbox",
    "FakeMailboxError",
    "FakeMailboxReader",
    "FakeMailboxWriter",
    "FakeOperation",
    "FakeWriteMode",
]
