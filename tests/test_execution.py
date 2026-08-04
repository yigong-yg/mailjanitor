from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from mailjanitor.domain import (
    ActionType,
    ApprovedMailboxCommand,
    FolderRef,
    MailboxItemRef,
    MailboxProfileRef,
    MoveMessage,
    ProviderKind,
    SetReadState,
)
from mailjanitor.ports import (
    AdapterIdentity,
    CurrentItemState,
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
from mailjanitor.workflow.approval import (
    ApprovalArtifact,
    ApprovalAuthenticationError,
    ApprovalExpiredError,
    ApprovalService,
)
from mailjanitor.workflow.execution import (
    ActionExecutionStatus,
    ApprovalClaimStatus,
    AuditedActionState,
    DurableActionStatus,
    ExecutionIntent,
    ExecutionPreflightError,
    ExecutionStateError,
    Executor,
    StoredExecution,
)
from mailjanitor.workflow.proposal import ActionProposal, ActionSpec, TargetSpec

NOW = datetime(2026, 8, 3, 18, 0, tzinfo=UTC)
RUN_ID = "11111111-1111-4111-8111-111111111111"
PROPOSAL_ID = "22222222-2222-4222-8222-222222222222"
ACTION_ID = "33333333-3333-4333-8333-333333333333"
APPROVAL_ID = "44444444-4444-4444-8444-444444444444"
MAILBOX_REF = f"mbx_{'1' * 32}"
TARGET_REF = f"msg_{'2' * 32}"
ACCOUNT_FINGERPRINT = f"sha256:{'a' * 64}"
APPROVAL_KEY = b"synthetic-approval-key-at-least-32-bytes"


def profile() -> MailboxProfileRef:
    return MailboxProfileRef(provider=ProviderKind.FIXTURE, profile_id="synthetic")


def item_ref(*, change: int = 1, folder: str = "synthetic-inbox") -> MailboxItemRef:
    return MailboxItemRef(
        profile=profile(),
        provider_id="synthetic-message",
        folder_id=folder,
        change_token=f"synthetic-change-{change}",
    )


def current_state(*, change: int = 1, is_read: bool = False) -> CurrentItemState:
    return CurrentItemState(ref=item_ref(change=change), is_read=is_read)


def proposal(*, state: CurrentItemState | None = None) -> ActionProposal:
    source = state or current_state()
    return ActionProposal(
        proposal_id=PROPOSAL_ID,
        run_nonce="b" * 64,
        profile=profile(),
        account_fingerprint=ACCOUNT_FINGERPRINT,
        mailbox_ref=MAILBOX_REF,
        generated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        actions=(
            ActionSpec(
                action_id=ACTION_ID,
                target=TargetSpec(
                    item_ref=source.ref,
                    before_state_digest=source.state_fingerprint,
                    target_ref=TARGET_REF,
                ),
                action=SetReadState(is_read=True),
                owner_summary="Synthetic message: mark read",
            ),
        ),
    )


def approval_service() -> ApprovalService:
    return ApprovalService(
        key=APPROVAL_KEY,
        key_id="owner-key-v1",
        approval_id_factory=lambda: APPROVAL_ID,
        nonce_factory=lambda: "c" * 64,
    )


def approve(plan: ActionProposal, ids: list[str] | None = None) -> ApprovalArtifact:
    return approval_service().issue(
        plan,
        [ACTION_ID] if ids is None else ids,
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )


class StubReader:
    def __init__(self, state: CurrentItemState | None, trace: list[str]) -> None:
        self.state = state
        self.trace = trace
        self.identity = AdapterIdentity(
            profile=profile(),
            account_fingerprint=ACCOUNT_FINGERPRINT,
        )
        self.strong_change_tokens = True
        self.stable_item_ids = True

    def capabilities(self, requested_profile: MailboxProfileRef) -> ReaderCapabilities:
        assert requested_profile == profile()
        return ReaderCapabilities(
            identity=self.identity,
            strong_change_tokens=self.strong_change_tokens,
            stable_item_ids=self.stable_item_ids,
        )

    def read_current(self, ref: MailboxItemRef) -> CurrentItemState | None:
        self.trace.append("reader.current")
        assert ref.profile == profile()
        return self.state

    def read_page(self, request: MetadataPageRequest) -> MetadataPage:
        raise AssertionError(f"unexpected metadata page read: {request!r}")


class StubWriter:
    def __init__(
        self,
        trace: list[str],
        *,
        result: WriteResult | None = None,
        reconciliation: Reconciliation | None = None,
    ) -> None:
        self.trace = trace
        self.identity = AdapterIdentity(
            profile=profile(),
            account_fingerprint=ACCOUNT_FINGERPRINT,
        )
        self.result = result or WriteResult(
            status=WriteStatus.SUCCEEDED,
            new_ref=item_ref(),
        )
        self.reconciliation = reconciliation or Reconciliation(
            status=ReconciliationStatus.UNKNOWN,
            error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
        )
        self.execute_calls = 0
        self.reconcile_calls = 0
        self.executed_action_ids: list[str] = []
        self.supported_actions = frozenset({ActionType.SET_READ_STATE})

    def capabilities(self, requested_profile: MailboxProfileRef) -> WriterCapabilities:
        assert requested_profile == profile()
        return WriterCapabilities(
            identity=self.identity,
            supported_actions=self.supported_actions,
            strong_preconditions=True,
        )

    def execute_one(self, command: ApprovedMailboxCommand) -> WriteResult:
        self.trace.append("writer.execute")
        self.execute_calls += 1
        self.executed_action_ids.append(command.action_id)
        assert isinstance(command, ApprovedMailboxCommand)
        return self.result

    def reconcile(self, command: ApprovedMailboxCommand) -> Reconciliation:
        self.trace.append("writer.reconcile")
        self.reconcile_calls += 1
        assert isinstance(command, ApprovedMailboxCommand)
        return self.reconciliation


class MemoryState:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.records: dict[str, StoredExecution] = {}
        self.approvals: dict[str, tuple[str, str]] = {}

    @contextmanager
    def profile_lock(self, mailbox_ref: str) -> Iterator[None]:
        assert mailbox_ref == MAILBOX_REF
        self.trace.append("state.lock")
        yield

    def get(self, idempotency_key: str) -> StoredExecution | None:
        return self.records.get(idempotency_key)

    def claim_approval(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus:
        self.trace.append("state.claim_approval")
        existing = self.approvals.get(approval_digest)
        binding = (proposal_digest, run_id)
        if existing is None:
            self.approvals[approval_digest] = binding
            return ApprovalClaimStatus.CLAIMED
        if existing == binding:
            return ApprovalClaimStatus.SAME_RUN
        return ApprovalClaimStatus.DIFFERENT_RUN

    def approval_claim_status(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus | None:
        self.trace.append("state.approval_claim_status")
        existing = self.approvals.get(approval_digest)
        if existing is None:
            return None
        if existing == (proposal_digest, run_id):
            return ApprovalClaimStatus.SAME_RUN
        return ApprovalClaimStatus.DIFFERENT_RUN

    def record_intent(self, intent: ExecutionIntent) -> bool:
        self.trace.append("state.intent")
        if intent.idempotency_key in self.records:
            return False
        self.records[intent.idempotency_key] = StoredExecution(
            intent=intent,
            status=DurableActionStatus.INTENT_RECORDED,
        )
        return True

    def mark_dispatched(self, idempotency_key: str) -> None:
        self.trace.append("state.dispatched")
        record = self.records[idempotency_key]
        self.records[idempotency_key] = replace(
            record,
            status=DurableActionStatus.DISPATCHED,
        )

    def record_terminal(
        self,
        idempotency_key: str,
        status: DurableActionStatus,
        outcome_code: str,
    ) -> None:
        self.trace.append(f"state.{status.value}")
        record = self.records[idempotency_key]
        self.records[idempotency_key] = replace(
            record,
            status=status,
            outcome_code=outcome_code,
        )


class InvalidClaimState(MemoryState):
    def claim_approval(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus:
        del approval_digest, proposal_digest, run_id
        self.trace.append("state.claim_approval")
        return cast("ApprovalClaimStatus", None)


class MemoryAudit:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.events: list[dict[str, object]] = []
        self.fail_append = False
        self.fail_next_event_type: str | None = None

    def verify(self) -> None:
        self.trace.append("audit.verify")

    def state_for(self, idempotency_key: str) -> str | None:
        latest = self.latest_for(idempotency_key)
        return None if latest is None else latest.event_type

    def latest_for(self, idempotency_key: str) -> AuditedActionState | None:
        matches = [
            event
            for event in self.events
            if event["idempotency_key"] == idempotency_key
        ]
        if not matches:
            return None
        event = matches[-1]
        outcome = event["outcome_code"]
        return AuditedActionState(
            event_type=str(event["event_type"]),
            run_id=str(event["run_id"]),
            proposal_digest=str(event["proposal_digest"]),
            approval_digest=str(event["approval_digest"]),
            action_id=str(event["action_id"]),
            idempotency_key=str(event["idempotency_key"]),
            mailbox_ref=str(event["mailbox_ref"]),
            target_ref=str(event["target_ref"]),
            action_type=str(event["action_type"]),
            outcome_code=None if outcome is None else str(outcome),
        )

    def append(self, **event: object) -> object:
        self.trace.append(f"audit.{event['event_type']}")
        if self.fail_append:
            raise RuntimeError("synthetic audit failure")
        if self.fail_next_event_type == event["event_type"]:
            self.fail_next_event_type = None
            raise RuntimeError("synthetic audit failure")
        self.events.append(event)
        return event


def make_executor(
    *,
    reader: StubReader,
    writer: StubWriter,
    state: MemoryState,
    audit: MemoryAudit,
    factory_calls: list[int] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Executor:
    def writer_factory() -> StubWriter:
        if factory_calls is not None:
            factory_calls.append(1)
        return writer

    return Executor(
        approval_service=approval_service(),
        reader=reader,
        writer_factory=writer_factory,
        state=state,
        audit=audit,
        clock=clock or (lambda: NOW + timedelta(minutes=2)),
    )


def test_success_journals_durable_intent_before_provider_call() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )

    report = executor.execute(
        plan,
        approve(plan),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert report.results[0].status is ActionExecutionStatus.SUCCEEDED
    assert report.halted is False
    assert writer.execute_calls == 1
    assert trace.index("state.intent") < trace.index("audit.action.started")
    assert trace.index("audit.action.started") < trace.index("writer.execute")
    assert trace[-2:] == ["state.succeeded", "audit.action.succeeded"]


def test_invalid_or_empty_approval_never_opens_writer() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    calls: list[int] = []
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=StubWriter(trace),
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
        factory_calls=calls,
    )
    signed = approve(plan)

    with pytest.raises(ApprovalAuthenticationError):
        executor.execute(
            plan,
            replace(signed, mailbox_ref=f"mbx_{'9' * 32}"),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )
    no_op = executor.execute(
        plan,
        approve(plan, []),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert no_op.results == ()
    assert calls == []


def test_stale_state_fails_before_intent_or_provider_call() -> None:
    trace: list[str] = []
    plan = proposal(state=current_state())
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(current_state(change=2), trace),
        writer=writer,
        state=state,
        audit=audit,
    )

    report = executor.execute(
        plan,
        approve(plan),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert report.results[0].status is ActionExecutionStatus.STALE
    assert report.halted is True
    assert state.records == {}
    assert writer.execute_calls == 0


def test_wrong_account_and_unsupported_action_fail_preflight() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    reader = StubReader(source, trace)
    reader.identity = replace(
        reader.identity,
        account_fingerprint=f"sha256:{'9' * 64}",
    )
    executor = make_executor(
        reader=reader,
        writer=StubWriter(trace),
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
    )

    with pytest.raises(ExecutionPreflightError, match="reader mailbox"):
        executor.execute(
            plan,
            approve(plan),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )


def test_invalid_approval_claim_result_fails_before_writer() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    writer_calls: list[int] = []
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=StubWriter(trace),
        state=InvalidClaimState(trace),
        audit=MemoryAudit(trace),
        factory_calls=writer_calls,
    )

    with pytest.raises(ExecutionPreflightError, match="claim result"):
        executor.execute(
            plan,
            approve(plan),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer_calls == []


@pytest.mark.parametrize("capability", ["strong_change_tokens", "stable_item_ids"])
def test_weak_reader_capabilities_fail_before_writer(capability: str) -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    reader = StubReader(source, trace)
    setattr(reader, capability, False)
    writer_calls: list[int] = []
    executor = make_executor(
        reader=reader,
        writer=StubWriter(trace),
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
        factory_calls=writer_calls,
    )

    with pytest.raises(ExecutionPreflightError, match="stable identities"):
        executor.execute(
            plan,
            approve(plan),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer_calls == []


@pytest.mark.parametrize(
    ("status", "error", "expected"),
    [
        (
            WriteStatus.DEFINITE_FAILURE,
            ProviderErrorCode.CONFLICT,
            ActionExecutionStatus.DEFINITE_FAILURE,
        ),
        (
            WriteStatus.OUTCOME_UNKNOWN,
            ProviderErrorCode.OUTCOME_UNKNOWN,
            ActionExecutionStatus.INDETERMINATE,
        ),
    ],
)
def test_non_success_results_halt_without_retry(
    status: WriteStatus,
    error: ProviderErrorCode,
    expected: ActionExecutionStatus,
) -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    writer = StubWriter(
        trace,
        result=WriteResult(status=status, error_code=error),
    )
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
    )

    report = executor.execute(
        plan,
        approve(plan),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert report.results[0].status is expected
    assert report.halted is True
    assert writer.execute_calls == 1
    assert writer.reconcile_calls == 0


def test_move_success_must_preserve_stable_target_identity() -> None:
    trace: list[str] = []
    source = current_state()
    base = proposal(state=source)
    destination = FolderRef(profile=profile(), folder_id="synthetic-archive")
    move = replace(
        base.actions[0],
        action=MoveMessage(destination=destination),
    )
    plan = replace(base, actions=(move,))
    writer = StubWriter(
        trace,
        result=WriteResult(
            status=WriteStatus.SUCCEEDED,
            new_ref=replace(
                source.ref,
                provider_id="different-synthetic-message",
                folder_id=destination.folder_id,
            ),
        ),
    )
    writer.supported_actions = frozenset({ActionType.MOVE_MESSAGE})
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
    )

    report = executor.execute(
        plan,
        approve(plan),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert report.results[0].status is ActionExecutionStatus.INDETERMINATE
    assert report.results[0].outcome_code == ProviderErrorCode.INVALID_RESPONSE.value
    assert writer.execute_calls == 1


def test_replay_of_success_is_idempotent_and_never_calls_writer_again() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    replay = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert replay.results[0].status is ActionExecutionStatus.ALREADY_SUCCEEDED
    assert writer.execute_calls == 1


def test_terminal_audit_crash_is_repaired_without_provider_reexecution() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    audit.fail_next_event_type = "action.succeeded"
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )

    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        executor.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    key = next(iter(state.records))
    assert state.records[key].status is DurableActionStatus.SUCCEEDED
    assert audit.state_for(key) == "action.started"

    replay = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert replay.results[0].status is ActionExecutionStatus.ALREADY_SUCCEEDED
    assert audit.state_for(key) == "action.succeeded"
    assert writer.execute_calls == 1
    assert writer.reconcile_calls == 0


def test_terminal_state_without_outcome_code_fails_closed() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    key = next(iter(state.records))
    state.records[key] = replace(state.records[key], outcome_code=None)

    with pytest.raises(ExecutionStateError, match="missing outcome code"):
        executor.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer.execute_calls == 1


def test_audit_without_durable_state_never_redispatches() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    key = next(iter(state.records))
    del state.records[key]

    with pytest.raises(ExecutionStateError, match="audit event exists"):
        executor.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer.execute_calls == 1
    assert writer.reconcile_calls == 0


def test_new_action_is_refused_when_approval_expires_mid_batch() -> None:
    trace: list[str] = []
    source = current_state()
    base = proposal(state=source)
    second = replace(
        base.actions[0],
        action_id="55555555-5555-4555-8555-555555555555",
        target=replace(base.actions[0].target, target_ref=f"msg_{'3' * 32}"),
    )
    plan = replace(base, actions=(*base.actions, second))
    signed = approval_service().issue(
        plan,
        [action.action_id for action in plan.actions],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )
    observed_times = iter(
        (
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=31),
        )
    )
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        clock=lambda: next(observed_times),
    )

    report = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert [result.status for result in report.results] == [
        ActionExecutionStatus.SUCCEEDED,
        ActionExecutionStatus.REQUIRES_NEW_APPROVAL,
    ]
    assert report.results[-1].outcome_code == "authorization_expired"
    assert report.halted is True
    assert writer.execute_calls == 1
    assert len(state.records) == 1

    recovery_writer_calls: list[int] = []
    recovery = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        factory_calls=recovery_writer_calls,
        clock=lambda: NOW + timedelta(hours=2),
    )
    recovered = recovery.recover(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert [result.status for result in recovered.results] == [
        ActionExecutionStatus.ALREADY_SUCCEEDED,
        ActionExecutionStatus.NOT_STARTED,
    ]
    assert recovered.results[-1].outcome_code == "no_durable_intent"
    assert recovered.halted is True
    assert recovery_writer_calls == []


def test_expiry_after_intent_still_prevents_provider_dispatch() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    observed_times = iter(
        (
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=31),
        )
    )
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        clock=lambda: next(observed_times),
    )

    report = executor.execute(
        plan,
        approve(plan),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    key = next(iter(state.records))
    assert report.results[0].status is ActionExecutionStatus.REQUIRES_NEW_APPROVAL
    assert report.results[0].outcome_code == "authorization_expired"
    assert state.records[key].status is DurableActionStatus.REQUIRES_NEW_APPROVAL
    assert audit.state_for(key) == "action.requires_new_approval"
    assert writer.execute_calls == 0


def test_expiry_while_marking_dispatched_still_prevents_provider_call() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    observed_times = iter(
        (
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=31),
        )
    )
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        clock=lambda: next(observed_times),
    )

    report = executor.execute(
        plan,
        approve(plan),
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    key = next(iter(state.records))
    assert report.results[0].status is ActionExecutionStatus.REQUIRES_NEW_APPROVAL
    assert state.records[key].status is DurableActionStatus.REQUIRES_NEW_APPROVAL
    assert audit.state_for(key) == "action.requires_new_approval"
    assert "state.dispatched" in trace
    assert writer.execute_calls == 0


def test_execution_clock_rollback_fails_before_durable_intent() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    observed_times = iter(
        (
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=1),
        )
    )
    state = MemoryState(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=MemoryAudit(trace),
        clock=lambda: next(observed_times),
    )

    with pytest.raises(ExecutionPreflightError, match="clock moved backwards"):
        executor.execute(
            plan,
            approve(plan),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert state.records == {}
    assert writer.execute_calls == 0


def test_multi_action_execution_uses_canonical_authenticated_order() -> None:
    trace: list[str] = []
    source = current_state()
    base = proposal(state=source)
    first = base.actions[0]
    second = replace(
        first,
        action_id="22222222-2222-4222-8222-222222222222",
        target=replace(first.target, target_ref=f"msg_{'3' * 32}"),
    )
    plan = replace(base, actions=(first, second))
    signed = approval_service().issue(
        plan,
        [first.action_id, second.action_id],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
    )

    report = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    expected = [second.action_id, first.action_id]
    assert writer.executed_action_ids == expected
    assert [result.action_id for result in report.results] == expected


def test_approval_replay_under_different_run_fails_before_writer() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    factory_calls: list[int] = []
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        factory_calls=factory_calls,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    with pytest.raises(ExecutionPreflightError, match="different run"):
        executor.execute(
            plan,
            signed,
            run_id="55555555-5555-4555-8555-555555555555",
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert factory_calls == [1]
    assert writer.execute_calls == 1


def test_ambiguous_prior_dispatch_reconciles_without_reexecution() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(
        trace,
        reconciliation=Reconciliation(
            status=ReconciliationStatus.DESIRED_STATE_PRESENT,
            current=current_state(is_read=True),
        ),
    )
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    first = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    key = next(iter(state.records))
    record = state.records[key]
    state.records[key] = replace(
        record,
        status=DurableActionStatus.INDETERMINATE,
        outcome_code="outcome_unknown",
    )
    audit.events[-1]["event_type"] = "action.indeterminate"
    writer.execute_calls = 0

    recovered = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert first.results[0].status is ActionExecutionStatus.SUCCEEDED
    assert recovered.results[0].status is ActionExecutionStatus.RECONCILED_SUCCEEDED
    assert writer.execute_calls == 0
    assert writer.reconcile_calls == 1


def test_expired_artifacts_recover_only_existing_intent_for_same_run() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(
        trace,
        result=WriteResult(
            status=WriteStatus.OUTCOME_UNKNOWN,
            error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
        ),
        reconciliation=Reconciliation(
            status=ReconciliationStatus.DESIRED_STATE_PRESENT,
            current=current_state(is_read=True),
        ),
    )
    initial = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    initial.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    expired = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        clock=lambda: NOW + timedelta(hours=2),
    )

    with pytest.raises(ApprovalExpiredError):
        expired.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )
    with pytest.raises(ExecutionPreflightError, match="different recovery run"):
        expired.recover(
            plan,
            signed,
            run_id="55555555-5555-4555-8555-555555555555",
            expected_mailbox_ref=MAILBOX_REF,
        )

    recovered = expired.recover(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert recovered.results[0].status is ActionExecutionStatus.RECONCILED_SUCCEEDED
    assert writer.execute_calls == 1
    assert writer.reconcile_calls == 1


def test_recovery_refuses_unclaimed_or_missing_durable_intent() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    writer_calls: list[int] = []
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=StubWriter(trace),
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
        factory_calls=writer_calls,
        clock=lambda: NOW + timedelta(hours=2),
    )

    with pytest.raises(ExecutionPreflightError, match="durable execution intent"):
        executor.recover(
            plan,
            approve(plan),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer_calls == []


def test_recovery_does_not_create_authority_for_unclaimed_durable_intent() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(
        trace,
        result=WriteResult(
            status=WriteStatus.OUTCOME_UNKNOWN,
            error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
        ),
    )
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
        clock=lambda: NOW + timedelta(minutes=2),
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    state.approvals.clear()
    execute_calls = writer.execute_calls

    with pytest.raises(ExecutionPreflightError, match="previously claimed approval"):
        executor.recover(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert state.approvals == {}
    assert writer.execute_calls == execute_calls
    assert writer.reconcile_calls == 0


def test_reconciliation_claim_is_validated_against_exact_desired_state() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    writer = StubWriter(
        trace,
        result=WriteResult(
            status=WriteStatus.OUTCOME_UNKNOWN,
            error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
        ),
        reconciliation=Reconciliation(
            status=ReconciliationStatus.DESIRED_STATE_PRESENT,
            current=current_state(is_read=False),
        ),
    )
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=MemoryState(trace),
        audit=MemoryAudit(trace),
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    recovered = executor.recover(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert recovered.results[0].status is ActionExecutionStatus.INDETERMINATE
    assert recovered.results[0].outcome_code == ProviderErrorCode.INVALID_RESPONSE.value
    assert writer.execute_calls == 1
    assert writer.reconcile_calls == 1


def test_reconciliation_not_present_requires_new_approval() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(
        trace,
        result=WriteResult(
            status=WriteStatus.OUTCOME_UNKNOWN,
            error_code=ProviderErrorCode.OUTCOME_UNKNOWN,
        ),
        reconciliation=Reconciliation(
            status=ReconciliationStatus.NOT_PRESENT,
            current=current_state(),
        ),
    )
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    recovered = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert recovered.results[0].status is ActionExecutionStatus.REQUIRES_NEW_APPROVAL
    assert writer.execute_calls == 1


def test_audit_append_failure_prevents_provider_call() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    audit = MemoryAudit(trace)
    audit.fail_append = True
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=MemoryState(trace),
        audit=audit,
    )

    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        executor.execute(
            plan,
            approve(plan),
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer.execute_calls == 0


def test_missing_started_audit_is_repaired_then_reconciled_without_dispatch() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    audit.fail_next_event_type = "action.started"
    writer = StubWriter(
        trace,
        reconciliation=Reconciliation(
            status=ReconciliationStatus.NOT_PRESENT,
            current=source,
        ),
    )
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )

    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        executor.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    key = next(iter(state.records))
    assert state.records[key].status is DurableActionStatus.INTENT_RECORDED
    assert audit.state_for(key) is None
    assert writer.execute_calls == 0

    replay = executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert replay.results[0].status is ActionExecutionStatus.REQUIRES_NEW_APPROVAL
    assert audit.state_for(key) == "action.requires_new_approval"
    assert writer.execute_calls == 0
    assert writer.reconcile_calls == 1


def test_tampered_durable_intent_or_audit_state_fails_closed() -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    audit.events[-1]["event_type"] = "action.failed"

    with pytest.raises(ExecutionStateError, match="disagree"):
        executor.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "55555555-5555-4555-8555-555555555555"),
        ("approval_digest", f"sha256:{'9' * 64}"),
        ("outcome_code", "mismatched_outcome"),
    ],
)
def test_full_audit_binding_must_match_durable_state(
    field: str,
    value: str,
) -> None:
    trace: list[str] = []
    source = current_state()
    plan = proposal(state=source)
    signed = approve(plan)
    state = MemoryState(trace)
    audit = MemoryAudit(trace)
    writer = StubWriter(trace)
    executor = make_executor(
        reader=StubReader(source, trace),
        writer=writer,
        state=state,
        audit=audit,
    )
    executor.execute(
        plan,
        signed,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )
    audit.events[-1][field] = value

    with pytest.raises(ExecutionStateError, match="disagree"):
        executor.execute(
            plan,
            signed,
            run_id=RUN_ID,
            expected_mailbox_ref=MAILBOX_REF,
        )

    assert writer.execute_calls == 1
