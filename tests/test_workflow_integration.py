from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from mailjanitor.adapters.fake import FakeMailbox, FakeOperation
from mailjanitor.adapters.local.audit import AuditLedger
from mailjanitor.adapters.local.state import SqliteOperationalState
from mailjanitor.domain import (
    ActionType,
    MailboxItemRef,
    MailboxProfileRef,
    MessageMetadata,
    ProviderKind,
    SetReadState,
)
from mailjanitor.ports import AdapterIdentity
from mailjanitor.workflow.approval import ApprovalService
from mailjanitor.workflow.execution import (
    ActionExecutionStatus,
    ApprovalClaimStatus,
    DurableActionStatus,
    Executor,
)
from mailjanitor.workflow.proposal import ActionProposal, ActionSpec, TargetSpec

NOW = datetime(2026, 8, 3, 18, 0, tzinfo=UTC)
EXECUTION_TIME = NOW + timedelta(minutes=2)
RUN_ID = "11111111-1111-4111-8111-111111111111"
PROPOSAL_ID = "22222222-2222-4222-8222-222222222222"
APPROVAL_ID = "33333333-3333-4333-8333-333333333333"
APPROVED_ACTION_ID = "44444444-4444-4444-8444-444444444444"
UNAPPROVED_ACTION_ID = "55555555-5555-4555-8555-555555555555"
MAILBOX_REF = f"mbx_{'1' * 32}"
ACCOUNT_FINGERPRINT = f"sha256:{'a' * 64}"
PROFILE = MailboxProfileRef(
    provider=ProviderKind.FIXTURE,
    profile_id="integration_profile",
)
INBOX = "synthetic-inbox"
APPROVAL_KEY = b"synthetic-integration-approval-key-32-bytes"
AUDIT_KEY = b"synthetic-integration-audit-key-at-least-32-bytes"


def _message(provider_id: str, *, minute: int) -> MessageMetadata:
    return MessageMetadata(
        ref=MailboxItemRef(
            profile=PROFILE,
            provider_id=provider_id,
            folder_id=INBOX,
            change_token=f"synthetic-change-{provider_id}",
        ),
        sender_address=f"{provider_id}@example.test",
        sender_domain="example.test",
        sender_display_name="Synthetic Sender",
        subject=f"Synthetic notification {provider_id}",
        received_at=NOW + timedelta(minutes=minute),
        is_read=False,
        has_attachments=False,
        attachment_count=0,
    )


def _action(message: MessageMetadata, *, action_id: str, target_ref: str) -> ActionSpec:
    return ActionSpec(
        action_id=action_id,
        target=TargetSpec(
            item_ref=message.ref,
            before_state_digest=message.state_fingerprint,
            target_ref=target_ref,
        ),
        action=SetReadState(is_read=True),
        owner_summary="Synthetic item: mark read",
    )


def test_exact_approved_action_is_durable_audited_and_idempotent(
    tmp_path: Path,
) -> None:
    approved_message = _message("item-approved", minute=1)
    unapproved_message = _message("item-unapproved", minute=2)
    proposal = ActionProposal(
        proposal_id=PROPOSAL_ID,
        run_nonce="b" * 64,
        profile=PROFILE,
        account_fingerprint=ACCOUNT_FINGERPRINT,
        mailbox_ref=MAILBOX_REF,
        generated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        actions=(
            _action(
                approved_message,
                action_id=APPROVED_ACTION_ID,
                target_ref=f"msg_{'2' * 32}",
            ),
            _action(
                unapproved_message,
                action_id=UNAPPROVED_ACTION_ID,
                target_ref=f"msg_{'3' * 32}",
            ),
        ),
    )
    approval_service = ApprovalService(
        key=APPROVAL_KEY,
        key_id="synthetic-owner-key",
        approval_id_factory=lambda: APPROVAL_ID,
        nonce_factory=lambda: "c" * 64,
    )
    approval = approval_service.issue(
        proposal,
        [APPROVED_ACTION_ID],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )
    mailbox = FakeMailbox(
        identity=AdapterIdentity(
            profile=PROFILE,
            account_fingerprint=ACCOUNT_FINGERPRINT,
        ),
        mailbox_ref=MAILBOX_REF,
        messages=(approved_message, unapproved_message),
        folder_ids=(INBOX,),
        supported_actions=frozenset({ActionType.SET_READ_STATE}),
    )
    state_path = tmp_path / "operational-state.sqlite3"
    audit_path = tmp_path / "actions.jsonl"
    state = SqliteOperationalState(state_path)
    event_ids = iter(
        (
            "66666666-6666-4666-8666-666666666666",
            "77777777-7777-4777-8777-777777777777",
        )
    )
    audit = AuditLedger(
        audit_path,
        ledger_id="integration-actions",
        integrity_key=AUDIT_KEY,
        anchor=state,
        clock=lambda: EXECUTION_TIME,
        event_id_factory=lambda: next(event_ids),
    )
    executor = Executor(
        approval_service=approval_service,
        reader=mailbox.reader,
        writer_factory=lambda: mailbox.writer,
        state=state,
        audit=audit,
        clock=lambda: EXECUTION_TIME,
    )

    report = executor.execute(
        proposal,
        approval,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert report.halted is False
    assert len(report.results) == 1
    assert report.results[0].action_id == APPROVED_ACTION_ID
    assert report.results[0].status is ActionExecutionStatus.SUCCEEDED
    assert report.results[0].outcome_code == "applied"
    assert mailbox.operation_count(FakeOperation.EXECUTE_ONE) == 1
    assert mailbox.provider_dispatch_count() == 1
    approved_current = mailbox.reader.read_current(approved_message.ref)
    unapproved_current = mailbox.reader.read_current(unapproved_message.ref)
    assert approved_current is not None
    assert approved_current.is_read is True
    assert unapproved_current is not None
    assert unapproved_current.is_read is False

    records = audit.records()
    assert [record.event_type for record in records] == [
        "action.started",
        "action.succeeded",
    ]
    assert {record.action_id for record in records} == {APPROVED_ACTION_ID}
    assert all(record.proposal_digest == proposal.digest for record in records)
    assert all(record.approval_digest == approval.digest for record in records)
    idempotency_key = records[0].idempotency_key
    assert records[1].idempotency_key == idempotency_key

    reopened_state = SqliteOperationalState(state_path)
    durable = reopened_state.get(idempotency_key)
    assert durable is not None
    assert durable.status is DurableActionStatus.SUCCEEDED
    assert durable.outcome_code == "applied"
    assert durable.intent.action_id == APPROVED_ACTION_ID
    assert (
        reopened_state.approval_claim_status(
            approval.digest,
            proposal.digest,
            RUN_ID,
        )
        is ApprovalClaimStatus.SAME_RUN
    )

    reopened_audit = AuditLedger(
        audit_path,
        ledger_id="integration-actions",
        integrity_key=AUDIT_KEY,
        anchor=reopened_state,
        clock=lambda: EXECUTION_TIME,
    )
    replay_executor = Executor(
        approval_service=approval_service,
        reader=mailbox.reader,
        writer_factory=lambda: mailbox.writer,
        state=reopened_state,
        audit=reopened_audit,
        clock=lambda: EXECUTION_TIME,
    )

    replay = replay_executor.execute(
        proposal,
        approval,
        run_id=RUN_ID,
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert replay.halted is False
    assert replay.results[0].status is ActionExecutionStatus.ALREADY_SUCCEEDED
    assert mailbox.operation_count(FakeOperation.EXECUTE_ONE) == 1
    assert mailbox.provider_dispatch_count(idempotency_key) == 1
    assert reopened_audit.records() == records
