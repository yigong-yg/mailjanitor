"""Fail-closed execution of explicitly approved, exact-target actions."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from mailjanitor.canonical import canonical_digest
from mailjanitor.domain import (
    ApprovedMailboxCommand,
    MoveMessage,
    SetCategory,
    SetReadState,
)
from mailjanitor.ports import (
    AdapterIdentity,
    CurrentItemState,
    MailboxReader,
    MailboxWriter,
    ProviderErrorCode,
    Reconciliation,
    ReconciliationStatus,
    WriteResult,
    WriteStatus,
)

if TYPE_CHECKING:
    from mailjanitor.workflow.approval import ApprovalArtifact, ApprovalService
    from mailjanitor.workflow.proposal import ActionProposal, ActionSpec


class ExecutionError(RuntimeError):
    """Base class for a closed execution failure."""


class ExecutionPreflightError(ExecutionError):
    """Raised before mutation when identity or capability checks fail."""


class ExecutionStateError(ExecutionError):
    """Raised when durable state and audit cannot prove a safe transition."""


class DurableActionStatus(StrEnum):
    """Authoritative local crash-recovery state."""

    INTENT_RECORDED = "intent_recorded"
    DISPATCHED = "dispatched"
    SUCCEEDED = "succeeded"
    DEFINITE_FAILURE = "definite_failure"
    INDETERMINATE = "indeterminate"
    RECONCILED_SUCCEEDED = "reconciled_succeeded"
    REQUIRES_NEW_APPROVAL = "requires_new_approval"


class ActionExecutionStatus(StrEnum):
    """Redacted per-action result returned to the owner."""

    SUCCEEDED = "succeeded"
    ALREADY_SUCCEEDED = "already_succeeded"
    DEFINITE_FAILURE = "definite_failure"
    STALE = "stale"
    INDETERMINATE = "indeterminate"
    RECONCILED_SUCCEEDED = "reconciled_succeeded"
    REQUIRES_NEW_APPROVAL = "requires_new_approval"
    NOT_STARTED = "not_started"


class ApprovalClaimStatus(StrEnum):
    """Atomic result of binding an approval artifact to one execution run."""

    CLAIMED = "claimed"
    SAME_RUN = "same_run"
    DIFFERENT_RUN = "different_run"


@dataclass(frozen=True, slots=True)
class ExecutionIntent:
    """Sensitive-free durable identity of one approved provider call."""

    idempotency_key: str
    proposal_digest: str
    approval_digest: str
    action_id: str
    mailbox_ref: str
    target_ref: str
    action_type: str


@dataclass(frozen=True, slots=True)
class StoredExecution:
    """Authoritative action state supplied by a local state adapter."""

    intent: ExecutionIntent
    status: DurableActionStatus
    outcome_code: str | None = None


@dataclass(frozen=True, slots=True)
class AuditedActionState:
    """Latest verified audit projection for one idempotency key."""

    event_type: str
    run_id: str
    proposal_digest: str
    approval_digest: str
    action_id: str
    idempotency_key: str
    mailbox_ref: str
    target_ref: str
    action_type: str
    outcome_code: str | None


@dataclass(slots=True)
class _AuthorizationWindow:
    """Run-local wall-clock guard for fresh provider dispatch authority."""

    expires_at: datetime
    last_checked_at: datetime

    def remains_fresh(self, observed_at: datetime) -> bool:
        if (
            not isinstance(observed_at, datetime)
            or observed_at.tzinfo is None
            or observed_at.utcoffset() != timedelta(0)
        ):
            raise ExecutionPreflightError("execution clock must return a UTC timestamp")
        if observed_at < self.last_checked_at:
            raise ExecutionPreflightError("execution clock moved backwards")
        self.last_checked_at = observed_at
        return observed_at < self.expires_at


class ExecutionStateStore(Protocol):
    """Narrow durable-CAS boundary; a SQLite adapter may implement this."""

    def profile_lock(self, mailbox_ref: str) -> AbstractContextManager[None]:
        """Hold an exclusive mailbox-profile execution lock."""
        ...

    def get(self, idempotency_key: str) -> StoredExecution | None:
        """Return the authoritative state for an exact idempotency key."""
        ...

    def claim_approval(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus:
        """Atomically bind approval to one run, allowing only same-run recovery."""
        ...

    def approval_claim_status(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus | None:
        """Read an existing approval binding without creating one."""
        ...

    def record_intent(self, intent: ExecutionIntent) -> bool:
        """Atomically insert intent; return false when the key already exists."""
        ...

    def mark_dispatched(self, idempotency_key: str) -> None:
        """Durably mark that a provider call may be issued."""
        ...

    def record_terminal(
        self,
        idempotency_key: str,
        status: DurableActionStatus,
        outcome_code: str,
    ) -> None:
        """Durably store a terminal or reconciliation-required state."""
        ...


class AuditJournal(Protocol):
    """Redacted append-only projection required before provider mutation."""

    def verify(self) -> None: ...

    def latest_for(self, idempotency_key: str) -> AuditedActionState | None: ...

    def append(
        self,
        *,
        event_type: str,
        run_id: str,
        proposal_digest: str,
        approval_digest: str,
        action_id: str,
        idempotency_key: str,
        mailbox_ref: str,
        target_ref: str,
        action_type: str,
        outcome_code: str | None = None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ActionExecutionResult:
    action_id: str
    status: ActionExecutionStatus
    outcome_code: str


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    run_id: str
    proposal_digest: str
    approval_digest: str
    results: tuple[ActionExecutionResult, ...]
    halted: bool


@dataclass(frozen=True, slots=True)
class _PreparedAction:
    """One fully validated command and its sensitive-free durable intent."""

    action: ActionSpec
    command: ApprovedMailboxCommand
    intent: ExecutionIntent


class Executor:
    """Verify authority, journal intent, and execute typed actions one at a time."""

    def __init__(
        self,
        *,
        approval_service: ApprovalService,
        reader: MailboxReader,
        writer_factory: Callable[[], MailboxWriter],
        state: ExecutionStateStore,
        audit: AuditJournal,
        clock: Callable[[], datetime],
    ) -> None:
        self._approval_service = approval_service
        self._reader = reader
        self._writer_factory = writer_factory
        self._state = state
        self._audit = audit
        self._clock = clock

    def execute(
        self,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        *,
        run_id: str,
        expected_mailbox_ref: str,
    ) -> ExecutionReport:
        """Execute the exact approved subset or stop at the first uncertainty."""
        _require_uuid(run_id, "run_id")
        verified_at = self._clock()
        selected = self._approval_service.verify(
            proposal,
            approval,
            now=verified_at,
            expected_mailbox_ref=expected_mailbox_ref,
        )
        prepared = _prepare_selected(proposal, approval, selected)
        authorization = _AuthorizationWindow(
            expires_at=min(proposal.expires_at, approval.expires_at),
            last_checked_at=verified_at,
        )
        self._audit.verify()
        if not prepared:
            return ExecutionReport(
                run_id=run_id,
                proposal_digest=proposal.digest,
                approval_digest=approval.digest,
                results=(),
                halted=False,
            )
        expected_identity = AdapterIdentity(
            profile=proposal.profile,
            account_fingerprint=proposal.account_fingerprint,
        )
        reader_capabilities = self._reader.capabilities(proposal.profile)
        if reader_capabilities.identity != expected_identity:
            raise ExecutionPreflightError("reader mailbox identity mismatch")
        if (
            not reader_capabilities.strong_change_tokens
            or not reader_capabilities.stable_item_ids
        ):
            raise ExecutionPreflightError(
                "reader lacks stable identities or strong change tokens"
            )
        with self._state.profile_lock(proposal.mailbox_ref):
            self._audit.verify()
            claim = self._state.claim_approval(
                approval.digest,
                proposal.digest,
                run_id,
            )
            if claim is ApprovalClaimStatus.DIFFERENT_RUN:
                raise ExecutionPreflightError(
                    "approval is already claimed by a different run"
                )
            if claim not in {
                ApprovalClaimStatus.CLAIMED,
                ApprovalClaimStatus.SAME_RUN,
            }:
                raise ExecutionPreflightError("approval claim result is invalid")
            writer = self._writer_factory()
            self._validate_writer(
                writer,
                proposal=proposal,
                selected=tuple(item.action for item in prepared),
                expected_identity=expected_identity,
            )
            return self._run_selected(
                writer,
                proposal=proposal,
                approval=approval,
                prepared=prepared,
                run_id=run_id,
                authorization=authorization,
            )

    def recover(
        self,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        *,
        run_id: str,
        expected_mailbox_ref: str,
    ) -> ExecutionReport:
        """Reconcile only pre-existing durable intents, even after expiry.

        Recovery authenticates the original artifact and requires its original
        claimed run. Proposal lines without durable intent are reported as not
        started, and this path never calls ``execute_one``.
        """
        _require_uuid(run_id, "run_id")
        selected = self._approval_service.verify_for_recovery(
            proposal,
            approval,
            now=self._clock(),
            expected_mailbox_ref=expected_mailbox_ref,
        )
        prepared = _prepare_selected(proposal, approval, selected)
        self._audit.verify()
        if not prepared:
            return ExecutionReport(
                run_id=run_id,
                proposal_digest=proposal.digest,
                approval_digest=approval.digest,
                results=(),
                halted=False,
            )
        expected_identity = AdapterIdentity(
            profile=proposal.profile,
            account_fingerprint=proposal.account_fingerprint,
        )
        with self._state.profile_lock(proposal.mailbox_ref):
            self._audit.verify()
            durable: list[tuple[_PreparedAction, StoredExecution | None]] = []
            durable_count = 0
            for item in prepared:
                stored = self._state.get(item.command.idempotency_key)
                if stored is None:
                    if self._audit.latest_for(item.command.idempotency_key) is not None:
                        raise ExecutionStateError(
                            "audit event exists without durable state"
                        )
                    durable.append((item, None))
                    continue
                if stored.intent != item.intent:
                    raise ExecutionStateError(
                        "idempotency key is bound to different intent"
                    )
                durable.append((item, stored))
                durable_count += 1
            if durable_count == 0:
                raise ExecutionPreflightError(
                    "recovery requires an existing durable execution intent"
                )
            claim = self._state.approval_claim_status(
                approval.digest,
                proposal.digest,
                run_id,
            )
            if claim is not ApprovalClaimStatus.SAME_RUN:
                if claim is ApprovalClaimStatus.DIFFERENT_RUN:
                    raise ExecutionPreflightError(
                        "approval is claimed by a different recovery run"
                    )
                raise ExecutionPreflightError(
                    "recovery requires a previously claimed approval"
                )
            reconcilable = _recovery_actions_requiring_writer(tuple(durable))
            writer: MailboxWriter | None = None
            if reconcilable:
                writer = self._writer_factory()
                self._validate_writer(
                    writer,
                    proposal=proposal,
                    selected=reconcilable,
                    expected_identity=expected_identity,
                )
            return self._run_recovery(
                writer,
                proposal=proposal,
                approval=approval,
                durable=tuple(durable),
                run_id=run_id,
            )

    def _validate_writer(
        self,
        writer: MailboxWriter,
        *,
        proposal: ActionProposal,
        selected: tuple[ActionSpec, ...],
        expected_identity: AdapterIdentity,
    ) -> None:
        capabilities = writer.capabilities(proposal.profile)
        if capabilities.identity != expected_identity:
            raise ExecutionPreflightError("writer mailbox identity mismatch")
        if not capabilities.strong_preconditions:
            raise ExecutionPreflightError("writer lacks strong preconditions")
        unsupported = {
            action.action_type
            for action in selected
            if action.action_type not in capabilities.supported_actions
        }
        if unsupported:
            raise ExecutionPreflightError("writer does not support an approved action")

    def _run_selected(
        self,
        writer: MailboxWriter,
        *,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        prepared: tuple[_PreparedAction, ...],
        run_id: str,
        authorization: _AuthorizationWindow,
    ) -> ExecutionReport:
        results: list[ActionExecutionResult] = []
        halted = False
        for item in prepared:
            result, must_halt = self._execute_action(
                writer,
                prepared=item,
                run_id=run_id,
                authorization=authorization,
            )
            results.append(result)
            if must_halt:
                halted = True
                break
        return ExecutionReport(
            run_id=run_id,
            proposal_digest=proposal.digest,
            approval_digest=approval.digest,
            results=tuple(results),
            halted=halted,
        )

    def _run_recovery(
        self,
        writer: MailboxWriter | None,
        *,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        durable: tuple[tuple[_PreparedAction, StoredExecution | None], ...],
        run_id: str,
    ) -> ExecutionReport:
        results: list[ActionExecutionResult] = []
        halted = False
        for item, stored in durable:
            if stored is None:
                result, must_halt = _not_started_result(item.action.action_id)
            else:
                result, must_halt = self._resume_existing(
                    writer,
                    command=item.command,
                    intent=item.intent,
                    stored=stored,
                    run_id=run_id,
                )
            results.append(result)
            if must_halt:
                halted = True
                break
        return ExecutionReport(
            run_id=run_id,
            proposal_digest=proposal.digest,
            approval_digest=approval.digest,
            results=tuple(results),
            halted=halted,
        )

    def _execute_action(
        self,
        writer: MailboxWriter,
        *,
        prepared: _PreparedAction,
        run_id: str,
        authorization: _AuthorizationWindow,
    ) -> tuple[ActionExecutionResult, bool]:
        command = prepared.command
        intent = prepared.intent
        existing = self._state.get(command.idempotency_key)
        if existing is not None:
            return self._resume_existing(
                writer,
                command=command,
                intent=intent,
                stored=existing,
                run_id=run_id,
            )
        return self._execute_new_action(
            writer,
            prepared=prepared,
            run_id=run_id,
            authorization=authorization,
        )

    def _execute_new_action(
        self,
        writer: MailboxWriter,
        *,
        prepared: _PreparedAction,
        run_id: str,
        authorization: _AuthorizationWindow,
    ) -> tuple[ActionExecutionResult, bool]:
        action = prepared.action
        command = prepared.command
        intent = prepared.intent
        if self._audit.latest_for(command.idempotency_key) is not None:
            raise ExecutionStateError("audit event exists without durable state")
        current = self._reader.read_current(action.target.item_ref)
        if (
            current is None
            or current.state_fingerprint != action.target.before_state_digest
        ):
            return (
                ActionExecutionResult(
                    action_id=action.action_id,
                    status=ActionExecutionStatus.STALE,
                    outcome_code="stale_state",
                ),
                True,
            )
        if not authorization.remains_fresh(self._clock()):
            return _authorization_expired_result(action.action_id)
        if not self._state.record_intent(intent):
            raced = self._state.get(command.idempotency_key)
            if raced is None:
                raise ExecutionStateError("intent claim lost without durable state")
            return self._resume_existing(
                writer,
                command=command,
                intent=intent,
                stored=raced,
                run_id=run_id,
            )
        self._append_audit("action.started", intent=intent, run_id=run_id)
        if not authorization.remains_fresh(self._clock()):
            return self._record_expired_intent(intent, run_id=run_id)
        self._state.mark_dispatched(command.idempotency_key)
        if not authorization.remains_fresh(self._clock()):
            return self._record_expired_intent(intent, run_id=run_id)
        result = writer.execute_one(command)
        return self._handle_write_result(
            result,
            command=command,
            intent=intent,
            run_id=run_id,
        )

    def _handle_write_result(
        self,
        result: WriteResult,
        *,
        command: ApprovedMailboxCommand,
        intent: ExecutionIntent,
        run_id: str,
    ) -> tuple[ActionExecutionResult, bool]:
        if result.status is WriteStatus.SUCCEEDED:
            if not _result_ref_is_valid(command, result):
                return self._record_result(
                    intent,
                    status=DurableActionStatus.INDETERMINATE,
                    public_status=ActionExecutionStatus.INDETERMINATE,
                    event_type="action.indeterminate",
                    outcome_code=ProviderErrorCode.INVALID_RESPONSE.value,
                    run_id=run_id,
                    halt=True,
                )
            return self._record_result(
                intent,
                status=DurableActionStatus.SUCCEEDED,
                public_status=ActionExecutionStatus.SUCCEEDED,
                event_type="action.succeeded",
                outcome_code="applied",
                run_id=run_id,
                halt=False,
            )
        outcome_code = _provider_code(result)
        if result.status is WriteStatus.DEFINITE_FAILURE:
            return self._record_result(
                intent,
                status=DurableActionStatus.DEFINITE_FAILURE,
                public_status=ActionExecutionStatus.DEFINITE_FAILURE,
                event_type="action.failed",
                outcome_code=outcome_code,
                run_id=run_id,
                halt=True,
            )
        return self._record_result(
            intent,
            status=DurableActionStatus.INDETERMINATE,
            public_status=ActionExecutionStatus.INDETERMINATE,
            event_type="action.indeterminate",
            outcome_code=outcome_code,
            run_id=run_id,
            halt=True,
        )

    def _resume_existing(
        self,
        writer: MailboxWriter | None,
        *,
        command: ApprovedMailboxCommand,
        intent: ExecutionIntent,
        stored: StoredExecution,
        run_id: str,
    ) -> tuple[ActionExecutionResult, bool]:
        if stored.intent != intent:
            raise ExecutionStateError("idempotency key is bound to different intent")
        audit_state = self._repair_audit_projection(stored, run_id=run_id)
        terminal = _terminal_replay_result(stored)
        if terminal is not None:
            return terminal
        if writer is None:
            raise ExecutionStateError("reconciliation writer is unavailable")
        _require_reconcilable_audit(
            audit_state,
            stored.status,
        )
        reconciliation = writer.reconcile(command)
        return self._handle_reconciliation(
            reconciliation,
            command=command,
            intent=intent,
            run_id=run_id,
        )

    def _repair_audit_projection(
        self,
        stored: StoredExecution,
        *,
        run_id: str,
    ) -> str | None:
        """Repair only a provable one-event state/audit crash window.

        Durable state is authoritative for whether a provider outcome was
        recorded.  Audit repair is allowed only when the current event is the
        exact predecessor of that state; every other mismatch fails closed.
        """
        audited = self._audit.latest_for(stored.intent.idempotency_key)
        if audited is not None:
            _require_matching_audit_identity(audited, stored.intent, run_id=run_id)
        if stored.status is DurableActionStatus.INTENT_RECORDED:
            if audited is None:
                self._append_audit(
                    "action.started", intent=stored.intent, run_id=run_id
                )
                return "action.started"
            if not _is_started_audit(audited):
                raise ExecutionStateError(
                    "durable state and audit recovery state disagree"
                )
            return audited.event_type

        if stored.status is DurableActionStatus.DISPATCHED:
            if audited is None or not _is_started_audit(audited):
                raise ExecutionStateError(
                    "durable state and audit recovery state disagree"
                )
            return audited.event_type

        return self._repair_terminal_audit(
            stored,
            audited=audited,
            run_id=run_id,
        )

    def _repair_terminal_audit(
        self,
        stored: StoredExecution,
        *,
        audited: AuditedActionState | None,
        run_id: str,
    ) -> str:
        """Project one durable terminal state from its exact audit predecessor."""
        terminal_projection = _terminal_audit_projection(stored.status)
        if terminal_projection is None:
            raise ExecutionStateError("durable execution status is invalid")
        expected, predecessors = terminal_projection
        if stored.outcome_code is None:
            raise ExecutionStateError("terminal durable state is missing outcome code")
        if (
            audited is not None
            and audited.event_type == expected
            and audited.outcome_code == stored.outcome_code
        ):
            return audited.event_type
        if audited is None or not _is_legal_audit_predecessor(audited, predecessors):
            raise ExecutionStateError("durable state and audit terminal state disagree")
        self._append_audit(
            expected,
            intent=stored.intent,
            run_id=run_id,
            outcome_code=stored.outcome_code,
        )
        return expected

    def _handle_reconciliation(
        self,
        reconciliation: Reconciliation,
        *,
        command: ApprovedMailboxCommand,
        intent: ExecutionIntent,
        run_id: str,
    ) -> tuple[ActionExecutionResult, bool]:
        if reconciliation.status is ReconciliationStatus.DESIRED_STATE_PRESENT:
            current = reconciliation.current
            if current is None or not _current_proves_desired(command, current):
                return self._record_result(
                    intent,
                    status=DurableActionStatus.INDETERMINATE,
                    public_status=ActionExecutionStatus.INDETERMINATE,
                    event_type="action.indeterminate",
                    outcome_code=ProviderErrorCode.INVALID_RESPONSE.value,
                    run_id=run_id,
                    halt=True,
                )
            return self._record_result(
                intent,
                status=DurableActionStatus.RECONCILED_SUCCEEDED,
                public_status=ActionExecutionStatus.RECONCILED_SUCCEEDED,
                event_type="action.reconciled_succeeded",
                outcome_code="desired_state_present",
                run_id=run_id,
                halt=False,
            )
        if reconciliation.status is ReconciliationStatus.NOT_PRESENT:
            outcome_code = _reconciliation_code(
                reconciliation,
                default="desired_state_not_present",
            )
            return self._record_result(
                intent,
                status=DurableActionStatus.REQUIRES_NEW_APPROVAL,
                public_status=ActionExecutionStatus.REQUIRES_NEW_APPROVAL,
                event_type="action.requires_new_approval",
                outcome_code=outcome_code,
                run_id=run_id,
                halt=True,
            )
        return self._record_result(
            intent,
            status=DurableActionStatus.INDETERMINATE,
            public_status=ActionExecutionStatus.INDETERMINATE,
            event_type="action.indeterminate",
            outcome_code=_reconciliation_code(
                reconciliation,
                default="reconciliation_unknown",
            ),
            run_id=run_id,
            halt=True,
        )

    def _record_result(
        self,
        intent: ExecutionIntent,
        *,
        status: DurableActionStatus,
        public_status: ActionExecutionStatus,
        event_type: str,
        outcome_code: str,
        run_id: str,
        halt: bool,
    ) -> tuple[ActionExecutionResult, bool]:
        self._state.record_terminal(intent.idempotency_key, status, outcome_code)
        self._append_audit(
            event_type,
            intent=intent,
            run_id=run_id,
            outcome_code=outcome_code,
        )
        return (
            ActionExecutionResult(
                action_id=intent.action_id,
                status=public_status,
                outcome_code=outcome_code,
            ),
            halt,
        )

    def _record_expired_intent(
        self,
        intent: ExecutionIntent,
        *,
        run_id: str,
    ) -> tuple[ActionExecutionResult, bool]:
        return self._record_result(
            intent,
            status=DurableActionStatus.REQUIRES_NEW_APPROVAL,
            public_status=ActionExecutionStatus.REQUIRES_NEW_APPROVAL,
            event_type="action.requires_new_approval",
            outcome_code="authorization_expired",
            run_id=run_id,
            halt=True,
        )

    def _append_audit(
        self,
        event_type: str,
        *,
        intent: ExecutionIntent,
        run_id: str,
        outcome_code: str | None = None,
    ) -> None:
        self._audit.append(
            event_type=event_type,
            run_id=run_id,
            proposal_digest=intent.proposal_digest,
            approval_digest=intent.approval_digest,
            action_id=intent.action_id,
            idempotency_key=intent.idempotency_key,
            mailbox_ref=intent.mailbox_ref,
            target_ref=intent.target_ref,
            action_type=intent.action_type,
            outcome_code=outcome_code,
        )


def _prepare_selected(
    proposal: ActionProposal,
    approval: ApprovalArtifact,
    selected: tuple[ActionSpec, ...],
) -> tuple[_PreparedAction, ...]:
    """Construct every selected command before any provider-facing call.

    ``ActionProposal.digest`` re-serializes every line on each access, so the
    run-level digests are resolved once here and threaded through rather than
    recomputed per action.
    """
    proposal_digest = proposal.digest
    approval_digest = approval.digest
    prepared: list[_PreparedAction] = []
    for action in sorted(selected, key=lambda item: item.action_id):
        command = _command_for(
            proposal,
            approval,
            action,
            proposal_digest=proposal_digest,
            approval_digest=approval_digest,
        )
        prepared.append(
            _PreparedAction(
                action=action,
                command=command,
                intent=_intent_for(
                    proposal,
                    action,
                    command,
                    proposal_digest=proposal_digest,
                    approval_digest=approval_digest,
                ),
            )
        )
    return tuple(prepared)


def _command_for(
    proposal: ActionProposal,
    approval: ApprovalArtifact,
    action: ActionSpec,
    *,
    proposal_digest: str,
    approval_digest: str,
) -> ApprovedMailboxCommand:
    line_digest = action.line_digest
    idempotency_key = canonical_digest(
        {
            "proposal_digest": proposal_digest,
            "action_id": action.action_id,
            "line_digest": line_digest,
        }
    )
    return ApprovedMailboxCommand(
        action_id=action.action_id,
        proposal_digest=proposal_digest,
        approval_digest=approval_digest,
        line_digest=line_digest,
        approval_id=approval.approval_id,
        mailbox_ref=proposal.mailbox_ref,
        target=action.target.item_ref,
        expected_state_fingerprint=action.target.before_state_digest,
        action=action.action,
        idempotency_key=idempotency_key,
    )


def _intent_for(
    proposal: ActionProposal,
    action: ActionSpec,
    command: ApprovedMailboxCommand,
    *,
    proposal_digest: str,
    approval_digest: str,
) -> ExecutionIntent:
    return ExecutionIntent(
        idempotency_key=command.idempotency_key,
        proposal_digest=proposal_digest,
        approval_digest=approval_digest,
        action_id=action.action_id,
        mailbox_ref=proposal.mailbox_ref,
        target_ref=action.target.target_ref,
        action_type=action.action_type.value,
    )


def _result_ref_is_valid(
    command: ApprovedMailboxCommand,
    result: WriteResult,
) -> bool:
    resulting = result.new_ref
    if resulting is None or resulting.profile != command.target.profile:
        return False
    if isinstance(command.action, MoveMessage):
        return (
            resulting.provider_id == command.target.provider_id
            and resulting.folder_id == command.action.destination.folder_id
        )
    return (
        resulting.provider_id == command.target.provider_id
        and resulting.folder_id == command.target.folder_id
    )


def _current_proves_desired(
    command: ApprovedMailboxCommand,
    current: CurrentItemState,
) -> bool:
    """Validate that reconciliation proved the exact command postcondition."""
    if (
        current.ref.profile != command.target.profile
        or current.ref.provider_id != command.target.provider_id
    ):
        return False
    action = command.action
    if isinstance(action, MoveMessage):
        return current.ref.folder_id == action.destination.folder_id
    if current.ref.folder_id != command.target.folder_id:
        return False

    desired_state_matches = False
    if isinstance(action, SetReadState):
        desired_state_matches = current.is_read is action.is_read
    elif isinstance(action, SetCategory):
        category_present = any(
            value.casefold() == action.category.casefold()
            for value in current.categories
        )
        desired_state_matches = category_present is action.present
    return desired_state_matches


def _provider_code(result: WriteResult) -> str:
    if result.error_code is None:
        raise ExecutionStateError("provider result is missing a required error code")
    return result.error_code.value


def _reconciliation_code(
    reconciliation: Reconciliation,
    *,
    default: str,
) -> str:
    if reconciliation.error_code is None:
        return default
    return reconciliation.error_code.value


def _terminal_replay_result(
    stored: StoredExecution,
) -> tuple[ActionExecutionResult, bool] | None:
    if stored.status in {
        DurableActionStatus.SUCCEEDED,
        DurableActionStatus.RECONCILED_SUCCEEDED,
    }:
        return (
            ActionExecutionResult(
                action_id=stored.intent.action_id,
                status=ActionExecutionStatus.ALREADY_SUCCEEDED,
                outcome_code=stored.outcome_code or "already_applied",
            ),
            False,
        )
    if stored.status is DurableActionStatus.DEFINITE_FAILURE:
        return (
            ActionExecutionResult(
                action_id=stored.intent.action_id,
                status=ActionExecutionStatus.DEFINITE_FAILURE,
                outcome_code=stored.outcome_code or "definite_failure",
            ),
            True,
        )
    if stored.status is DurableActionStatus.REQUIRES_NEW_APPROVAL:
        return (
            ActionExecutionResult(
                action_id=stored.intent.action_id,
                status=ActionExecutionStatus.REQUIRES_NEW_APPROVAL,
                outcome_code=stored.outcome_code or "requires_new_approval",
            ),
            True,
        )
    return None


def _authorization_expired_result(
    action_id: str,
) -> tuple[ActionExecutionResult, bool]:
    return (
        ActionExecutionResult(
            action_id=action_id,
            status=ActionExecutionStatus.REQUIRES_NEW_APPROVAL,
            outcome_code="authorization_expired",
        ),
        True,
    )


def _not_started_result(action_id: str) -> tuple[ActionExecutionResult, bool]:
    return (
        ActionExecutionResult(
            action_id=action_id,
            status=ActionExecutionStatus.NOT_STARTED,
            outcome_code="no_durable_intent",
        ),
        True,
    )


def _requires_reconciliation(status: DurableActionStatus) -> bool:
    return status in {
        DurableActionStatus.INTENT_RECORDED,
        DurableActionStatus.DISPATCHED,
        DurableActionStatus.INDETERMINATE,
    }


def _recovery_actions_requiring_writer(
    durable: tuple[tuple[_PreparedAction, StoredExecution | None], ...],
) -> tuple[ActionSpec, ...]:
    selected: list[ActionSpec] = []
    for item, stored in durable:
        if stored is None:
            break
        if _requires_reconciliation(stored.status):
            selected.append(item.action)
    return tuple(selected)


def _require_matching_audit_identity(
    audited: AuditedActionState,
    intent: ExecutionIntent,
    *,
    run_id: str,
) -> None:
    observed = (
        audited.run_id,
        audited.proposal_digest,
        audited.approval_digest,
        audited.action_id,
        audited.idempotency_key,
        audited.mailbox_ref,
        audited.target_ref,
        audited.action_type,
    )
    expected = (
        run_id,
        intent.proposal_digest,
        intent.approval_digest,
        intent.action_id,
        intent.idempotency_key,
        intent.mailbox_ref,
        intent.target_ref,
        intent.action_type,
    )
    if observed != expected:
        raise ExecutionStateError("durable state and audit identity disagree")


def _is_started_audit(audited: AuditedActionState) -> bool:
    return audited.event_type == "action.started" and audited.outcome_code is None


def _is_legal_audit_predecessor(
    audited: AuditedActionState,
    predecessors: frozenset[str],
) -> bool:
    if audited.event_type not in predecessors:
        return False
    if audited.event_type == "action.started":
        return audited.outcome_code is None
    return audited.outcome_code is not None


def _terminal_audit_projection(
    durable_status: DurableActionStatus,
) -> tuple[str, frozenset[str]] | None:
    projections = {
        DurableActionStatus.SUCCEEDED: (
            "action.succeeded",
            frozenset({"action.started"}),
        ),
        DurableActionStatus.DEFINITE_FAILURE: (
            "action.failed",
            frozenset({"action.started"}),
        ),
        DurableActionStatus.INDETERMINATE: (
            "action.indeterminate",
            frozenset({"action.started", "action.indeterminate"}),
        ),
        DurableActionStatus.RECONCILED_SUCCEEDED: (
            "action.reconciled_succeeded",
            frozenset({"action.started", "action.indeterminate"}),
        ),
        DurableActionStatus.REQUIRES_NEW_APPROVAL: (
            "action.requires_new_approval",
            frozenset({"action.started", "action.indeterminate"}),
        ),
    }
    return projections.get(durable_status)


def _require_reconcilable_audit(
    audit_state: str | None,
    durable_status: DurableActionStatus,
) -> None:
    allowed_by_status: dict[DurableActionStatus, frozenset[str | None]] = {
        DurableActionStatus.INTENT_RECORDED: frozenset({"action.started"}),
        DurableActionStatus.DISPATCHED: frozenset({"action.started"}),
        DurableActionStatus.INDETERMINATE: frozenset({"action.indeterminate"}),
    }
    allowed = allowed_by_status.get(durable_status)
    if allowed is None or audit_state not in allowed:
        raise ExecutionStateError("durable state and audit recovery state disagree")


def _require_uuid(value: str, field_name: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ExecutionPreflightError(f"{field_name} must be a UUID") from exc
    if str(parsed) != value:
        raise ExecutionPreflightError(f"{field_name} must use canonical UUID text")
