"""Tests for SQLite approval, execution, locking, and audit-anchor state."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailjanitor.adapters.local.audit import AuditTail
from mailjanitor.adapters.local.state import (
    OperationalStateError,
    SqliteOperationalState,
)
from mailjanitor.workflow.execution import (
    ApprovalClaimStatus,
    DurableActionStatus,
    ExecutionIntent,
    StoredExecution,
)

DIGEST_A = f"sha256:{'a' * 64}"
DIGEST_B = f"sha256:{'b' * 64}"
MAILBOX_REF = f"mbx_{'1' * 32}"
TARGET_REF = f"msg_{'2' * 32}"
RUN_ID = "11111111-1111-4111-8111-111111111111"
OTHER_RUN_ID = "22222222-2222-4222-8222-222222222222"
ACTION_ID = "33333333-3333-4333-8333-333333333333"


def make_state(tmp_path: Path) -> SqliteOperationalState:
    return SqliteOperationalState(tmp_path / "state.sqlite3")


def make_intent() -> ExecutionIntent:
    return ExecutionIntent(
        idempotency_key=DIGEST_A,
        proposal_digest=DIGEST_A,
        approval_digest=DIGEST_B,
        action_id=ACTION_ID,
        mailbox_ref=MAILBOX_REF,
        target_ref=TARGET_REF,
        action_type="set_read_state",
    )


def test_approval_claim_is_atomic_and_recoverable_by_same_run(tmp_path: Path) -> None:
    state = make_state(tmp_path)

    assert (
        state.claim_approval(DIGEST_B, DIGEST_A, RUN_ID) is ApprovalClaimStatus.CLAIMED
    )
    assert (
        state.claim_approval(DIGEST_B, DIGEST_A, RUN_ID) is ApprovalClaimStatus.SAME_RUN
    )
    assert (
        state.claim_approval(DIGEST_B, DIGEST_A, OTHER_RUN_ID)
        is ApprovalClaimStatus.DIFFERENT_RUN
    )


def test_approval_claim_status_is_read_only(tmp_path: Path) -> None:
    state = make_state(tmp_path)

    assert state.approval_claim_status(DIGEST_B, DIGEST_A, RUN_ID) is None
    assert (
        state.claim_approval(DIGEST_B, DIGEST_A, RUN_ID) is ApprovalClaimStatus.CLAIMED
    )
    assert (
        state.approval_claim_status(DIGEST_B, DIGEST_A, RUN_ID)
        is ApprovalClaimStatus.SAME_RUN
    )
    assert (
        state.approval_claim_status(DIGEST_B, DIGEST_A, OTHER_RUN_ID)
        is ApprovalClaimStatus.DIFFERENT_RUN
    )
    assert (
        state.approval_claim_status(DIGEST_B, DIGEST_B, RUN_ID)
        is ApprovalClaimStatus.DIFFERENT_RUN
    )


def test_intent_round_trip_and_duplicate_claim(tmp_path: Path) -> None:
    state = make_state(tmp_path)
    intent = make_intent()

    assert state.get(intent.idempotency_key) is None
    assert state.record_intent(intent) is True
    assert state.record_intent(intent) is False
    assert state.get(intent.idempotency_key) == StoredExecution(
        intent=intent,
        status=DurableActionStatus.INTENT_RECORDED,
    )


def test_execution_state_transitions_are_guarded(tmp_path: Path) -> None:
    state = make_state(tmp_path)
    intent = make_intent()
    state.record_intent(intent)

    state.mark_dispatched(intent.idempotency_key)
    state.record_terminal(
        intent.idempotency_key,
        DurableActionStatus.SUCCEEDED,
        "applied",
    )

    assert state.get(intent.idempotency_key) == StoredExecution(
        intent=intent,
        status=DurableActionStatus.SUCCEEDED,
        outcome_code="applied",
    )
    with pytest.raises(OperationalStateError, match="transition"):
        state.record_terminal(
            intent.idempotency_key,
            DurableActionStatus.INDETERMINATE,
            "late_change",
        )


def test_reconciliation_can_close_a_dispatched_intent(tmp_path: Path) -> None:
    state = make_state(tmp_path)
    intent = make_intent()
    state.record_intent(intent)
    state.mark_dispatched(intent.idempotency_key)

    state.record_terminal(
        intent.idempotency_key,
        DurableActionStatus.RECONCILED_SUCCEEDED,
        "desired_state_present",
    )

    stored = state.get(intent.idempotency_key)
    assert stored is not None
    assert stored.status is DurableActionStatus.RECONCILED_SUCCEEDED


def test_mark_dispatched_requires_existing_fresh_intent(tmp_path: Path) -> None:
    state = make_state(tmp_path)

    with pytest.raises(OperationalStateError, match="dispatched"):
        state.mark_dispatched(DIGEST_A)


def test_terminal_transition_requires_existing_intent(tmp_path: Path) -> None:
    state = make_state(tmp_path)

    with pytest.raises(OperationalStateError, match="does not exist"):
        state.record_terminal(
            DIGEST_A,
            DurableActionStatus.SUCCEEDED,
            "applied",
        )


def test_profile_lock_rejects_concurrent_holder(tmp_path: Path) -> None:
    state = make_state(tmp_path)

    with (
        state.profile_lock(MAILBOX_REF),
        pytest.raises(OperationalStateError, match="already locked"),
        state.profile_lock(MAILBOX_REF),
    ):
        pytest.fail("second lock must not be acquired")


def test_audit_anchor_advances_exactly_once(tmp_path: Path) -> None:
    state = make_state(tmp_path)
    genesis = AuditTail(0, "0" * 64)
    first = AuditTail(1, "a" * 64)

    assert state.load("action-log") is None
    state.store("action-log", genesis)
    state.store("action-log", first)

    assert state.load("action-log") == first
    with pytest.raises(OperationalStateError, match="advance by one"):
        state.store("action-log", AuditTail(3, "c" * 64))


def test_first_audit_anchor_must_start_at_genesis(tmp_path: Path) -> None:
    state = make_state(tmp_path)

    with pytest.raises(OperationalStateError, match="sequence zero"):
        state.store("action-log", AuditTail(1, "a" * 64))


def test_invalid_sensitive_values_do_not_enter_state(tmp_path: Path) -> None:
    state = make_state(tmp_path)
    intent = make_intent()
    invalid = ExecutionIntent(
        idempotency_key=intent.idempotency_key,
        proposal_digest=intent.proposal_digest,
        approval_digest=intent.approval_digest,
        action_id=intent.action_id,
        mailbox_ref="owner@example.invalid",
        target_ref=intent.target_ref,
        action_type=intent.action_type,
    )

    with pytest.raises(ValueError, match="mailbox_ref"):
        state.record_intent(invalid)


def test_dangling_state_symlink_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    try:
        path.symlink_to(tmp_path / "missing-target.sqlite3")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(OperationalStateError, match="regular file"):
        SqliteOperationalState(path)
