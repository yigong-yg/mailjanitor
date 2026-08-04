from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from mailjanitor.domain import (
    MailboxItemRef,
    MailboxProfileRef,
    ProviderKind,
    SetReadState,
)
from mailjanitor.workflow.approval import (
    ApprovalArtifact,
    ApprovalAuthenticationError,
    ApprovalExpiredError,
    ApprovalService,
    ApprovalValidationError,
)
from mailjanitor.workflow.proposal import (
    ActionProposal,
    ActionSpec,
    TargetSpec,
)

KEY = b"approval-key-is-at-least-thirty-two-bytes"
NOW = datetime(2026, 8, 3, 18, 0, tzinfo=UTC)
PROPOSAL_ID = "11111111-1111-4111-8111-111111111111"
ACTION_ID = "22222222-2222-4222-8222-222222222222"
APPROVAL_ID = "33333333-3333-4333-8333-333333333333"
MAILBOX_REF = f"mbx_{'1' * 32}"
ACCOUNT_FINGERPRINT = f"sha256:{'d' * 64}"


def change_token(version: int) -> str:
    return f"synthetic-version-{version}"


def profile() -> MailboxProfileRef:
    return MailboxProfileRef(provider=ProviderKind.FIXTURE, profile_id="synthetic")


def make_proposal() -> ActionProposal:
    return ActionProposal(
        proposal_id=PROPOSAL_ID,
        run_nonce="a" * 64,
        profile=profile(),
        account_fingerprint=ACCOUNT_FINGERPRINT,
        mailbox_ref=MAILBOX_REF,
        generated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        actions=(
            ActionSpec(
                action_id=ACTION_ID,
                target=TargetSpec(
                    item_ref=MailboxItemRef(
                        profile=profile(),
                        provider_id="synthetic-message",
                        folder_id="synthetic-inbox",
                        change_token=change_token(1),
                    ),
                    before_state_digest=f"sha256:{'b' * 64}",
                    target_ref=f"msg_{'2' * 32}",
                ),
                action=SetReadState(is_read=True),
                owner_summary="Synthetic message: set read state",
            ),
        ),
    )


def service(key: bytes = KEY) -> ApprovalService:
    return ApprovalService(
        key=key,
        key_id="owner-key-v1",
        approval_id_factory=lambda: APPROVAL_ID,
        nonce_factory=lambda: "c" * 64,
    )


def issue() -> tuple[ActionProposal, ApprovalArtifact]:
    proposal = make_proposal()
    approval = service().issue(
        proposal,
        [ACTION_ID],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )
    return proposal, approval


def test_explicit_subset_is_authenticated_and_verifiable() -> None:
    proposal = make_proposal()
    approval = service().issue(
        proposal,
        [ACTION_ID],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )

    selected = service().verify(
        proposal,
        approval,
        now=NOW + timedelta(minutes=2),
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert [item.action_id for item in selected] == [ACTION_ID]
    assert approval.digest.startswith("sha256:")
    assert approval.auth_tag.startswith("hmac-sha256:")


def test_approved_subset_order_is_canonical_and_not_malleable() -> None:
    first = make_proposal().actions[0]
    second = replace(
        first,
        action_id="44444444-4444-4444-8444-444444444444",
        target=replace(first.target, target_ref=f"msg_{'4' * 32}"),
    )
    proposal = replace(make_proposal(), actions=(second, first))
    approval = service().issue(
        proposal,
        [second.action_id, first.action_id],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )

    reordered = replace(
        approval,
        approved_action_ids=tuple(reversed(approval.approved_action_ids)),
    )
    selected = service().verify(
        proposal,
        reordered,
        now=NOW + timedelta(minutes=2),
        expected_mailbox_ref=MAILBOX_REF,
    )

    expected_ids = tuple(sorted((first.action_id, second.action_id)))
    assert approval.approved_action_ids == expected_ids
    assert reordered.approved_action_ids == expected_ids
    assert reordered.auth_tag == approval.auth_tag
    assert reordered.digest == approval.digest
    assert tuple(action.action_id for action in selected) == expected_ids


def test_empty_explicit_subset_is_a_valid_no_op() -> None:
    proposal = make_proposal()
    approval = service().issue(
        proposal,
        [],
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )

    assert (
        service().verify(
            proposal,
            approval,
            now=NOW + timedelta(minutes=2),
            expected_mailbox_ref=MAILBOX_REF,
        )
        == ()
    )


def test_unknown_or_duplicate_action_cannot_be_approved() -> None:
    proposal = make_proposal()
    with pytest.raises(ApprovalValidationError, match="outside the proposal"):
        service().issue(
            proposal,
            ["44444444-4444-4444-8444-444444444444"],
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(ApprovalValidationError, match="must be unique"):
        service().issue(
            proposal,
            [ACTION_ID, ACTION_ID],
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )


def test_tampered_approval_fails_authentication() -> None:
    proposal = make_proposal()
    approval = service().issue(
        proposal,
        [ACTION_ID],
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    tampered = replace(approval, mailbox_ref=f"mbx_{'9' * 32}")

    with pytest.raises(ApprovalAuthenticationError):
        service().verify(
            proposal,
            tampered,
            now=NOW + timedelta(minutes=1),
            expected_mailbox_ref=MAILBOX_REF,
        )


def test_proposal_edit_invalidates_approval_binding() -> None:
    proposal = make_proposal()
    approval = service().issue(
        proposal,
        [ACTION_ID],
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    changed = replace(
        proposal,
        actions=(
            replace(
                proposal.actions[0],
                owner_summary="Changed synthetic review display",
            ),
        ),
    )

    with pytest.raises(ApprovalValidationError, match="digest mismatch"):
        service().verify(
            changed,
            approval,
            now=NOW + timedelta(minutes=1),
            expected_mailbox_ref=MAILBOX_REF,
        )


def test_cross_mailbox_and_expired_approvals_fail_closed() -> None:
    proposal = make_proposal()
    approval = service().issue(
        proposal,
        [ACTION_ID],
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    with pytest.raises(ApprovalValidationError, match="execution mailbox"):
        service().verify(
            proposal,
            approval,
            now=NOW + timedelta(minutes=1),
            expected_mailbox_ref=f"mbx_{'9' * 32}",
        )
    with pytest.raises(ApprovalExpiredError):
        service().verify(
            proposal,
            approval,
            now=NOW + timedelta(minutes=30),
            expected_mailbox_ref=MAILBOX_REF,
        )


def test_expired_approval_can_be_authenticated_for_recovery_only() -> None:
    proposal, approval = issue()

    selected = service().verify_for_recovery(
        proposal,
        approval,
        now=NOW + timedelta(hours=2),
        expected_mailbox_ref=MAILBOX_REF,
    )

    assert tuple(action.action_id for action in selected) == (ACTION_ID,)


def test_short_key_and_approval_outliving_proposal_are_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        service(b"short")
    with pytest.raises(ApprovalValidationError, match="outlives"):
        service().issue(
            make_proposal(),
            [ACTION_ID],
            approved_at=NOW,
            expires_at=NOW + timedelta(hours=2),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("approval_id", "not-a-uuid"),
        ("proposal_id", "not-a-uuid"),
        ("approval_nonce", "z" * 64),
        ("proposal_digest", "sha256:short"),
        ("mailbox_ref", "owner@example.invalid"),
        ("approved_action_ids", [ACTION_ID]),
        ("approved_action_ids", (ACTION_ID, ACTION_ID)),
        ("key_id", "UPPER"),
        ("auth_tag", "hmac-sha256:xyz"),
    ],
)
def test_malformed_approval_fields_fail_closed(field: str, value: object) -> None:
    _, approval = issue()

    with pytest.raises(ApprovalValidationError):
        replace(approval, **cast("Any", {field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("approved_at", NOW.replace(tzinfo=None)),
        ("expires_at", NOW - timedelta(minutes=1)),
    ],
)
def test_approval_timestamps_must_be_aware_and_ordered(
    field: str, value: object
) -> None:
    _, approval = issue()

    with pytest.raises(ApprovalValidationError):
        replace(approval, **cast("Any", {field: value}))


def test_same_key_under_a_different_key_id_does_not_verify() -> None:
    plan, approval = issue()
    other = ApprovalService(key=KEY, key_id="rotated")

    with pytest.raises(ApprovalAuthenticationError, match="key identifier"):
        other.verify(
            plan,
            approval,
            now=NOW,
            expected_mailbox_ref=MAILBOX_REF,
        )


def test_approval_dated_after_the_verification_clock_is_refused() -> None:
    plan, approval = issue()

    with pytest.raises(ApprovalValidationError, match="future"):
        service().verify(
            plan,
            approval,
            now=NOW - timedelta(minutes=1),
            expected_mailbox_ref=MAILBOX_REF,
        )
