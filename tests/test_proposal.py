from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from mailjanitor.domain import (
    FolderRef,
    MailboxItemRef,
    MailboxProfileRef,
    MoveMessage,
    ProviderKind,
    SetCategory,
    SetReadState,
)
from mailjanitor.workflow.proposal import (
    ActionProposal,
    ActionSpec,
    ProposalValidationError,
    TargetSpec,
)

PROPOSAL_ID = "11111111-1111-4111-8111-111111111111"
ACTION_ID = "22222222-2222-4222-8222-222222222222"
MAILBOX_REF = f"mbx_{'1' * 32}"
TARGET_REF = f"msg_{'2' * 32}"
STATE_DIGEST = f"sha256:{'a' * 64}"
ACCOUNT_FINGERPRINT = f"sha256:{'c' * 64}"
NOW = datetime(2026, 8, 3, 18, 0, tzinfo=UTC)


def change_token(version: int) -> str:
    return f"synthetic-version-{version}"


def profile() -> MailboxProfileRef:
    return MailboxProfileRef(provider=ProviderKind.FAKE, profile_id="synthetic")


def target() -> TargetSpec:
    return TargetSpec(
        item_ref=MailboxItemRef(
            profile=profile(),
            provider_id="synthetic-message-1",
            folder_id="synthetic-inbox",
            change_token=change_token(1),
        ),
        before_state_digest=STATE_DIGEST,
        target_ref=TARGET_REF,
    )


def action() -> ActionSpec:
    return ActionSpec(
        action_id=ACTION_ID,
        target=target(),
        action=SetReadState(is_read=True),
        owner_summary="Synthetic message: set read state",
    )


def proposal(*actions: ActionSpec) -> ActionProposal:
    selected = actions or (action(),)
    return ActionProposal(
        proposal_id=PROPOSAL_ID,
        run_nonce="b" * 64,
        profile=profile(),
        account_fingerprint=ACCOUNT_FINGERPRINT,
        mailbox_ref=MAILBOX_REF,
        generated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        actions=tuple(selected),
    )


def test_proposal_digest_and_line_digest_are_deterministic() -> None:
    first = proposal()
    second = proposal()

    assert first.digest == second.digest
    assert first.actions[0].line_digest == second.actions[0].line_digest
    assert first.digest.startswith("sha256:")


def test_proposal_canonicalizes_action_order() -> None:
    first = action()
    second = replace(
        first,
        action_id="33333333-3333-4333-8333-333333333333",
        action=SetCategory(category="Synthetic", present=True),
    )

    forward = proposal(first, second)
    reverse = proposal(second, first)

    assert forward.digest == reverse.digest
    assert forward.actions == reverse.actions == (first, second)


def test_exact_target_and_action_changes_invalidate_digests() -> None:
    original = action()
    changed_target = replace(
        original,
        target=replace(
            original.target,
            item_ref=replace(
                original.target.item_ref,
                change_token=change_token(2),
            ),
        ),
    )
    changed_action = replace(original, action=SetReadState(is_read=False))

    assert changed_target.line_digest != original.line_digest
    assert changed_action.line_digest != original.line_digest
    assert proposal(changed_target).digest != proposal(original).digest


def test_artifacts_are_frozen_and_require_tuple_actions() -> None:
    item = action()
    with pytest.raises(FrozenInstanceError):
        item.owner_summary = "changed"  # type: ignore[misc]
    with pytest.raises(ProposalValidationError, match="immutable tuple"):
        replace(proposal(), actions=[item])  # type: ignore[arg-type]


def test_duplicate_action_ids_are_rejected() -> None:
    with pytest.raises(ProposalValidationError, match="must be unique"):
        proposal(action(), action())


def test_proposal_lifetime_is_bounded() -> None:
    with pytest.raises(ProposalValidationError, match="exceeds 24 hours"):
        replace(proposal(), expires_at=NOW + timedelta(hours=25))


@pytest.mark.parametrize(
    "bad_summary",
    ["mail\nsubject", "direction\u202eoverride", ""],
)
def test_owner_summary_rejects_terminal_and_bidi_controls(bad_summary: str) -> None:
    with pytest.raises(ProposalValidationError):
        replace(action(), owner_summary=bad_summary)


def test_closed_action_registry_rejects_arbitrary_objects() -> None:
    with pytest.raises(ProposalValidationError, match="closed registry"):
        replace(action(), action=object())  # type: ignore[arg-type]


def test_all_initial_action_types_are_exactly_serialized() -> None:
    move = replace(
        action(),
        action=MoveMessage(
            destination=FolderRef(
                profile=profile(),
                folder_id="synthetic-archive",
            )
        ),
    )
    category = replace(
        action(),
        action=SetCategory(category="Needs Review", present=False),
    )

    assert move.as_dict()["action"] == {
        "type": "move_message",
        "destination": {
            "provider": "fixture",
            "profile_id": "synthetic",
            "folder_id": "synthetic-archive",
        },
    }
    assert category.as_dict()["action"] == {
        "type": "remove_category",
        "category": "Needs Review",
    }


def test_cross_profile_move_is_rejected_at_proposal_line_construction() -> None:
    other_profile = MailboxProfileRef(
        provider=ProviderKind.FAKE,
        profile_id="synthetic-other",
    )

    with pytest.raises(ProposalValidationError, match="share a mailbox profile"):
        replace(
            action(),
            action=MoveMessage(
                destination=FolderRef(
                    profile=other_profile,
                    folder_id="synthetic-archive",
                )
            ),
        )
