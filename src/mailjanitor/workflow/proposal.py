"""Immutable, exact-target action proposals."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from mailjanitor.canonical import JsonValue, canonical_digest
from mailjanitor.domain import (
    ActionType,
    MailboxAction,
    MailboxItemRef,
    MailboxProfileRef,
    MoveMessage,
    SetCategory,
    SetReadState,
)

MAX_PROPOSAL_LIFETIME = timedelta(hours=24)
_MAX_SUMMARY_LENGTH = 512
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NONCE_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_PSEUDONYM_PATTERN = re.compile(r"(?:msg|fld|obj)_[0-9a-f]{32,64}\Z")
_MAILBOX_PATTERN = re.compile(r"mbx_[0-9a-f]{32,64}\Z")


class ProposalValidationError(ValueError):
    """Raised when a proposal is not exact, bounded, or internally coherent."""


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """Exact sensitive provider locator plus redacted audit correlation value."""

    item_ref: MailboxItemRef
    before_state_digest: str
    target_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.item_ref, MailboxItemRef):
            raise ProposalValidationError("item_ref must be a MailboxItemRef")
        _require_digest(self.before_state_digest, "before_state_digest")
        if not _PSEUDONYM_PATTERN.fullmatch(self.target_ref):
            raise ProposalValidationError(
                "target_ref must be an HMAC-derived pseudonym"
            )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "provider": self.item_ref.profile.provider.value,
            "profile_id": self.item_ref.profile.profile_id,
            "provider_id": self.item_ref.provider_id,
            "folder_id": self.item_ref.folder_id,
            "change_token": self.item_ref.change_token,
            "before_state_digest": self.before_state_digest,
            "target_ref": self.target_ref,
        }


@dataclass(frozen=True, slots=True)
class ActionSpec:
    """One immutable proposal line with no selector or expansion semantics."""

    action_id: str
    target: TargetSpec
    action: MailboxAction
    owner_summary: str

    def __post_init__(self) -> None:
        _require_uuid(self.action_id, "action_id")
        if not isinstance(self.target, TargetSpec):
            raise ProposalValidationError("target must be a TargetSpec")
        if not isinstance(self.action, MoveMessage | SetReadState | SetCategory):
            raise ProposalValidationError("action type is not in the closed registry")
        if (
            isinstance(self.action, MoveMessage)
            and self.action.destination.profile != self.target.item_ref.profile
        ):
            raise ProposalValidationError(
                "move destination and target must share a mailbox profile"
            )
        _require_display_text(
            self.owner_summary,
            "owner_summary",
            maximum_length=_MAX_SUMMARY_LENGTH,
        )

    @property
    def action_type(self) -> ActionType:
        """Return the closed action discriminator."""
        if isinstance(self.action, MoveMessage):
            return ActionType.MOVE_MESSAGE
        if isinstance(self.action, SetReadState):
            return ActionType.SET_READ_STATE
        return (
            ActionType.ADD_CATEGORY
            if self.action.present
            else ActionType.REMOVE_CATEGORY
        )

    def unsigned_dict(self) -> dict[str, JsonValue]:
        """Return the exact line content covered by its digest."""
        return {
            "action_id": self.action_id,
            "target": self.target.as_dict(),
            "action": _action_dict(self.action),
            "owner_summary": self.owner_summary,
        }

    @property
    def line_digest(self) -> str:
        """Digest the exact target, action, precondition, and review display."""
        return canonical_digest(self.unsigned_dict())

    def as_dict(self) -> dict[str, JsonValue]:
        return {**self.unsigned_dict(), "line_digest": self.line_digest}


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """A canonical, immutable proposal bound to one adapter profile."""

    proposal_id: str
    run_nonce: str
    profile: MailboxProfileRef
    account_fingerprint: str
    mailbox_ref: str
    generated_at: datetime
    expires_at: datetime
    actions: tuple[ActionSpec, ...]

    def __post_init__(self) -> None:
        _require_uuid(self.proposal_id, "proposal_id")
        if not _NONCE_PATTERN.fullmatch(self.run_nonce):
            raise ProposalValidationError("run_nonce must contain 256 random bits")
        if not isinstance(self.profile, MailboxProfileRef):
            raise ProposalValidationError("profile must be a MailboxProfileRef")
        _require_digest(self.account_fingerprint, "account_fingerprint")
        if not _MAILBOX_PATTERN.fullmatch(self.mailbox_ref):
            raise ProposalValidationError(
                "mailbox_ref must be an HMAC-derived pseudonym"
            )
        generated = _require_utc(self.generated_at, "generated_at")
        expires = _require_utc(self.expires_at, "expires_at")
        if expires <= generated:
            raise ProposalValidationError("proposal expiry must follow generation")
        if expires - generated > MAX_PROPOSAL_LIFETIME:
            raise ProposalValidationError("proposal lifetime exceeds 24 hours")
        if type(self.actions) is not tuple:
            raise ProposalValidationError("actions must be an immutable tuple")
        if any(not isinstance(action, ActionSpec) for action in self.actions):
            raise ProposalValidationError("actions must contain only ActionSpec values")
        canonical_actions = tuple(
            sorted(self.actions, key=lambda action: action.action_id)
        )
        object.__setattr__(self, "actions", canonical_actions)
        action_ids = [action.action_id for action in canonical_actions]
        if len(action_ids) != len(set(action_ids)):
            raise ProposalValidationError("proposal action identifiers must be unique")
        if any(
            action.target.item_ref.profile != self.profile
            for action in canonical_actions
        ):
            raise ProposalValidationError(
                "proposal cannot contain a cross-adapter or cross-profile target"
            )

    def as_dict(self) -> dict[str, JsonValue]:
        """Return canonical proposal content in stable action order."""
        return {
            "schema_version": 1,
            "proposal_id": self.proposal_id,
            "run_nonce": self.run_nonce,
            "profile": {
                "provider": self.profile.provider.value,
                "profile_id": self.profile.profile_id,
            },
            "account_fingerprint": self.account_fingerprint,
            "mailbox_ref": self.mailbox_ref,
            "generated_at": _format_utc(self.generated_at),
            "expires_at": _format_utc(self.expires_at),
            "actions": [action.as_dict() for action in self.actions],
        }

    @property
    def digest(self) -> str:
        """Return the immutable full-proposal content digest."""
        return canonical_digest(self.as_dict())

    def action_by_id(self, action_id: str) -> ActionSpec | None:
        """Resolve only an exact action identifier; selectors are unsupported."""
        return next(
            (action for action in self.actions if action.action_id == action_id),
            None,
        )


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ProposalValidationError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise ProposalValidationError(f"{field_name} must be expressed in UTC")
    return value


def _require_uuid(value: str, field_name: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ProposalValidationError(f"{field_name} must be a UUID") from exc
    if str(parsed) != value:
        raise ProposalValidationError(f"{field_name} must use canonical UUID text")


def _require_digest(value: str, field_name: str) -> None:
    if not _DIGEST_PATTERN.fullmatch(value):
        raise ProposalValidationError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )


def _require_display_text(value: str, field_name: str, *, maximum_length: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ProposalValidationError(f"{field_name} must be non-empty text")
    if len(value) > maximum_length:
        raise ProposalValidationError(f"{field_name} exceeds the maximum length")
    _reject_controls(value, field_name)


def _reject_controls(value: str, field_name: str) -> None:
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        raise ProposalValidationError(f"{field_name} contains control characters")


def _action_dict(action: MailboxAction) -> dict[str, JsonValue]:
    if isinstance(action, MoveMessage):
        return {
            "type": ActionType.MOVE_MESSAGE.value,
            "destination": {
                "provider": action.destination.profile.provider.value,
                "profile_id": action.destination.profile.profile_id,
                "folder_id": action.destination.folder_id,
            },
        }
    if isinstance(action, SetReadState):
        return {
            "type": ActionType.SET_READ_STATE.value,
            "is_read": action.is_read,
        }
    if isinstance(action, SetCategory):
        action_type = (
            ActionType.ADD_CATEGORY if action.present else ActionType.REMOVE_CATEGORY
        )
        return {
            "type": action_type.value,
            "category": action.category,
        }
    raise ProposalValidationError("action type is not in the closed registry")
