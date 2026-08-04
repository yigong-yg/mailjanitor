"""Explicit-subset, authenticated owner approval artifacts."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from mailjanitor.canonical import JsonValue, canonical_bytes, canonical_digest

if TYPE_CHECKING:
    from mailjanitor.workflow.proposal import ActionProposal, ActionSpec

_MINIMUM_KEY_BYTES = 32
_AUTH_TAG_PATTERN = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_ID_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_NONCE_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_MAILBOX_PATTERN = re.compile(r"mbx_[0-9a-f]{32,64}\Z")


class ApprovalValidationError(ValueError):
    """Raised when approval structure or proposal binding is invalid."""


class ApprovalAuthenticationError(ApprovalValidationError):
    """Raised when an approval authentication tag does not verify."""


class ApprovalExpiredError(ApprovalValidationError):
    """Raised when a proposal or approval is no longer fresh."""


@dataclass(frozen=True, slots=True)
class ApprovalArtifact:
    """A separately authenticated explicit subset of proposal action IDs."""

    approval_id: str
    approval_nonce: str
    proposal_id: str
    proposal_digest: str
    mailbox_ref: str
    approved_action_ids: tuple[str, ...]
    approved_at: datetime
    expires_at: datetime
    key_id: str
    auth_tag: str

    def __post_init__(self) -> None:
        _require_uuid(self.approval_id, "approval_id")
        _require_uuid(self.proposal_id, "proposal_id")
        if not _NONCE_PATTERN.fullmatch(self.approval_nonce):
            raise ApprovalValidationError("approval_nonce must contain 256 random bits")
        if not _DIGEST_PATTERN.fullmatch(self.proposal_digest):
            raise ApprovalValidationError("proposal_digest must be SHA-256")
        if not _MAILBOX_PATTERN.fullmatch(self.mailbox_ref):
            raise ApprovalValidationError("mailbox_ref must be a pseudonym")
        if type(self.approved_action_ids) is not tuple:
            raise ApprovalValidationError(
                "approved_action_ids must be an immutable tuple"
            )
        for action_id in self.approved_action_ids:
            _require_uuid(action_id, "approved action ID")
        if len(self.approved_action_ids) != len(set(self.approved_action_ids)):
            raise ApprovalValidationError("approved action IDs must be unique")
        object.__setattr__(
            self,
            "approved_action_ids",
            tuple(sorted(self.approved_action_ids)),
        )
        _require_aware(self.approved_at, "approved_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ApprovalValidationError("approval expiry must follow issuance")
        if not _KEY_ID_PATTERN.fullmatch(self.key_id):
            raise ApprovalValidationError("key_id must be a bounded machine code")
        if not _AUTH_TAG_PATTERN.fullmatch(self.auth_tag):
            raise ApprovalValidationError("auth_tag must be an HMAC-SHA-256 tag")

    def authentication_payload(self) -> dict[str, JsonValue]:
        """Return every authority-bearing field except the authentication tag."""
        approved_ids: list[JsonValue] = []
        approved_ids.extend(self.approved_action_ids)
        return {
            "schema_version": 1,
            "approval_id": self.approval_id,
            "approval_nonce": self.approval_nonce,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "mailbox_ref": self.mailbox_ref,
            "approved_action_ids": approved_ids,
            "approved_at": _format_utc(self.approved_at),
            "expires_at": _format_utc(self.expires_at),
            "approver": "owner-local",
            "auth_algorithm": "hmac-sha256",
            "key_id": self.key_id,
        }

    def as_dict(self) -> dict[str, JsonValue]:
        return {**self.authentication_payload(), "auth_tag": self.auth_tag}

    @property
    def digest(self) -> str:
        """Return a safe reference to the complete authenticated artifact."""
        return canonical_digest(self.as_dict())


class ApprovalService:
    """Issue and verify approval artifacts using an injected protected key."""

    def __init__(
        self,
        *,
        key: bytes,
        key_id: str,
        approval_id_factory: Callable[[], str] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        if len(key) < _MINIMUM_KEY_BYTES:
            raise ValueError(
                f"approval key must contain at least {_MINIMUM_KEY_BYTES} bytes"
            )
        if not _KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError("approval key ID must be a bounded machine code")
        self._key = bytes(key)
        self._key_id = key_id
        self._approval_id_factory = approval_id_factory or (lambda: str(uuid4()))
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))

    def issue(
        self,
        proposal: ActionProposal,
        approved_action_ids: Sequence[str],
        *,
        approved_at: datetime,
        expires_at: datetime,
    ) -> ApprovalArtifact:
        """Create an authenticated approval for an explicitly named subset."""
        if isinstance(approved_action_ids, (str, bytes)):
            raise TypeError("approved_action_ids must be an explicit sequence")
        approved = tuple(approved_action_ids)
        if len(approved) != len(set(approved)):
            raise ApprovalValidationError("approved action IDs must be unique")
        proposal_ids = {action.action_id for action in proposal.actions}
        unknown = set(approved).difference(proposal_ids)
        if unknown:
            raise ApprovalValidationError(
                "approval contains an action outside the proposal"
            )
        _validate_times(proposal, approved_at=approved_at, expires_at=expires_at)
        ordered = tuple(
            action.action_id
            for action in proposal.actions
            if action.action_id in approved
        )
        unsigned = ApprovalArtifact(
            approval_id=self._approval_id_factory(),
            approval_nonce=self._nonce_factory(),
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest,
            mailbox_ref=proposal.mailbox_ref,
            approved_action_ids=ordered,
            approved_at=approved_at,
            expires_at=expires_at,
            key_id=self._key_id,
            auth_tag=f"hmac-sha256:{'0' * 64}",
        )
        return ApprovalArtifact(
            approval_id=unsigned.approval_id,
            approval_nonce=unsigned.approval_nonce,
            proposal_id=unsigned.proposal_id,
            proposal_digest=unsigned.proposal_digest,
            mailbox_ref=unsigned.mailbox_ref,
            approved_action_ids=unsigned.approved_action_ids,
            approved_at=unsigned.approved_at,
            expires_at=unsigned.expires_at,
            key_id=unsigned.key_id,
            auth_tag=self._sign(unsigned.authentication_payload()),
        )

    def verify(
        self,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        *,
        now: datetime,
        expected_mailbox_ref: str,
    ) -> tuple[ActionSpec, ...]:
        """Verify authority and return only exact approved proposal lines."""
        selected = self._verify_bound_subset(
            proposal,
            approval,
            now=now,
            expected_mailbox_ref=expected_mailbox_ref,
        )
        if now >= approval.expires_at or now >= proposal.expires_at:
            raise ApprovalExpiredError("proposal or approval has expired")
        return selected

    def verify_for_recovery(
        self,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        *,
        now: datetime,
        expected_mailbox_ref: str,
    ) -> tuple[ActionSpec, ...]:
        """Authenticate an old approval for read-only durable-intent recovery.

        This deliberately ignores expiry.  It does not itself grant dispatch
        authority; the executor additionally requires an existing intent and
        the approval's original claimed run before invoking reconciliation.
        """
        return self._verify_bound_subset(
            proposal,
            approval,
            now=now,
            expected_mailbox_ref=expected_mailbox_ref,
        )

    def _verify_bound_subset(
        self,
        proposal: ActionProposal,
        approval: ApprovalArtifact,
        *,
        now: datetime,
        expected_mailbox_ref: str,
    ) -> tuple[ActionSpec, ...]:
        """Authenticate, bind, and canonically resolve one approved subset."""
        _require_aware(now, "now")
        expected_tag = self._sign(approval.authentication_payload())
        if not hmac.compare_digest(approval.auth_tag, expected_tag):
            raise ApprovalAuthenticationError("approval authentication failed")
        if approval.key_id != self._key_id:
            raise ApprovalAuthenticationError("approval key identifier is unknown")
        if approval.proposal_id != proposal.proposal_id:
            raise ApprovalValidationError("approval proposal ID mismatch")
        if not hmac.compare_digest(approval.proposal_digest, proposal.digest):
            raise ApprovalValidationError("approval proposal digest mismatch")
        if not hmac.compare_digest(approval.mailbox_ref, proposal.mailbox_ref):
            raise ApprovalValidationError("approval mailbox binding mismatch")
        if not hmac.compare_digest(approval.mailbox_ref, expected_mailbox_ref):
            raise ApprovalValidationError("execution mailbox binding mismatch")
        _validate_times(
            proposal,
            approved_at=approval.approved_at,
            expires_at=approval.expires_at,
        )
        if now < approval.approved_at:
            raise ApprovalValidationError("approval timestamp is in the future")
        actions_by_id = {action.action_id: action for action in proposal.actions}
        try:
            return tuple(
                actions_by_id[action_id] for action_id in approval.approved_action_ids
            )
        except KeyError as exc:
            raise ApprovalValidationError(
                "approval contains an action outside the proposal"
            ) from exc

    def _sign(self, payload: dict[str, JsonValue]) -> str:
        tag = hmac.new(self._key, canonical_bytes(payload), hashlib.sha256).hexdigest()
        return f"hmac-sha256:{tag}"


def _validate_times(
    proposal: ActionProposal,
    *,
    approved_at: datetime,
    expires_at: datetime,
) -> None:
    _require_aware(approved_at, "approved_at")
    _require_aware(expires_at, "expires_at")
    if approved_at < proposal.generated_at:
        raise ApprovalValidationError("approval predates its proposal")
    if expires_at <= approved_at:
        raise ApprovalValidationError("approval expiry must follow issuance")
    if expires_at > proposal.expires_at:
        raise ApprovalValidationError("approval outlives its proposal")


def _format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _require_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ApprovalValidationError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise ApprovalValidationError(f"{field_name} must be expressed in UTC")


def _require_uuid(value: str, field_name: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ApprovalValidationError(f"{field_name} must be a UUID") from exc
    if str(parsed) != value:
        raise ApprovalValidationError(f"{field_name} must use canonical UUID text")
