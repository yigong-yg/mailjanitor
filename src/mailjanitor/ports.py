"""Narrow provider ports; no SDK object or generic operation crosses them."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from mailjanitor.canonical import canonical_digest
from mailjanitor.domain import (
    ActionType,
    ApprovedMailboxCommand,
    HeaderName,
    MailboxItemRef,
    MailboxProfileRef,
    MessageMetadata,
    ProviderKind,
    normalize_categories,
    validate_digest,
    validate_opaque_id,
)

MAX_PAGE_SIZE = 500


@dataclass(frozen=True, slots=True, kw_only=True)
class AdapterIdentity:
    """The exact local profile and provider account opened by an adapter."""

    profile: MailboxProfileRef
    account_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.profile, MailboxProfileRef):
            raise TypeError("profile must be a MailboxProfileRef")
        validate_digest("account_fingerprint", self.account_fingerprint)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReaderCapabilities:
    identity: AdapterIdentity
    strong_change_tokens: bool
    stable_item_ids: bool
    attachment_count_without_enumeration: bool = False
    supported_headers: frozenset[HeaderName] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.identity, AdapterIdentity):
            raise TypeError("identity must be an AdapterIdentity")
        for name in (
            "strong_change_tokens",
            "stable_item_ids",
            "attachment_count_without_enumeration",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")
        if type(self.supported_headers) is not frozenset or any(
            not isinstance(header, HeaderName) for header in self.supported_headers
        ):
            raise TypeError("supported_headers must be a frozenset of HeaderName")

    @property
    def provider(self) -> ProviderKind:
        return self.identity.profile.provider


@dataclass(frozen=True, slots=True, kw_only=True)
class WriterCapabilities:
    identity: AdapterIdentity
    supported_actions: frozenset[ActionType]
    strong_preconditions: bool

    def __post_init__(self) -> None:
        if not isinstance(self.identity, AdapterIdentity):
            raise TypeError("identity must be an AdapterIdentity")
        if type(self.supported_actions) is not frozenset or any(
            not isinstance(action, ActionType) for action in self.supported_actions
        ):
            raise TypeError("supported_actions must be a frozenset of ActionType")
        if type(self.strong_preconditions) is not bool:
            raise TypeError("strong_preconditions must be a bool")
        if not self.supported_actions:
            raise ValueError("writer must declare at least one typed action")

    @property
    def provider(self) -> ProviderKind:
        return self.identity.profile.provider


@dataclass(frozen=True, slots=True, kw_only=True)
class MetadataPageRequest:
    profile: MailboxProfileRef
    folder_ids: tuple[str, ...]
    page_size: int = 100
    cursor: str | None = None
    headers: tuple[HeaderName, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.profile, MailboxProfileRef):
            raise TypeError("profile must be a MailboxProfileRef")
        if type(self.folder_ids) is not tuple or not self.folder_ids:
            raise ValueError("folder_ids must be a non-empty tuple")
        folders = tuple(
            sorted(validate_opaque_id("folder_id", item) for item in self.folder_ids)
        )
        if len(set(folders)) != len(folders):
            raise ValueError("folder_ids must be unique")
        object.__setattr__(self, "folder_ids", folders)
        if type(self.page_size) is not int or not 1 <= self.page_size <= MAX_PAGE_SIZE:
            raise ValueError("page_size must be an int from 1 through 500")
        if self.cursor is not None:
            object.__setattr__(
                self,
                "cursor",
                validate_opaque_id("cursor", self.cursor),
            )
        if type(self.headers) is not tuple or any(
            not isinstance(header, HeaderName) for header in self.headers
        ):
            raise TypeError("headers must be a tuple of HeaderName")
        if len(set(self.headers)) != len(self.headers):
            raise ValueError("headers must be unique")
        object.__setattr__(
            self,
            "headers",
            tuple(sorted(self.headers, key=lambda header: header.value)),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class MetadataPage:
    profile: MailboxProfileRef
    items: tuple[MessageMetadata, ...]
    next_cursor: str | None = None
    rejected_record_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.profile, MailboxProfileRef):
            raise TypeError("profile must be a MailboxProfileRef")
        if type(self.items) is not tuple or any(
            not isinstance(item, MessageMetadata) for item in self.items
        ):
            raise TypeError("items must be a tuple of MessageMetadata")
        if any(item.ref.profile != self.profile for item in self.items):
            raise ValueError("page items must belong to the page profile")
        if type(self.rejected_record_count) is not int:
            raise TypeError("rejected_record_count must be an int")
        if self.rejected_record_count < 0:
            raise ValueError("rejected_record_count cannot be negative")
        if self.next_cursor is not None:
            object.__setattr__(
                self,
                "next_cursor",
                validate_opaque_id("next_cursor", self.next_cursor),
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class CurrentItemState:
    ref: MailboxItemRef
    is_read: bool
    categories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.ref, MailboxItemRef):
            raise TypeError("ref must be a MailboxItemRef")
        if type(self.is_read) is not bool:
            raise TypeError("is_read must be a bool")
        object.__setattr__(
            self,
            "categories",
            normalize_categories(self.categories),
        )

    @property
    def state_fingerprint(self) -> str:
        return canonical_digest(
            {
                "profile": {
                    "provider": self.ref.profile.provider.value,
                    "profile_id": self.ref.profile.profile_id,
                },
                "provider_id": self.ref.provider_id,
                "folder_id": self.ref.folder_id,
                "change_token": self.ref.change_token,
                "is_read": self.is_read,
                "categories": list(self.categories),
            }
        )

    @classmethod
    def from_metadata(cls, metadata: MessageMetadata) -> CurrentItemState:
        return cls(
            ref=metadata.ref,
            is_read=metadata.is_read,
            categories=metadata.categories,
        )


class ProviderErrorCode(StrEnum):
    AUTH_REQUIRED = "auth_required"
    PERMISSION_DENIED = "permission_denied"
    WRONG_ACCOUNT = "wrong_account"
    STALE_ITEM = "stale_item"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    UNSUPPORTED = "unsupported"
    INVALID_RESPONSE = "invalid_response"
    CONFLICT = "conflict"
    OUTCOME_UNKNOWN = "outcome_unknown"


class MailboxAdapterError(RuntimeError):
    """A normalized adapter failure that cannot echo provider content."""

    def __init__(self, code: ProviderErrorCode) -> None:
        if not isinstance(code, ProviderErrorCode):
            raise TypeError("code must be a ProviderErrorCode")
        self.code = code
        super().__init__(code.value)


class WriteStatus(StrEnum):
    SUCCEEDED = "succeeded"
    DEFINITE_FAILURE = "definite_failure"
    OUTCOME_UNKNOWN = "outcome_unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class WriteResult:
    status: WriteStatus
    new_ref: MailboxItemRef | None = None
    error_code: ProviderErrorCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, WriteStatus):
            raise TypeError("status must be a WriteStatus")
        if self.new_ref is not None and not isinstance(self.new_ref, MailboxItemRef):
            raise TypeError("new_ref must be a MailboxItemRef or None")
        if self.error_code is not None and not isinstance(
            self.error_code, ProviderErrorCode
        ):
            raise TypeError("error_code must be a ProviderErrorCode or None")
        if self.status is WriteStatus.SUCCEEDED and self.error_code is not None:
            raise ValueError("a successful result cannot have an error_code")
        if self.status is WriteStatus.SUCCEEDED and self.new_ref is None:
            raise ValueError("a successful result requires the resulting reference")
        if self.status is not WriteStatus.SUCCEEDED and self.error_code is None:
            raise ValueError("a non-success result requires an error_code")
        if self.status is not WriteStatus.SUCCEEDED and self.new_ref is not None:
            raise ValueError("a non-success result cannot assert a new reference")


class ReconciliationStatus(StrEnum):
    DESIRED_STATE_PRESENT = "desired_state_present"
    NOT_PRESENT = "not_present"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class Reconciliation:
    status: ReconciliationStatus
    current: CurrentItemState | None = None
    error_code: ProviderErrorCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ReconciliationStatus):
            raise TypeError("status must be a ReconciliationStatus")
        if self.current is not None and not isinstance(self.current, CurrentItemState):
            raise TypeError("current must be a CurrentItemState or None")
        if self.error_code is not None and not isinstance(
            self.error_code, ProviderErrorCode
        ):
            raise TypeError("error_code must be a ProviderErrorCode or None")
        _validate_reconciliation_shape(self.status, self.current, self.error_code)


def _validate_reconciliation_shape(
    status: ReconciliationStatus,
    current: CurrentItemState | None,
    error_code: ProviderErrorCode | None,
) -> None:
    if status is ReconciliationStatus.DESIRED_STATE_PRESENT:
        if current is None:
            raise ValueError("desired state present requires current state")
        if error_code is not None:
            raise ValueError("desired state present cannot contain an error")
    elif status is ReconciliationStatus.NOT_PRESENT:
        if current is not None and error_code is not None:
            raise ValueError("not present cannot contain state and an error")
        if current is None and error_code is None:
            raise ValueError("not present requires current state or an error")
    else:
        if current is not None:
            raise ValueError("unknown reconciliation cannot contain current state")
        if error_code is None:
            raise ValueError("unknown reconciliation requires an error")


@runtime_checkable
class MailboxReader(Protocol):
    def capabilities(self, profile: MailboxProfileRef) -> ReaderCapabilities: ...

    def read_page(self, request: MetadataPageRequest) -> MetadataPage: ...

    def read_current(self, ref: MailboxItemRef) -> CurrentItemState | None: ...


@runtime_checkable
class MailboxWriter(Protocol):
    def capabilities(self, profile: MailboxProfileRef) -> WriterCapabilities: ...

    def execute_one(self, command: ApprovedMailboxCommand) -> WriteResult: ...

    def reconcile(self, command: ApprovedMailboxCommand) -> Reconciliation: ...
