"""Immutable, provider-neutral domain values for metadata-only triage."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from mailjanitor.canonical import JsonValue, canonical_bytes, canonical_digest

SCHEMA_VERSION = 1
MAX_OPAQUE_ID_LENGTH = 2048
MAX_ADDRESS_LENGTH = 320
MAX_DISPLAY_NAME_LENGTH = 256
MAX_SUBJECT_LENGTH = 998
MAX_CATEGORY_LENGTH = 128
MAX_CATEGORIES = 64
MAX_HEADER_VALUE_LENGTH = 8192
MAX_HEADERS = 8
# Cardinality limits keep the canonical node count bounded.  The aggregate
# canonical byte check in ``MailboxSnapshot`` additionally rejects unusually
# large Unicode metadata before the value can cross a core boundary.
MAX_MESSAGES_PER_SNAPSHOT = 500
MAX_FOLDERS_PER_SNAPSHOT = 256
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_ATTACHMENT_COUNT = 10_000
MAX_DOMAIN_LENGTH = 253
MAX_DOMAIN_LABEL_LENGTH = 63
MIN_DOMAIN_LABELS = 2

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FORBIDDEN_BIDI = frozenset(
    {
        "LRE",
        "RLE",
        "LRO",
        "RLO",
        "PDF",
        "LRI",
        "RLI",
        "FSI",
        "PDI",
    }
)


def _require_exact_bool(name: str, value: object) -> None:
    if type(value) is not bool:
        raise TypeError(f"{name} must be a bool")


def _bounded_text(
    name: str,
    value: object,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized and not allow_empty:
        raise ValueError(f"{name} must not be empty")
    if len(normalized) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    for character in normalized:
        category = unicodedata.category(character)
        if (
            category in {"Cc", "Cs"}
            or unicodedata.bidirectional(character) in _FORBIDDEN_BIDI
        ):
            raise ValueError(f"{name} contains a forbidden control character")
    return normalized


def _opaque_id(name: str, value: object) -> str:
    text = _bounded_text(name, value, maximum=MAX_OPAQUE_ID_LENGTH)
    if text != text.strip():
        raise ValueError(f"{name} must not have surrounding whitespace")
    if any(marker in text for marker in ("*", "?", "[", "]", "$", "&")):
        raise ValueError(f"{name} must identify one exact resource")
    return text


def _safe_token(name: str, value: object) -> str:
    text = _bounded_text(name, value, maximum=128)
    if _SAFE_TOKEN_RE.fullmatch(text) is None:
        raise ValueError(f"{name} is not a valid opaque token")
    return text


def _aware_utc(name: str, value: object) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def normalize_domain(value: str) -> str:
    """Return a lowercase ASCII domain, rejecting ambiguous input."""

    if type(value) is str and any(
        unicodedata.category(character) == "Cf" for character in value
    ):
        raise ValueError("domain contains a forbidden Unicode format character")
    text = (
        _bounded_text("domain", value, maximum=MAX_DOMAIN_LENGTH)
        .removesuffix(".")
        .lower()
    )
    try:
        domain = text.encode("idna").decode("ascii")
        decoded = domain.encode("ascii").decode("idna")
        reencoded = decoded.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("domain is not valid IDNA") from error
    if reencoded != domain or (
        not text.isascii() and unicodedata.normalize("NFC", decoded) != text
    ):
        raise ValueError("domain changes under IDNA round-trip normalization")
    labels = domain.split(".")
    if len(domain) > MAX_DOMAIN_LENGTH or len(labels) < MIN_DOMAIN_LABELS:
        raise ValueError("domain must be a bounded fully qualified name")
    if any(
        not label
        or len(label) > MAX_DOMAIN_LABEL_LENGTH
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise ValueError("domain contains an invalid label")
    return domain


def validate_opaque_id(name: str, value: object) -> str:
    """Validate one exact provider identifier without selector semantics."""
    return _opaque_id(name, value)


def normalize_categories(values: object) -> tuple[str, ...]:
    """Validate and deterministically order category state."""
    return _categories(values)


def validate_digest(name: str, value: object) -> str:
    """Validate an algorithm-labelled SHA-256 digest."""
    return _require_digest(name, value)


def _categories(values: object) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise TypeError("categories must be a tuple")
    if len(values) > MAX_CATEGORIES:
        raise ValueError("too many categories")
    checked = tuple(
        _bounded_text("category", value, maximum=MAX_CATEGORY_LENGTH)
        for value in values
    )
    if len({value.casefold() for value in checked}) != len(checked):
        raise ValueError("categories must be unique")
    return tuple(sorted(checked, key=lambda item: (item.casefold(), item)))


class ProviderKind(StrEnum):
    """Supported adapter identities; availability is a separate capability."""

    FIXTURE = "fixture"
    GRAPH = "graph"
    OUTLOOK_COM = "outlook_com"


class Importance(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class HeaderName(StrEnum):
    AUTHENTICATION_RESULTS = "authentication-results"
    LIST_UNSUBSCRIBE = "list-unsubscribe"
    LIST_UNSUBSCRIBE_POST = "list-unsubscribe-post"
    RECEIVED_SPF = "received-spf"


@dataclass(frozen=True, slots=True, kw_only=True)
class MailboxProfileRef:
    provider: ProviderKind
    profile_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ProviderKind):
            raise TypeError("provider must be a ProviderKind")
        object.__setattr__(
            self,
            "profile_id",
            _safe_token("profile_id", self.profile_id),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class FolderRef:
    profile: MailboxProfileRef
    folder_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.profile, MailboxProfileRef):
            raise TypeError("profile must be a MailboxProfileRef")
        object.__setattr__(self, "folder_id", _opaque_id("folder_id", self.folder_id))


@dataclass(frozen=True, slots=True, kw_only=True)
class MailboxItemRef:
    profile: MailboxProfileRef
    provider_id: str
    folder_id: str
    change_token: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, MailboxProfileRef):
            raise TypeError("profile must be a MailboxProfileRef")
        object.__setattr__(
            self,
            "provider_id",
            _opaque_id("provider_id", self.provider_id),
        )
        object.__setattr__(self, "folder_id", _opaque_id("folder_id", self.folder_id))
        if self.change_token is not None:
            object.__setattr__(
                self,
                "change_token",
                _opaque_id("change_token", self.change_token),
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class HeaderMetadata:
    name: HeaderName
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, HeaderName):
            raise TypeError("header name must be allowlisted")
        object.__setattr__(
            self,
            "value",
            _bounded_text("header value", self.value, maximum=MAX_HEADER_VALUE_LENGTH),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageMetadata:
    """The complete allowed message projection; bodies cannot be represented."""

    ref: MailboxItemRef
    sender_address: str
    sender_domain: str
    subject: str
    received_at: datetime
    is_read: bool
    has_attachments: bool
    sender_display_name: str = ""
    is_flagged: bool = False
    importance: Importance = Importance.NORMAL
    categories: tuple[str, ...] = ()
    attachment_count: int | None = None
    headers: tuple[HeaderMetadata, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.ref, MailboxItemRef):
            raise TypeError("ref must be a MailboxItemRef")
        address, domain = _validated_sender(
            address=self.sender_address,
            declared_domain=self.sender_domain,
        )
        object.__setattr__(self, "sender_address", address)
        object.__setattr__(self, "sender_domain", domain)
        object.__setattr__(
            self,
            "subject",
            _bounded_text(
                "subject",
                self.subject,
                maximum=MAX_SUBJECT_LENGTH,
                allow_empty=True,
            ),
        )
        object.__setattr__(
            self,
            "sender_display_name",
            _bounded_text(
                "sender_display_name",
                self.sender_display_name,
                maximum=MAX_DISPLAY_NAME_LENGTH,
                allow_empty=True,
            ),
        )
        object.__setattr__(
            self,
            "received_at",
            _aware_utc("received_at", self.received_at),
        )
        _require_exact_bool("is_read", self.is_read)
        _require_exact_bool("has_attachments", self.has_attachments)
        _require_exact_bool("is_flagged", self.is_flagged)
        if not isinstance(self.importance, Importance):
            raise TypeError("importance must be an Importance")
        object.__setattr__(self, "categories", _categories(self.categories))
        _validate_attachment_metadata(
            has_attachments=self.has_attachments,
            attachment_count=self.attachment_count,
        )
        object.__setattr__(self, "headers", _headers(self.headers))

    @property
    def state_fingerprint(self) -> str:
        """Digest only state used for preconditions and reconciliation."""
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

    def as_canonical_dict(self) -> dict[str, JsonValue]:
        """Return the sensitive representation stored only outside Git."""
        return {
            "ref": _item_ref_dict(self.ref),
            "sender_address": self.sender_address,
            "sender_domain": self.sender_domain,
            "sender_display_name": self.sender_display_name,
            "subject": self.subject,
            "received_at": _format_utc(self.received_at),
            "is_read": self.is_read,
            "has_attachments": self.has_attachments,
            "is_flagged": self.is_flagged,
            "importance": self.importance.value,
            "categories": list(self.categories),
            "attachment_count": self.attachment_count,
            "headers": [
                {"name": header.name.value, "value": header.value}
                for header in self.headers
            ],
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class MailboxSnapshot:
    """A complete immutable acquisition suitable for deterministic replay."""

    snapshot_id: str
    profile: MailboxProfileRef
    as_of: datetime
    adapter_version: str
    capability_digest: str
    scope_folder_ids: tuple[str, ...]
    messages: tuple[MessageMetadata, ...]
    rejected_record_count: int = 0
    complete: bool = True
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
        ):
            raise ValueError("unsupported snapshot schema_version")
        object.__setattr__(
            self,
            "snapshot_id",
            _safe_token("snapshot_id", self.snapshot_id),
        )
        if not isinstance(self.profile, MailboxProfileRef):
            raise TypeError("profile must be a MailboxProfileRef")
        object.__setattr__(self, "as_of", _aware_utc("as_of", self.as_of))
        object.__setattr__(
            self,
            "adapter_version",
            _bounded_text("adapter_version", self.adapter_version, maximum=128),
        )
        _require_digest("capability_digest", self.capability_digest)
        if type(self.rejected_record_count) is not int:
            raise TypeError("rejected_record_count must be an int")
        if self.rejected_record_count < 0:
            raise ValueError("rejected_record_count cannot be negative")
        _require_exact_bool("complete", self.complete)
        folders = _validated_snapshot_scope(self.scope_folder_ids)
        object.__setattr__(self, "scope_folder_ids", folders)
        ordered_messages = _validated_snapshot_messages(
            self.messages,
            self.profile,
            folders,
        )
        object.__setattr__(
            self,
            "messages",
            ordered_messages,
        )
        if len(canonical_bytes(self.as_canonical_dict())) > MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot exceeds maximum canonical byte size")

    @property
    def digest(self) -> str:
        return canonical_digest(self.as_canonical_dict())

    def as_canonical_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "profile": {
                "provider": self.profile.provider.value,
                "profile_id": self.profile.profile_id,
            },
            "as_of": _format_utc(self.as_of),
            "adapter_version": self.adapter_version,
            "capability_digest": self.capability_digest,
            "scope_folder_ids": list(self.scope_folder_ids),
            "messages": [message.as_canonical_dict() for message in self.messages],
            "rejected_record_count": self.rejected_record_count,
            "complete": self.complete,
        }


class ActionType(StrEnum):
    MOVE_MESSAGE = "move_message"
    SET_READ_STATE = "set_read_state"
    ADD_CATEGORY = "add_category"
    REMOVE_CATEGORY = "remove_category"


@dataclass(frozen=True, slots=True, kw_only=True)
class MoveMessage:
    destination: FolderRef

    def __post_init__(self) -> None:
        if not isinstance(self.destination, FolderRef):
            raise TypeError("destination must be a FolderRef")


@dataclass(frozen=True, slots=True, kw_only=True)
class SetReadState:
    is_read: bool

    def __post_init__(self) -> None:
        _require_exact_bool("is_read", self.is_read)


@dataclass(frozen=True, slots=True, kw_only=True)
class SetCategory:
    category: str
    present: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            _bounded_text("category", self.category, maximum=MAX_CATEGORY_LENGTH),
        )
        _require_exact_bool("present", self.present)


type MailboxAction = MoveMessage | SetReadState | SetCategory


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovedMailboxCommand:
    """The only value accepted by the write port."""

    action_id: str
    proposal_digest: str
    approval_digest: str
    line_digest: str
    approval_id: str
    mailbox_ref: str
    target: MailboxItemRef
    expected_state_fingerprint: str
    action: MailboxAction
    idempotency_key: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "action_id",
            _safe_token("action_id", self.action_id),
        )
        object.__setattr__(
            self,
            "approval_id",
            _safe_token("approval_id", self.approval_id),
        )
        _require_digest("proposal_digest", self.proposal_digest)
        _require_digest("approval_digest", self.approval_digest)
        _require_digest("line_digest", self.line_digest)
        _require_digest("idempotency_key", self.idempotency_key)
        _require_digest("expected_state_fingerprint", self.expected_state_fingerprint)
        if re.fullmatch(r"mbx_[0-9a-f]{32,64}", self.mailbox_ref) is None:
            raise ValueError("mailbox_ref must be an HMAC pseudonym")
        if not isinstance(self.target, MailboxItemRef):
            raise TypeError("target must be a MailboxItemRef")
        if not isinstance(self.action, MoveMessage | SetReadState | SetCategory):
            raise TypeError("action must be a supported typed action")
        if (
            isinstance(self.action, MoveMessage)
            and self.action.destination.profile != self.target.profile
        ):
            raise ValueError("move destination and target must share a mailbox profile")

    @property
    def action_type(self) -> ActionType:
        if isinstance(self.action, MoveMessage):
            return ActionType.MOVE_MESSAGE
        if isinstance(self.action, SetReadState):
            return ActionType.SET_READ_STATE
        if self.action.present:
            return ActionType.ADD_CATEGORY
        return ActionType.REMOVE_CATEGORY


def _require_digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 digest")
    return value


def _validated_sender(*, address: str, declared_domain: str) -> tuple[str, str]:
    checked_address = _bounded_text(
        "sender_address",
        address,
        maximum=MAX_ADDRESS_LENGTH,
    )
    if checked_address.count("@") != 1:
        raise ValueError("sender_address must contain one @")
    local, address_domain = checked_address.rsplit("@", 1)
    normalized_domain = normalize_domain(declared_domain)
    if not local or normalize_domain(address_domain) != normalized_domain:
        raise ValueError("sender_address and sender_domain do not agree")
    return checked_address, normalized_domain


def _validate_attachment_metadata(
    *, has_attachments: bool, attachment_count: int | None
) -> None:
    if attachment_count is None:
        return
    if type(attachment_count) is not int:
        raise TypeError("attachment_count must be an int or None")
    if not 0 <= attachment_count <= MAX_ATTACHMENT_COUNT:
        raise ValueError("attachment_count is out of bounds")
    if has_attachments and attachment_count == 0:
        raise ValueError("attachment_count conflicts with has_attachments")
    if not has_attachments and attachment_count != 0:
        raise ValueError("attachment_count conflicts with has_attachments")


def _headers(values: tuple[HeaderMetadata, ...]) -> tuple[HeaderMetadata, ...]:
    if type(values) is not tuple:
        raise TypeError("headers must be a tuple")
    if len(values) > MAX_HEADERS or any(
        not isinstance(header, HeaderMetadata) for header in values
    ):
        raise ValueError("headers must contain at most the allowlisted metadata")
    if len({header.name for header in values}) != len(values):
        raise ValueError("header names must be unique")
    return tuple(sorted(values, key=lambda header: header.name.value))


def _item_ref_dict(value: MailboxItemRef) -> dict[str, JsonValue]:
    return {
        "profile": {
            "provider": value.profile.provider.value,
            "profile_id": value.profile.profile_id,
        },
        "provider_id": value.provider_id,
        "folder_id": value.folder_id,
        "change_token": value.change_token,
    }


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _validated_snapshot_scope(values: object) -> tuple[str, ...]:
    if type(values) is not tuple or not values:
        raise ValueError("scope_folder_ids must be a non-empty tuple")
    if len(values) > MAX_FOLDERS_PER_SNAPSHOT:
        raise ValueError("snapshot contains too many scope folders")
    folders = tuple(sorted(_opaque_id("folder_id", item) for item in values))
    if len(set(folders)) != len(folders):
        raise ValueError("scope_folder_ids must be unique")
    return folders


def _validated_snapshot_messages(
    values: object,
    profile: MailboxProfileRef,
    scope_folder_ids: tuple[str, ...],
) -> tuple[MessageMetadata, ...]:
    if type(values) is not tuple:
        raise TypeError("messages must be a tuple")
    if len(values) > MAX_MESSAGES_PER_SNAPSHOT:
        raise ValueError("snapshot contains too many messages")
    if any(not isinstance(message, MessageMetadata) for message in values):
        raise TypeError("messages must contain MessageMetadata")
    messages = tuple(values)
    if any(message.ref.profile != profile for message in messages):
        raise ValueError("all messages must belong to the snapshot profile")
    if any(message.ref.folder_id not in scope_folder_ids for message in messages):
        raise ValueError("all messages must belong to the snapshot folder scope")
    keys = [(item.ref.provider_id, item.ref.folder_id) for item in messages]
    if len(set(keys)) != len(keys):
        raise ValueError("snapshot contains duplicate message references")
    return tuple(
        sorted(
            messages,
            key=lambda item: (item.ref.provider_id, item.ref.folder_id),
        )
    )
