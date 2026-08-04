"""Deterministic, explainable classification over sealed mailbox metadata."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import StrEnum

from mailjanitor.canonical import canonical_digest
from mailjanitor.domain import (
    HeaderName,
    MailboxItemRef,
    MailboxSnapshot,
    MessageMetadata,
    normalize_domain,
    validate_opaque_id,
)

CLASSIFIER_VERSION = "3"
MIN_ROTATING_SENDERS = 2
MAX_ROTATING_SENDERS = 20
MAX_SEVERITY = 100
MAX_POLICY_TOKEN_LENGTH = 128
MAX_POLICY_ADDRESS_LENGTH = 320


class IncompleteSnapshotError(ValueError):
    """Raised when a snapshot cannot safely support classification."""


class TriageBucket(StrEnum):
    SUSPECT = "suspect"
    SECURITY = "security"
    TRANSACTIONAL = "transactional"
    JOB_ALERT = "job_alert"
    NEWSLETTER = "newsletter"
    UNKNOWN = "unknown"


_PRECEDENCE = (
    TriageBucket.SUSPECT,
    TriageBucket.SECURITY,
    TriageBucket.TRANSACTIONAL,
    TriageBucket.JOB_ALERT,
    TriageBucket.NEWSLETTER,
    TriageBucket.UNKNOWN,
)
_PRECEDENCE_INDEX = {bucket: index for index, bucket in enumerate(_PRECEDENCE)}

_SECURITY_TOKENS = frozenset(
    {"login", "password", "security", "signin", "suspicious", "unusual", "verify"}
)
_TRANSACTION_TOKENS = frozenset(
    {"delivery", "invoice", "order", "payment", "receipt", "shipped", "transaction"}
)
_JOB_TOKENS = frozenset(
    {"application", "career", "job", "jobs", "position", "recruiter"}
)
_NEWSLETTER_TOKENS = frozenset({"digest", "newsletter", "weekly"})
_FINANCE_LURE_TOKENS = frozenset(
    {"bank", "finance", "invoice", "payment", "payroll", "refund", "statement", "tax"}
)
_DELIVERY_LURE_TOKENS = frozenset(
    {"delivery", "package", "parcel", "shipment", "shipping"}
)


@dataclass(frozen=True, slots=True, kw_only=True)
class BrandPolicy:
    """One claimed-brand token and its exact/suffix domain allowlist."""

    brand_id: str
    tokens: tuple[str, ...]
    expected_domains: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "brand_id", _policy_token("brand_id", self.brand_id))
        object.__setattr__(self, "tokens", _policy_tokens("tokens", self.tokens))
        object.__setattr__(
            self,
            "expected_domains",
            _policy_domains("expected_domains", self.expected_domains),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ClassifierPolicy:
    """Bounded declarative inputs; it deliberately has no regex or callbacks."""

    brands: tuple[BrandPolicy, ...] = ()
    known_security_senders: tuple[str, ...] = ()
    transactional_domains: tuple[str, ...] = ()
    job_domains: tuple[str, ...] = ()
    newsletter_domains: tuple[str, ...] = ()
    free_mail_domains: tuple[str, ...] = ("gmail.com", "outlook.com", "yahoo.com")
    junk_folder_ids: tuple[str, ...] = ("junk", "junk-email")
    rotating_sender_threshold: int = 3

    def __post_init__(self) -> None:
        if type(self.brands) is not tuple or any(
            not isinstance(brand, BrandPolicy) for brand in self.brands
        ):
            raise TypeError("brands must be a tuple of BrandPolicy")
        brands = tuple(sorted(self.brands, key=lambda brand: brand.brand_id))
        if len({brand.brand_id for brand in brands}) != len(brands):
            raise ValueError("brand_id values must be unique")
        object.__setattr__(self, "brands", brands)
        object.__setattr__(
            self,
            "known_security_senders",
            _policy_addresses(self.known_security_senders),
        )
        for field_name in (
            "transactional_domains",
            "job_domains",
            "newsletter_domains",
            "free_mail_domains",
        ):
            object.__setattr__(
                self,
                field_name,
                _policy_domains(field_name, getattr(self, field_name)),
            )
        if type(self.junk_folder_ids) is not tuple or not self.junk_folder_ids:
            raise ValueError("junk_folder_ids must be a non-empty tuple")
        folders = tuple(
            sorted(
                validate_opaque_id("junk_folder_id", folder)
                for folder in self.junk_folder_ids
            )
        )
        if len(set(folders)) != len(folders):
            raise ValueError("junk_folder_ids must be unique")
        object.__setattr__(self, "junk_folder_ids", folders)
        if (
            type(self.rotating_sender_threshold) is not int
            or not MIN_ROTATING_SENDERS
            <= self.rotating_sender_threshold
            <= MAX_ROTATING_SENDERS
        ):
            raise ValueError("rotating_sender_threshold must be an int from 2 to 20")

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "brands": [
                    {
                        "brand_id": brand.brand_id,
                        "tokens": list(brand.tokens),
                        "expected_domains": list(brand.expected_domains),
                    }
                    for brand in self.brands
                ],
                "known_security_senders": list(self.known_security_senders),
                "transactional_domains": list(self.transactional_domains),
                "job_domains": list(self.job_domains),
                "newsletter_domains": list(self.newsletter_domains),
                "free_mail_domains": list(self.free_mail_domains),
                "junk_folder_ids": list(self.junk_folder_ids),
                "rotating_sender_threshold": self.rotating_sender_threshold,
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleEvidence:
    rule_id: str
    bucket: TriageBucket
    severity: int
    signals: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _policy_token("rule_id", self.rule_id))
        if not isinstance(self.bucket, TriageBucket):
            raise TypeError("bucket must be a TriageBucket")
        if type(self.severity) is not int or not 0 <= self.severity <= MAX_SEVERITY:
            raise ValueError("severity must be an int from 0 through 100")
        object.__setattr__(self, "signals", _policy_signals(self.signals))


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageClassification:
    ref: MailboxItemRef
    primary_bucket: TriageBucket
    labels: tuple[TriageBucket, ...]
    evidence: tuple[RuleEvidence, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ClassificationSet:
    snapshot_id: str
    snapshot_digest: str
    policy_digest: str
    classifier_version: str
    classifications: tuple[MessageClassification, ...]


def classify_snapshot(
    snapshot: MailboxSnapshot,
    policy: ClassifierPolicy | None = None,
) -> ClassificationSet:
    """Classify one sealed snapshot without I/O, time, randomness, or mutation."""

    if not isinstance(snapshot, MailboxSnapshot):
        raise TypeError("snapshot must be a MailboxSnapshot")
    if policy is None:
        policy = DEFAULT_POLICY
    if not isinstance(policy, ClassifierPolicy):
        raise TypeError("policy must be a ClassifierPolicy")
    if not snapshot.complete or snapshot.rejected_record_count:
        raise IncompleteSnapshotError(
            "classification requires a complete snapshot with no rejected records"
        )

    rotating = _rotating_free_mail_evidence(snapshot.messages, policy)
    classifications = tuple(
        _classify_message(message, policy, rotating.get(_ref_key(message.ref)))
        for message in snapshot.messages
    )
    return ClassificationSet(
        snapshot_id=snapshot.snapshot_id,
        snapshot_digest=snapshot.digest,
        policy_digest=policy.digest,
        classifier_version=CLASSIFIER_VERSION,
        classifications=classifications,
    )


def _classify_message(
    message: MessageMetadata,
    policy: ClassifierPolicy,
    rotating_evidence: RuleEvidence | None,
) -> MessageClassification:
    tokens = _tokens(f"{message.sender_display_name} {message.subject}")
    evidence: dict[str, RuleEvidence] = {}

    claimed_brands = tuple(
        brand
        for brand in policy.brands
        if tokens.intersection(brand.tokens)
        and not any(
            _domain_matches(message.sender_domain, domain)
            for domain in brand.expected_domains
        )
    )
    if claimed_brands:
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="suspect.brand_domain_mismatch.v1",
                bucket=TriageBucket.SUSPECT,
                severity=100,
                signals=(
                    *(f"claimed_brand:{brand.brand_id}" for brand in claimed_brands),
                    "sender_domain_not_expected",
                ),
            ),
        )

    lure_themes = _lure_themes(tokens)
    if (
        message.ref.folder_id.casefold()
        in {folder.casefold() for folder in policy.junk_folder_ids}
        and message.has_attachments
        and lure_themes
    ):
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="suspect.junk_attachment_lure.v1",
                bucket=TriageBucket.SUSPECT,
                severity=95,
                signals=("attachment_flag", "junk_scope", *lure_themes),
            ),
        )
    if rotating_evidence is not None:
        _add_evidence(evidence, rotating_evidence)

    if (
        message.sender_address.casefold() in policy.known_security_senders
        and tokens.intersection(_SECURITY_TOKENS)
    ):
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="security.known_sender.v1",
                bucket=TriageBucket.SECURITY,
                severity=60,
                signals=("configured_exact_sender", "security_theme"),
            ),
        )

    if _domain_in(
        message.sender_domain, policy.transactional_domains
    ) and tokens.intersection(_TRANSACTION_TOKENS):
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="transactional.known_domain.v1",
                bucket=TriageBucket.TRANSACTIONAL,
                severity=70,
                signals=("transaction_theme", "known_transactional_domain"),
            ),
        )

    if _domain_in(message.sender_domain, policy.job_domains) and tokens.intersection(
        _JOB_TOKENS
    ):
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="job_alert.known_domain.v1",
                bucket=TriageBucket.JOB_ALERT,
                severity=50,
                signals=("job_theme", "known_job_domain"),
            ),
        )

    header_names = {header.name for header in message.headers}
    if HeaderName.LIST_UNSUBSCRIBE in header_names:
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="newsletter.list_unsubscribe_header.v1",
                bucket=TriageBucket.NEWSLETTER,
                severity=40,
                signals=("list_unsubscribe_present",),
            ),
        )
    if _domain_in(
        message.sender_domain, policy.newsletter_domains
    ) and tokens.intersection(_NEWSLETTER_TOKENS):
        _add_evidence(
            evidence,
            RuleEvidence(
                rule_id="newsletter.known_domain.v1",
                bucket=TriageBucket.NEWSLETTER,
                severity=35,
                signals=("newsletter_theme", "known_newsletter_domain"),
            ),
        )

    ordered_evidence = tuple(sorted(evidence.values(), key=lambda item: item.rule_id))
    labels_found = {item.bucket for item in ordered_evidence}
    labels = tuple(bucket for bucket in _PRECEDENCE if bucket in labels_found)
    if not labels:
        labels = (TriageBucket.UNKNOWN,)
    return MessageClassification(
        ref=message.ref,
        primary_bucket=labels[0],
        labels=labels,
        evidence=ordered_evidence,
    )


def _rotating_free_mail_evidence(
    messages: tuple[MessageMetadata, ...],
    policy: ClassifierPolicy,
) -> dict[tuple[str, str], RuleEvidence]:
    candidates: dict[str, list[MessageMetadata]] = {}
    for message in messages:
        if not message.has_attachments or not _domain_in(
            message.sender_domain, policy.free_mail_domains
        ):
            continue
        for theme in _lure_themes(_tokens(message.subject)):
            candidates.setdefault(theme, []).append(message)

    result: dict[tuple[str, str], RuleEvidence] = {}
    for theme in sorted(candidates):
        group = candidates[theme]
        addresses = {message.sender_address.casefold() for message in group}
        if len(addresses) < policy.rotating_sender_threshold:
            continue
        evidence = RuleEvidence(
            rule_id="suspect.rotating_free_mail.v1",
            bucket=TriageBucket.SUSPECT,
            severity=90,
            signals=(theme, "multiple_free_mail_senders"),
        )
        for message in group:
            result[_ref_key(message.ref)] = evidence
    return result


def _tokens(value: str) -> frozenset[str]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    words: list[str] = []
    current: list[str] = []
    for character in normalized:
        # Zero-width and joining characters survive NFKC but render as nothing,
        # so a sender could split a brand token the reviewer still reads whole.
        if unicodedata.category(character) == "Cf":
            continue
        if character.isalnum():
            current.append(character)
        elif current:
            words.append("".join(current))
            current.clear()
    if current:
        words.append("".join(current))
    return frozenset(words)


def _lure_themes(tokens: frozenset[str]) -> tuple[str, ...]:
    themes: list[str] = []
    if tokens.intersection(_DELIVERY_LURE_TOKENS):
        themes.append("delivery_theme")
    if tokens.intersection(_FINANCE_LURE_TOKENS):
        themes.append("finance_theme")
    return tuple(themes)


def _domain_matches(candidate: str, expected: str) -> bool:
    return candidate == expected or candidate.endswith(f".{expected}")


def _domain_in(candidate: str, expected: tuple[str, ...]) -> bool:
    return any(_domain_matches(candidate, domain) for domain in expected)


def _ref_key(ref: MailboxItemRef) -> tuple[str, str]:
    return (ref.provider_id, ref.folder_id)


def _add_evidence(target: dict[str, RuleEvidence], evidence: RuleEvidence) -> None:
    target[evidence.rule_id] = evidence


def _policy_token(name: str, value: object) -> str:
    if type(value) is not str or not value or len(value) > MAX_POLICY_TOKEN_LENGTH:
        raise ValueError(f"{name} must be a non-empty bounded string")
    if not value.isascii() or any(
        not (character.isalnum() or character in {".", ":", "_"}) for character in value
    ):
        raise ValueError(
            f"{name} must contain only ASCII letters, digits, dot, colon, or underscore"
        )
    return value.casefold()


def _policy_tokens(name: str, values: object) -> tuple[str, ...]:
    if type(values) is not tuple or not values:
        raise ValueError(f"{name} must be a non-empty tuple")
    result = tuple(sorted(_policy_token(name, value) for value in values))
    if len(set(result)) != len(result):
        raise ValueError(f"{name} must be unique")
    return result


def _policy_domains(name: str, values: object) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise TypeError(f"{name} must be a tuple")
    result = tuple(sorted(normalize_domain(value) for value in values))
    if len(set(result)) != len(result):
        raise ValueError(f"{name} must be unique")
    return result


def _policy_addresses(values: object) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise TypeError("known_security_senders must be a tuple")
    result: list[str] = []
    for value in values:
        if (
            type(value) is not str
            or value.count("@") != 1
            or len(value) > MAX_POLICY_ADDRESS_LENGTH
        ):
            raise ValueError("known security sender must be one bounded address")
        local, domain = value.rsplit("@", 1)
        if not local or any(character.isspace() for character in local):
            raise ValueError("known security sender local part is invalid")
        result.append(f"{local.casefold()}@{normalize_domain(domain)}")
    ordered = tuple(sorted(result))
    if len(set(ordered)) != len(ordered):
        raise ValueError("known_security_senders must be unique")
    return ordered


def _policy_signals(values: object) -> tuple[str, ...]:
    if type(values) is not tuple or not values:
        raise ValueError("signals must be a non-empty tuple")
    result = tuple(sorted(_policy_token("signal", value) for value in values))
    if len(set(result)) != len(result):
        raise ValueError("signals must be unique")
    return result


# Public defaults contain no organization, sender, brand, or account-derived
# allowlists. Operators must supply reviewed policy explicitly; a sender-address
# match is a routing hint, never proof of message authentication.
DEFAULT_POLICY = ClassifierPolicy()
