"""Tamper-evident, privacy-preserving append-only execution audit."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Protocol, Self, cast
from uuid import UUID, uuid4

from mailjanitor.canonical import canonical_bytes
from mailjanitor.workflow.execution import AuditedActionState

_GENESIS_MAC = "0" * 64
_MINIMUM_KEY_BYTES = 32
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PSEUDONYM_PATTERN = re.compile(r"(?:mbx|msg|fld|obj)_[0-9a-f]{32,64}\Z")
_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "event_id",
        "occurred_at",
        "event_type",
        "run_id",
        "proposal_digest",
        "approval_digest",
        "action_id",
        "idempotency_key",
        "mailbox_ref",
        "target_ref",
        "action_type",
        "outcome_code",
        "previous_mac",
        "mac",
    }
)


class AuditError(RuntimeError):
    """Base class for closed audit failures."""


class AuditIntegrityError(AuditError):
    """Raised when the ledger or its protected anchor does not verify."""


class AuditUnavailableError(AuditError):
    """Raised when durable append or locking is unavailable."""


@dataclass(frozen=True, slots=True)
class AuditTail:
    """Protected ledger head used to detect truncation."""

    sequence: int
    mac: str

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("audit sequence cannot be negative")
        if not re.fullmatch(r"[0-9a-f]{64}", self.mac):
            raise ValueError("audit tail MAC must be 64 lowercase hex characters")


class ProtectedTailAnchor(Protocol):
    """Storage boundary for a tail value protected outside the ledger file."""

    def load(self, ledger_id: str) -> AuditTail | None:
        """Return the protected tail, or ``None`` for a new ledger."""
        ...

    def store(self, ledger_id: str, tail: AuditTail) -> None:
        """Durably replace the protected tail."""
        ...


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One validated, redacted ledger record."""

    sequence: int
    event_id: str
    occurred_at: str
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
    previous_mac: str
    mac: str

    def __post_init__(self) -> None:
        if self.sequence < 1:
            raise ValueError("audit record sequence must be positive")
        _require_uuid(self.event_id, "event_id")
        _require_utc_timestamp(self.occurred_at)
        _require_code(self.event_type, "event_type")
        _require_uuid(self.run_id, "run_id")
        _require_digest(self.proposal_digest, "proposal_digest")
        _require_digest(self.approval_digest, "approval_digest")
        _require_uuid(self.action_id, "action_id")
        _require_digest(self.idempotency_key, "idempotency_key")
        _require_pseudonym(self.mailbox_ref, "mailbox_ref", prefix="mbx_")
        _require_pseudonym(self.target_ref, "target_ref")
        _require_code(self.action_type, "action_type")
        if self.outcome_code is not None:
            _require_code(self.outcome_code, "outcome_code")
        _require_mac(self.previous_mac, "previous_mac")
        _require_mac(self.mac, "mac")

    def payload(self) -> dict[str, object]:
        """Return the authenticated payload, excluding its own MAC."""
        return {
            "schema_version": 1,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "event_type": self.event_type,
            "run_id": self.run_id,
            "proposal_digest": self.proposal_digest,
            "approval_digest": self.approval_digest,
            "action_id": self.action_id,
            "idempotency_key": self.idempotency_key,
            "mailbox_ref": self.mailbox_ref,
            "target_ref": self.target_ref,
            "action_type": self.action_type,
            "outcome_code": self.outcome_code,
            "previous_mac": self.previous_mac,
        }

    def as_dict(self) -> dict[str, object]:
        """Return the complete canonical record mapping."""
        return {**self.payload(), "mac": self.mac}

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Self:
        """Parse a record without accepting unknown or missing fields."""
        if frozenset(value) != _RECORD_KEYS:
            raise ValueError("audit record has missing or unknown fields")
        if value["schema_version"] != 1:
            raise ValueError("unsupported audit schema version")
        if type(value["sequence"]) is not int:
            raise ValueError("audit sequence must be an integer")
        string_fields = (
            "event_id",
            "occurred_at",
            "event_type",
            "run_id",
            "proposal_digest",
            "approval_digest",
            "action_id",
            "idempotency_key",
            "mailbox_ref",
            "target_ref",
            "action_type",
            "previous_mac",
            "mac",
        )
        if any(not isinstance(value[name], str) for name in string_fields):
            raise ValueError("audit string field has an invalid type")
        outcome = value["outcome_code"]
        if outcome is not None and not isinstance(outcome, str):
            raise ValueError("audit outcome_code must be a string or null")
        return cls(
            sequence=value["sequence"],
            event_id=cast("str", value["event_id"]),
            occurred_at=cast("str", value["occurred_at"]),
            event_type=cast("str", value["event_type"]),
            run_id=cast("str", value["run_id"]),
            proposal_digest=cast("str", value["proposal_digest"]),
            approval_digest=cast("str", value["approval_digest"]),
            action_id=cast("str", value["action_id"]),
            idempotency_key=cast("str", value["idempotency_key"]),
            mailbox_ref=cast("str", value["mailbox_ref"]),
            target_ref=cast("str", value["target_ref"]),
            action_type=cast("str", value["action_type"]),
            outcome_code=outcome,
            previous_mac=cast("str", value["previous_mac"]),
            mac=cast("str", value["mac"]),
        )


class AuditLedger:
    """Append-only JSONL ledger authenticated by an HMAC chain and anchor."""

    def __init__(
        self,
        path: Path,
        *,
        ledger_id: str,
        integrity_key: bytes,
        anchor: ProtectedTailAnchor,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if len(integrity_key) < _MINIMUM_KEY_BYTES:
            raise ValueError(
                f"audit integrity key must contain at least {_MINIMUM_KEY_BYTES} bytes"
            )
        _require_code(ledger_id, "ledger_id")
        self._path = path
        self._lock_path = path.with_name(f"{path.name}.lock")
        self._ledger_id = ledger_id
        self._key = bytes(integrity_key)
        self._anchor = anchor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._event_id_factory = event_id_factory or (lambda: str(uuid4()))

    def verify(self) -> None:
        """Verify the complete ledger and its protected tail anchor."""
        with self._exclusive_lock():
            self._verify_unlocked()

    def records(self) -> tuple[AuditRecord, ...]:
        """Return records only after full chain and anchor verification."""
        with self._exclusive_lock():
            return self._verify_unlocked()[1]

    def state_for(self, idempotency_key: str) -> str | None:
        """Return the latest audited event type for an idempotency key."""
        latest = self.latest_for(idempotency_key)
        return None if latest is None else latest.event_type

    def latest_for(self, idempotency_key: str) -> AuditedActionState | None:
        """Return the latest fully bound event after complete ledger verification."""
        _require_digest(idempotency_key, "idempotency_key")
        matching = (
            record
            for record in self.records()
            if record.idempotency_key == idempotency_key
        )
        record = next(reversed(tuple(matching)), None)
        if record is None:
            return None
        return AuditedActionState(
            event_type=record.event_type,
            run_id=record.run_id,
            proposal_digest=record.proposal_digest,
            approval_digest=record.approval_digest,
            action_id=record.action_id,
            idempotency_key=record.idempotency_key,
            mailbox_ref=record.mailbox_ref,
            target_ref=record.target_ref,
            action_type=record.action_type,
            outcome_code=record.outcome_code,
        )

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
    ) -> AuditRecord:
        """Durably append one fully redacted event and advance the anchor."""
        with self._exclusive_lock():
            tail, _ = self._verify_unlocked()
            timestamp = _format_utc(self._clock())
            event_id = self._event_id_factory()
            payload: dict[str, object] = {
                "schema_version": 1,
                "sequence": tail.sequence + 1,
                "event_id": event_id,
                "occurred_at": timestamp,
                "event_type": event_type,
                "run_id": run_id,
                "proposal_digest": proposal_digest,
                "approval_digest": approval_digest,
                "action_id": action_id,
                "idempotency_key": idempotency_key,
                "mailbox_ref": mailbox_ref,
                "target_ref": target_ref,
                "action_type": action_type,
                "outcome_code": outcome_code,
                "previous_mac": tail.mac,
            }
            mac = self._mac(payload)
            record = AuditRecord.from_mapping({**payload, "mac": mac})
            self._prepare_path()
            try:
                with self._open_append_stream() as stream:
                    stream.write(canonical_bytes(record.as_dict()))
                    stream.write(b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise AuditUnavailableError("could not durably append audit") from exc
            new_tail = AuditTail(record.sequence, record.mac)
            self._store_anchor(new_tail, operation="advance")
            return record

    def _verify_unlocked(self) -> tuple[AuditTail, tuple[AuditRecord, ...]]:
        records = self._load_records_unlocked()
        tail = AuditTail(len(records), records[-1].mac if records else _GENESIS_MAC)
        anchored = self._load_anchor()
        if anchored is None:
            if records:
                raise AuditIntegrityError("non-empty audit has no protected anchor")
            self._store_anchor(tail, operation="initialize")
            return tail, records
        if anchored == tail:
            return tail, records
        if (
            records
            and anchored.sequence + 1 == tail.sequence
            and hmac.compare_digest(anchored.mac, records[-1].previous_mac)
        ):
            # The JSONL record is already durable and its HMAC proves it is the
            # unique next link. Repair only this one-record append/anchor crash
            # window; missing or larger gaps remain integrity failures.
            self._store_anchor(tail, operation="recover")
            return tail, records
        raise AuditIntegrityError("audit tail does not match protected anchor")

    def _store_anchor(self, tail: AuditTail, *, operation: str) -> None:
        try:
            self._anchor.store(self._ledger_id, tail)
        except Exception as exc:
            raise AuditUnavailableError(
                f"could not {operation} protected audit anchor"
            ) from exc

    def _load_records_unlocked(self) -> tuple[AuditRecord, ...]:
        records: list[AuditRecord] = []
        expected_previous = _GENESIS_MAC
        if self._path.is_symlink():
            raise AuditIntegrityError("audit path is not a regular file")
        if not self._path.exists():
            return ()
        if not self._path.is_file():
            raise AuditIntegrityError("audit path is not a regular file")
        try:
            with self._path.open("rb") as stream:
                for sequence, raw_line in enumerate(stream, start=1):
                    record = self._parse_record(
                        raw_line,
                        sequence=sequence,
                        expected_previous=expected_previous,
                    )
                    records.append(record)
                    expected_previous = record.mac
        except OSError as exc:
            raise AuditUnavailableError("could not read audit ledger") from exc
        return tuple(records)

    def _parse_record(
        self,
        raw_line: bytes,
        *,
        sequence: int,
        expected_previous: str,
    ) -> AuditRecord:
        if not raw_line.endswith(b"\n"):
            raise AuditIntegrityError("audit has a truncated final line")
        try:
            decoded = json.loads(raw_line)
            if not isinstance(decoded, dict):
                raise TypeError("record is not an object")
            record = AuditRecord.from_mapping(decoded)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise AuditIntegrityError("audit record is invalid") from exc
        expected_encoding = canonical_bytes(record.as_dict()) + b"\n"
        if not hmac.compare_digest(raw_line, expected_encoding):
            raise AuditIntegrityError("audit record encoding is not canonical")
        if record.sequence != sequence:
            raise AuditIntegrityError("audit sequence is not contiguous")
        if not hmac.compare_digest(record.previous_mac, expected_previous):
            raise AuditIntegrityError("audit chain predecessor mismatch")
        if not hmac.compare_digest(record.mac, self._mac(record.payload())):
            raise AuditIntegrityError("audit record MAC mismatch")
        return record

    def _load_anchor(self) -> AuditTail | None:
        try:
            return self._anchor.load(self._ledger_id)
        except Exception as exc:
            raise AuditUnavailableError(
                "could not read protected audit anchor"
            ) from exc

    def _mac(self, payload: Mapping[str, object]) -> str:
        return hmac.new(
            self._key,
            canonical_bytes(dict(payload)),
            hashlib.sha256,
        ).hexdigest()

    def _prepare_path(self) -> None:
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditUnavailableError("could not create audit directory") from exc
        if self._path.parent.is_symlink():
            raise AuditIntegrityError("audit directory cannot be a symbolic link")

    @contextmanager
    def _open_append_stream(self) -> Iterator[BinaryIO]:
        if self._path.is_symlink():
            raise AuditIntegrityError("audit path is not a regular file")
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(self._path, flags, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditIntegrityError("audit path is not a regular file")
            with os.fdopen(descriptor, "ab", closefd=True) as stream:
                descriptor = None
                yield stream
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._prepare_path()
        try:
            lock = self._lock_path.open("x", encoding="ascii")
        except FileExistsError as exc:
            raise AuditUnavailableError("audit ledger is already locked") from exc
        except OSError as exc:
            raise AuditUnavailableError("could not acquire audit lock") from exc
        try:
            lock.write(str(os.getpid()))
            lock.flush()
            yield
        finally:
            # Cleanup must not raise; see SqliteOperationalState.profile_lock.
            # A failed unlink leaves a stale lock that fails closed, which is
            # preferable to discarding the result of a durable append.
            with suppress(OSError):
                lock.close()
            with suppress(OSError):
                self._lock_path.unlink()


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("audit clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_utc_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("audit timestamp is invalid") from exc
    if not value.endswith("Z") or parsed.tzinfo is None:
        raise ValueError("audit timestamp must be canonical UTC")


def _require_uuid(value: str, field_name: str) -> None:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field_name} must be a UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{field_name} must use canonical UUID text")


def _require_digest(value: str, field_name: str) -> None:
    if not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_pseudonym(
    value: str,
    field_name: str,
    *,
    prefix: str | None = None,
) -> None:
    if not _PSEUDONYM_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be an HMAC-derived pseudonym")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"{field_name} has an invalid pseudonym kind")


def _require_code(value: str, field_name: str) -> None:
    if not _CODE_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a bounded machine code")


def _require_mac(value: str, field_name: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{field_name} must be 64 lowercase hex characters")
