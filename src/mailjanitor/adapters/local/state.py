"""SQLite operational state for approval claims and crash-safe execution."""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Final
from uuid import UUID

from mailjanitor.adapters.local.audit import AuditTail
from mailjanitor.workflow.execution import (
    ApprovalClaimStatus,
    DurableActionStatus,
    ExecutionIntent,
    StoredExecution,
)

_SCHEMA_VERSION: Final = 1
_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAILBOX_PATTERN: Final = re.compile(r"mbx_[0-9a-f]{32,64}\Z")
_TARGET_PATTERN: Final = re.compile(r"(?:msg|fld|obj)_[0-9a-f]{32,64}\Z")
_CODE_PATTERN: Final = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")

_DIRECT_TERMINAL = frozenset(
    {
        DurableActionStatus.SUCCEEDED,
        DurableActionStatus.DEFINITE_FAILURE,
        DurableActionStatus.INDETERMINATE,
    }
)
_RECONCILIATION_TERMINAL = frozenset(
    {
        DurableActionStatus.RECONCILED_SUCCEEDED,
        DurableActionStatus.REQUIRES_NEW_APPROVAL,
        DurableActionStatus.INDETERMINATE,
    }
)


class OperationalStateError(RuntimeError):
    """Raised when durable state cannot prove a safe transition."""


class SqliteOperationalState:
    """Durable execution state and protected audit anchor in one local DB."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._prepare_path()
        self._initialize()

    @contextmanager
    def profile_lock(self, mailbox_ref: str) -> Iterator[None]:
        """Acquire a fail-closed, cross-process lock for one mailbox pseudonym."""
        _require_mailbox_ref(mailbox_ref)
        lock_path = self._path.with_name(f"{self._path.name}.{mailbox_ref}.lock")
        try:
            lock = lock_path.open("x", encoding="ascii")
        except FileExistsError as exc:
            raise OperationalStateError("mailbox profile is already locked") from exc
        except OSError as exc:
            raise OperationalStateError("mailbox profile lock is unavailable") from exc
        try:
            lock.write(str(os.getpid()))
            lock.flush()
            os.fsync(lock.fileno())
            yield
        finally:
            lock.close()
            with suppress(FileNotFoundError):
                lock_path.unlink()

    def get(self, idempotency_key: str) -> StoredExecution | None:
        _require_digest(idempotency_key, "idempotency_key")
        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT proposal_digest, approval_digest, action_id, mailbox_ref,
                       target_ref, action_type, status, outcome_code
                  FROM executions
                 WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
        if row is None:
            return None
        try:
            intent = ExecutionIntent(
                idempotency_key=idempotency_key,
                proposal_digest=row[0],
                approval_digest=row[1],
                action_id=row[2],
                mailbox_ref=row[3],
                target_ref=row[4],
                action_type=row[5],
            )
            return StoredExecution(
                intent=intent,
                status=DurableActionStatus(row[6]),
                outcome_code=row[7],
            )
        except (TypeError, ValueError) as exc:
            raise OperationalStateError("stored execution row is invalid") from exc

    def claim_approval(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus:
        """Atomically bind one approval to one recoverable execution run."""
        _require_digest(approval_digest, "approval_digest")
        _require_digest(proposal_digest, "proposal_digest")
        _require_uuid(run_id, "run_id")
        with self._write_connection() as connection:
            row = connection.execute(
                """
                SELECT proposal_digest, run_id
                  FROM approval_claims
                 WHERE approval_digest = ?
                """,
                (approval_digest,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO approval_claims
                        (approval_digest, proposal_digest, run_id)
                    VALUES (?, ?, ?)
                    """,
                    (approval_digest, proposal_digest, run_id),
                )
                return ApprovalClaimStatus.CLAIMED
            if row == (proposal_digest, run_id):
                return ApprovalClaimStatus.SAME_RUN
            return ApprovalClaimStatus.DIFFERENT_RUN

    def approval_claim_status(
        self,
        approval_digest: str,
        proposal_digest: str,
        run_id: str,
    ) -> ApprovalClaimStatus | None:
        """Read an approval binding without creating or changing it.

        ``None`` means unclaimed, ``SAME_RUN`` means the stored proposal and
        run both match, and ``DIFFERENT_RUN`` means an existing binding differs.
        This lookup never returns ``CLAIMED`` because it performs no write.
        """
        _require_digest(approval_digest, "approval_digest")
        _require_digest(proposal_digest, "proposal_digest")
        _require_uuid(run_id, "run_id")
        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT proposal_digest, run_id
                  FROM approval_claims
                 WHERE approval_digest = ?
                """,
                (approval_digest,),
            ).fetchone()
        if row is None:
            return None
        if row == (proposal_digest, run_id):
            return ApprovalClaimStatus.SAME_RUN
        return ApprovalClaimStatus.DIFFERENT_RUN

    def record_intent(self, intent: ExecutionIntent) -> bool:
        """Insert one immutable intent with an atomic unique-key claim."""
        _validate_intent(intent)
        with self._write_connection() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO executions
                        (idempotency_key, proposal_digest, approval_digest,
                         action_id, mailbox_ref, target_ref, action_type, status,
                         outcome_code)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        intent.idempotency_key,
                        intent.proposal_digest,
                        intent.approval_digest,
                        intent.action_id,
                        intent.mailbox_ref,
                        intent.target_ref,
                        intent.action_type,
                        DurableActionStatus.INTENT_RECORDED.value,
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def mark_dispatched(self, idempotency_key: str) -> None:
        """Advance exactly INTENT_RECORDED to DISPATCHED."""
        _require_digest(idempotency_key, "idempotency_key")
        with self._write_connection() as connection:
            cursor = connection.execute(
                """
                UPDATE executions
                   SET status = ?
                 WHERE idempotency_key = ? AND status = ?
                """,
                (
                    DurableActionStatus.DISPATCHED.value,
                    idempotency_key,
                    DurableActionStatus.INTENT_RECORDED.value,
                ),
            )
            if cursor.rowcount != 1:
                raise OperationalStateError("execution cannot enter dispatched state")

    def record_terminal(
        self,
        idempotency_key: str,
        status: DurableActionStatus,
        outcome_code: str,
    ) -> None:
        """Apply one legal terminal/reconciliation transition."""
        _require_digest(idempotency_key, "idempotency_key")
        if not isinstance(status, DurableActionStatus):
            raise TypeError("status must be a DurableActionStatus")
        _require_code(outcome_code, "outcome_code")
        with self._write_connection() as connection:
            row = connection.execute(
                "SELECT status FROM executions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                raise OperationalStateError("execution intent does not exist")
            try:
                previous = DurableActionStatus(row[0])
            except ValueError as exc:
                raise OperationalStateError(
                    "stored execution status is invalid"
                ) from exc
            if not _transition_allowed(previous, status):
                raise OperationalStateError("execution terminal transition is invalid")
            connection.execute(
                """
                UPDATE executions
                   SET status = ?, outcome_code = ?
                 WHERE idempotency_key = ?
                """,
                (status.value, outcome_code, idempotency_key),
            )

    def load(self, ledger_id: str) -> AuditTail | None:
        """Load the protected tail required by ``AuditLedger``."""
        _require_code(ledger_id, "ledger_id")
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT sequence, mac FROM audit_anchors WHERE ledger_id = ?",
                (ledger_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            return AuditTail(sequence=row[0], mac=row[1])
        except (TypeError, ValueError) as exc:
            raise OperationalStateError("stored audit anchor is invalid") from exc

    def store(self, ledger_id: str, tail: AuditTail) -> None:
        """Advance an audit anchor by exactly one sequence number."""
        _require_code(ledger_id, "ledger_id")
        if not isinstance(tail, AuditTail):
            raise TypeError("tail must be an AuditTail")
        with self._write_connection() as connection:
            row = connection.execute(
                "SELECT sequence, mac FROM audit_anchors WHERE ledger_id = ?",
                (ledger_id,),
            ).fetchone()
            if row is None:
                if tail.sequence != 0:
                    raise OperationalStateError(
                        "first audit anchor must be the genesis sequence zero"
                    )
                connection.execute(
                    """
                    INSERT INTO audit_anchors (ledger_id, sequence, mac)
                    VALUES (?, ?, ?)
                    """,
                    (ledger_id, tail.sequence, tail.mac),
                )
                return
            if tail.sequence != row[0] + 1:
                raise OperationalStateError("audit anchor sequence must advance by one")
            connection.execute(
                """
                UPDATE audit_anchors SET sequence = ?, mac = ? WHERE ledger_id = ?
                """,
                (tail.sequence, tail.mac, ledger_id),
            )

    def _prepare_path(self) -> None:
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise OperationalStateError("state directory is unavailable") from exc
        if self._path.parent.is_symlink():
            raise OperationalStateError("state directory cannot be a symbolic link")
        if self._path.is_symlink():
            raise OperationalStateError("state path must be a regular file")
        if self._path.exists() and not self._path.is_file():
            raise OperationalStateError("state path must be a regular file")

    def _initialize(self) -> None:
        with self._write_connection(initialize=True) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    version INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_meta (singleton, version) VALUES (1, ?)",
                (_SCHEMA_VERSION,),
            )
            row = connection.execute(
                "SELECT version FROM schema_meta WHERE singleton = 1"
            ).fetchone()
            if row != (_SCHEMA_VERSION,):
                raise OperationalStateError("unsupported operational-state schema")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_claims (
                    approval_digest TEXT PRIMARY KEY,
                    proposal_digest TEXT NOT NULL,
                    run_id TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS executions (
                    idempotency_key TEXT PRIMARY KEY,
                    proposal_digest TEXT NOT NULL,
                    approval_digest TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    mailbox_ref TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    outcome_code TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_anchors (
                    ledger_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL CHECK (sequence >= 0),
                    mac TEXT NOT NULL
                )
                """
            )
        with suppress(OSError):
            self._path.chmod(0o600)

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._open_connection()
        try:
            yield connection
        except sqlite3.Error as exc:
            raise OperationalStateError("operational state read failed") from exc
        finally:
            connection.close()

    @contextmanager
    def _write_connection(
        self, *, initialize: bool = False
    ) -> Iterator[sqlite3.Connection]:
        self._prepare_path()
        connection = self._open_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except OperationalStateError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            if initialize:
                raise OperationalStateError("operational state setup failed") from exc
            raise OperationalStateError("operational state write failed") from exc
        finally:
            connection.close()

    def _open_connection(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self._path, timeout=5.0)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 5000")
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise OperationalStateError("operational state is unavailable") from exc
        return connection


def _transition_allowed(
    previous: DurableActionStatus,
    requested: DurableActionStatus,
) -> bool:
    if previous is DurableActionStatus.DISPATCHED:
        return requested in _DIRECT_TERMINAL | _RECONCILIATION_TERMINAL
    if previous in {
        DurableActionStatus.INTENT_RECORDED,
        DurableActionStatus.INDETERMINATE,
    }:
        return requested in _RECONCILIATION_TERMINAL
    return False


def _validate_intent(intent: ExecutionIntent) -> None:
    if not isinstance(intent, ExecutionIntent):
        raise TypeError("intent must be an ExecutionIntent")
    _require_digest(intent.idempotency_key, "idempotency_key")
    _require_digest(intent.proposal_digest, "proposal_digest")
    _require_digest(intent.approval_digest, "approval_digest")
    _require_uuid(intent.action_id, "action_id")
    _require_mailbox_ref(intent.mailbox_ref)
    if _TARGET_PATTERN.fullmatch(intent.target_ref) is None:
        raise ValueError("target_ref must be an HMAC pseudonym")
    _require_code(intent.action_type, "action_type")


def _require_digest(value: str, name: str) -> None:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")


def _require_mailbox_ref(value: str) -> None:
    if type(value) is not str or _MAILBOX_PATTERN.fullmatch(value) is None:
        raise ValueError("mailbox_ref must be an HMAC pseudonym")


def _require_code(value: str, name: str) -> None:
    if type(value) is not str or _CODE_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded machine code")


def _require_uuid(value: str, name: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{name} must be a UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{name} must use canonical UUID text")
