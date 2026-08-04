from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mailjanitor.adapters.local.audit import (
    AuditIntegrityError,
    AuditLedger,
    AuditTail,
    AuditUnavailableError,
)

KEY = b"audit-integrity-key-is-at-least-32-bytes"
DIGEST_A = f"sha256:{'a' * 64}"
DIGEST_B = f"sha256:{'b' * 64}"
MAILBOX_REF = f"mbx_{'1' * 32}"
TARGET_REF = f"msg_{'2' * 32}"
RUN_ID = "11111111-1111-4111-8111-111111111111"
ACTION_ID = "22222222-2222-4222-8222-222222222222"
EVENT_ID = "33333333-3333-4333-8333-333333333333"


@dataclass
class MemoryAnchor:
    value: AuditTail | None = None

    def load(self, ledger_id: str) -> AuditTail | None:
        assert ledger_id == "action-log"
        return self.value

    def store(self, ledger_id: str, tail: AuditTail) -> None:
        assert ledger_id == "action-log"
        self.value = tail


class FailingStoreAnchor(MemoryAnchor):
    def store(self, _ledger_id: str, _tail: AuditTail) -> None:
        raise OSError("synthetic protected-store failure")


@dataclass
class FailOnceAfterGenesisAnchor(MemoryAnchor):
    failed: bool = False

    def store(self, ledger_id: str, tail: AuditTail) -> None:
        if tail.sequence == 1 and not self.failed:
            self.failed = True
            raise OSError("synthetic interrupted anchor update")
        super().store(ledger_id, tail)


def make_ledger(path: Path, anchor: MemoryAnchor) -> AuditLedger:
    return AuditLedger(
        path,
        ledger_id="action-log",
        integrity_key=KEY,
        anchor=anchor,
        clock=lambda: datetime(2026, 8, 3, 18, 0, tzinfo=UTC),
        event_id_factory=lambda: EVENT_ID,
    )


def append_started(ledger: AuditLedger) -> None:
    ledger.append(
        event_type="action.started",
        run_id=RUN_ID,
        proposal_digest=DIGEST_A,
        approval_digest=DIGEST_B,
        action_id=ACTION_ID,
        idempotency_key=DIGEST_B,
        mailbox_ref=MAILBOX_REF,
        target_ref=TARGET_REF,
        action_type="set_read_state",
    )


def test_append_is_canonical_redacted_and_verifiable(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    anchor = MemoryAnchor()
    ledger = make_ledger(path, anchor)

    append_started(ledger)

    ledger.verify()
    records = ledger.records()
    assert len(records) == 1
    assert records[0].event_type == "action.started"
    assert records[0].outcome_code is None
    assert ledger.state_for(DIGEST_B) == "action.started"
    assert anchor.value == AuditTail(1, records[0].mac)
    raw = path.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    assert "subject" not in raw.casefold()
    assert "sender" not in raw.casefold()
    assert "provider_id" not in raw.casefold()


def test_two_events_form_chain_and_report_latest_state(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    ledger = make_ledger(tmp_path / "actions.jsonl", anchor)
    append_started(ledger)
    ledger.append(
        event_type="action.succeeded",
        run_id=RUN_ID,
        proposal_digest=DIGEST_A,
        approval_digest=DIGEST_B,
        action_id=ACTION_ID,
        idempotency_key=DIGEST_B,
        mailbox_ref=MAILBOX_REF,
        target_ref=TARGET_REF,
        action_type="set_read_state",
        outcome_code="applied",
    )

    first, second = ledger.records()
    assert second.previous_mac == first.mac
    assert ledger.state_for(DIGEST_B) == "action.succeeded"


@pytest.mark.parametrize("tamper", ["edit", "reencode", "truncate", "insert"])
def test_tampering_fails_closed(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "actions.jsonl"
    anchor = MemoryAnchor()
    ledger = make_ledger(path, anchor)
    append_started(ledger)

    raw = path.read_bytes()
    if tamper == "edit":
        parsed = json.loads(raw)
        parsed["event_type"] = "action.failed"
        path.write_text(json.dumps(parsed) + "\n", encoding="utf-8")
    elif tamper == "reencode":
        path.write_bytes(raw.rstrip(b"\n") + b" \n")
    elif tamper == "truncate":
        path.write_bytes(b"")
    else:
        path.write_bytes(raw + raw)

    with pytest.raises(AuditIntegrityError):
        ledger.verify()


def test_missing_anchor_for_existing_log_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    anchor = MemoryAnchor()
    ledger = make_ledger(path, anchor)
    append_started(ledger)
    anchor.value = None

    with pytest.raises(AuditIntegrityError, match="no protected anchor"):
        ledger.verify()


def test_anchor_mismatch_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    anchor = MemoryAnchor()
    ledger = make_ledger(path, anchor)
    append_started(ledger)
    anchor.value = AuditTail(1, "f" * 64)

    with pytest.raises(AuditIntegrityError, match="protected anchor"):
        ledger.verify()


def test_anchor_store_unavailability_fails_closed(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path / "actions.jsonl", FailingStoreAnchor())

    with pytest.raises(AuditUnavailableError, match="initialize protected"):
        append_started(ledger)
    with pytest.raises(AuditUnavailableError, match="initialize protected"):
        ledger.verify()


def test_single_durable_append_repairs_interrupted_anchor_update(
    tmp_path: Path,
) -> None:
    path = tmp_path / "actions.jsonl"
    anchor = FailOnceAfterGenesisAnchor()
    ledger = make_ledger(path, anchor)

    with pytest.raises(AuditUnavailableError, match="advance protected"):
        append_started(ledger)

    ledger.verify()
    assert anchor.value is not None
    assert anchor.value.sequence == 1
    assert len(ledger.records()) == 1


@pytest.mark.parametrize("raw", [b"{not-json}\n", b"{}"])
def test_invalid_or_truncated_json_fails_closed(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "actions.jsonl"
    path.write_bytes(raw)
    ledger = make_ledger(path, MemoryAnchor())

    with pytest.raises(AuditIntegrityError):
        ledger.verify()


def test_existing_lock_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    path.with_name("actions.jsonl.lock").write_text("synthetic", encoding="ascii")
    ledger = make_ledger(path, MemoryAnchor())

    with pytest.raises(AuditUnavailableError, match="already locked"):
        ledger.verify()


def test_non_regular_ledger_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    path.mkdir()
    ledger = make_ledger(path, MemoryAnchor())

    with pytest.raises(AuditIntegrityError, match="not a regular file"):
        ledger.verify()


def test_dangling_ledger_symlink_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    try:
        path.symlink_to(tmp_path / "missing-target.jsonl")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    ledger = make_ledger(path, MemoryAnchor())

    with pytest.raises(AuditIntegrityError, match="not a regular file"):
        ledger.verify()


def test_private_values_cannot_enter_fixed_audit_fields(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path / "actions.jsonl", MemoryAnchor())

    with pytest.raises(ValueError, match="pseudonym"):
        ledger.append(
            event_type="action.started",
            run_id=RUN_ID,
            proposal_digest=DIGEST_A,
            approval_digest=DIGEST_B,
            action_id=ACTION_ID,
            idempotency_key=DIGEST_B,
            mailbox_ref="owner@example.invalid",
            target_ref=TARGET_REF,
            action_type="set_read_state",
        )


def test_short_integrity_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        AuditLedger(
            tmp_path / "actions.jsonl",
            ledger_id="action-log",
            integrity_key=b"short",
            anchor=MemoryAnchor(),
        )
