"""Unit tests for AuraStore (SQLite, WAL, Hash Chain, Idempotency)."""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aura.models import (
    AuditEntry,
    Decision,
    RiskLevel,
    ToolAction,
    compute_request_digest,
)
from aura.store import (
    GENESIS_HASH,
    AuraStore,
    IdempotencyConflictError,
)


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary SQLite database for testing."""
    db_file = tmp_path / "test_aura.db"
    store = AuraStore(db_file)
    yield store
    store.close()


def _make_dummy_entry(seq: int = 0, trace_id: str = "trace-1") -> AuditEntry:
    return AuditEntry(
        sequence_number=seq,
        request_id=f"req-{seq}",
        trace_id=trace_id,
        timestamp=datetime.now(timezone.utc),
        action=ToolAction.READ_FILE,
        agent_id="test_agent",
        agent_role="tester",
        decision=Decision.ALLOW,
        risk_level=RiskLevel.NONE,
        policy_version="1.0",
        rule_ids=["rbac_check"],
        reason_codes=["PERMISSION_GRANTED"],
        execution_status="success",
        safe_result_summary="Sample safe output",
    )


# ────────────────────────────────────────────────────────────────────
# Database Configuration & Initialization
# ────────────────────────────────────────────────────────────────────

class TestStoreInit:
    def test_sqlite_pragmas(self, temp_db):
        """Verify journal_mode is WAL and synchronous is FULL."""
        conn = temp_db._get_connection()
        cur = conn.cursor()

        cur.execute("PRAGMA journal_mode;")
        mode = cur.fetchone()[0]
        assert mode.lower() == "wal"

        cur.execute("PRAGMA synchronous;")
        sync = cur.fetchone()[0]
        # 2 = FULL in SQLite
        assert sync == 2

    def test_tables_created(self, temp_db):
        conn = temp_db._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cur.fetchall()}
        assert "audit_log" in tables
        assert "idempotency_records" in tables
        assert "approvals" in tables


# ────────────────────────────────────────────────────────────────────
# Hash Chain & Audit Operations
# ────────────────────────────────────────────────────────────────────

class TestAuditHashChain:
    def test_append_first_entry_links_genesis(self, temp_db):
        entry = _make_dummy_entry(0)
        appended = temp_db.append_audit_entry(entry)

        assert appended.sequence_number == 0
        assert appended.previous_hash == GENESIS_HASH
        assert len(appended.current_hash) == 64

    def test_append_sequential_chaining(self, temp_db):
        entry0 = temp_db.append_audit_entry(_make_dummy_entry(0))
        entry1 = temp_db.append_audit_entry(_make_dummy_entry(1))
        entry2 = temp_db.append_audit_entry(_make_dummy_entry(2))

        assert entry1.sequence_number == 1
        assert entry1.previous_hash == entry0.current_hash

        assert entry2.sequence_number == 2
        assert entry2.previous_hash == entry1.current_hash

        # Verify integrity passes
        is_valid, err = temp_db.verify_hash_chain()
        assert is_valid is True
        assert err is None

    def test_detect_modified_entry(self, temp_db):
        """Tampering with an existing entry's decision breaks hash chain verification."""
        temp_db.append_audit_entry(_make_dummy_entry(0))
        temp_db.append_audit_entry(_make_dummy_entry(1))
        temp_db.append_audit_entry(_make_dummy_entry(2))

        # Tamper directly in SQLite
        conn = temp_db._get_connection()
        with conn:
            conn.execute(
                "UPDATE audit_log SET decision = 'BLOCK' WHERE sequence_number = 1;"
            )

        is_valid, err = temp_db.verify_hash_chain()
        assert is_valid is False
        assert "Tampered content at sequence 1" in err

    def test_detect_deleted_entry(self, temp_db):
        """Deleting a row from the middle causes a sequence gap."""
        temp_db.append_audit_entry(_make_dummy_entry(0))
        temp_db.append_audit_entry(_make_dummy_entry(1))
        temp_db.append_audit_entry(_make_dummy_entry(2))

        # Delete row 1
        conn = temp_db._get_connection()
        with conn:
            conn.execute("DELETE FROM audit_log WHERE sequence_number = 1;")

        is_valid, err = temp_db.verify_hash_chain()
        assert is_valid is False
        assert "Sequence gap or reorder at index 1" in err

    def test_get_trace(self, temp_db):
        temp_db.append_audit_entry(_make_dummy_entry(0, trace_id="trace-A"))
        temp_db.append_audit_entry(_make_dummy_entry(1, trace_id="trace-B"))
        temp_db.append_audit_entry(_make_dummy_entry(2, trace_id="trace-A"))

        trace_a = temp_db.get_trace("trace-A")
        assert len(trace_a) == 2
        assert trace_a[0].sequence_number == 0
        assert trace_a[1].sequence_number == 2

    def test_export_jsonl(self, temp_db, tmp_path):
        temp_db.append_audit_entry(_make_dummy_entry(0))
        temp_db.append_audit_entry(_make_dummy_entry(1))

        export_file = tmp_path / "audit_export.jsonl"
        count = temp_db.export_jsonl(export_file)

        assert count == 2
        assert export_file.exists()
        lines = export_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2


# ────────────────────────────────────────────────────────────────────
# Caller-Scoped Idempotency
# ────────────────────────────────────────────────────────────────────

class TestIdempotency:
    def test_claim_new_key(self, temp_db):
        status, cached = temp_db.check_or_claim_idempotency(
            agent_id="agent-1",
            idempotency_key="key-001",
            canonical_digest="digest-abc",
            request_id="req-1",
        )
        assert status == "NEW"
        assert cached is None

    def test_in_progress_key(self, temp_db):
        temp_db.check_or_claim_idempotency(
            agent_id="agent-1",
            idempotency_key="key-002",
            canonical_digest="digest-abc",
            request_id="req-1",
        )
        # Second call with same key while still in progress
        status, cached = temp_db.check_or_claim_idempotency(
            agent_id="agent-1",
            idempotency_key="key-002",
            canonical_digest="digest-abc",
            request_id="req-2",
        )
        assert status == "IN_PROGRESS"
        assert cached is None

    def test_completed_key_returns_cached_result(self, temp_db):
        temp_db.check_or_claim_idempotency(
            agent_id="agent-1",
            idempotency_key="key-003",
            canonical_digest="digest-abc",
            request_id="req-1",
        )
        # Mark completed
        result_payload = {"status": "success", "data": 42}
        temp_db.complete_idempotency(
            agent_id="agent-1",
            idempotency_key="key-003",
            status="COMPLETED",
            result=result_payload,
        )

        # Subsequent check returns COMPLETED with cached payload
        status, cached = temp_db.check_or_claim_idempotency(
            agent_id="agent-1",
            idempotency_key="key-003",
            canonical_digest="digest-abc",
            request_id="req-3",
        )
        assert status == "COMPLETED"
        assert cached == result_payload

    def test_conflict_different_request_digest_rejected(self, temp_db):
        temp_db.check_or_claim_idempotency(
            agent_id="agent-1",
            idempotency_key="key-reuse",
            canonical_digest="digest-original",
            request_id="req-1",
        )

        with pytest.raises(IdempotencyConflictError):
            temp_db.check_or_claim_idempotency(
                agent_id="agent-1",
                idempotency_key="key-reuse",
                canonical_digest="digest-tampered-different",
                request_id="req-2",
            )

    def test_caller_scoping(self, temp_db):
        """Different agents can use the same idempotency key independently."""
        status1, _ = temp_db.check_or_claim_idempotency(
            agent_id="agent-A",
            idempotency_key="shared-key",
            canonical_digest="digest-A",
            request_id="req-1",
        )
        status2, _ = temp_db.check_or_claim_idempotency(
            agent_id="agent-B",
            idempotency_key="shared-key",
            canonical_digest="digest-B",
            request_id="req-2",
        )
        assert status1 == "NEW"
        assert status2 == "NEW"

