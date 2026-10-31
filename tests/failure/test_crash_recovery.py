"""Crash Recovery and Storage Failure Tests for AURA."""

from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    RunContext,
    ToolAction,
)
from aura.store import AuraStore
from tests.conftest import FIXTURES_DIR


class TestCrashRecovery:
    def test_store_crash_recovery_integrity(self, tmp_path):
        """Simulate abrupt shutdown, re-open database, and verify hash-chain integrity."""
        db_path = tmp_path / "crash_recovery.db"

        # 1. First run: record several operations
        gw1 = AuraGateway.create_default(config_dir=str(FIXTURES_DIR), db_path=db_path)
        reader = AgentIdentity(agent_id="reader_agent", role="reader")

        for i in range(5):
            req = AuraRequest(
                request_id=f"crash-req-{i}",
                action=ToolAction.READ_FILE,
                params={"doc_id": "public/readme"},
                agent=reader,
            )
            res = gw1.handle(req, RunContext(request=req))
            assert res.decision == Decision.ALLOW

        # 2. Simulate abrupt process termination (close connection without clean shutdown)
        gw1.store.close()

        # 3. Re-open gateway with the same persisted database
        gw2 = AuraGateway.create_default(config_dir=str(FIXTURES_DIR), db_path=db_path)

        # Invariant: Tamper-evident hash chain remains intact across restarts!
        is_valid, err = gw2.audit_logger.verify_integrity()
        assert is_valid is True
        assert err is None

        # Verify next sequence number continues smoothly from 5
        seq, _ = gw2.store.get_latest_hash()
        assert seq == 4  # 0 to 4 = 5 entries

        # Append next entry
        req_next = AuraRequest(
            request_id="crash-req-next",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=reader,
        )
        res_next = gw2.handle(req_next, RunContext(request=req_next))
        assert res_next.decision == Decision.ALLOW

        seq_after, _ = gw2.store.get_latest_hash()
        assert seq_after == 5

        gw2.store.close()

    def test_transient_sqlite_lock_fails_closed(self, tmp_path):
        """When SQLite encounters an unrecoverable disk/lock error, gateway refuses execution."""
        db_path = tmp_path / "locked.db"
        gw = AuraGateway.create_default(config_dir=str(FIXTURES_DIR), db_path=db_path)
        reader = AgentIdentity(agent_id="reader_agent", role="reader")

        req = AuraRequest(
            request_id="lock-req-1",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=reader,
        )

        with patch.object(gw.store, "append_audit_entry", side_effect=sqlite3.OperationalError("database is locked")):
            res = gw.handle(req, RunContext(request=req))
            assert res.decision == Decision.BLOCK
            assert "DURABLE_AUDIT_WRITE_FAILED" in (res.error or "")

        gw.store.close()

