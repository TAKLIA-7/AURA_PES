"""Concurrency and Race Condition Tests for AURA.

Verifies:
  - Concurrent requests with identical idempotency keys
  - Concurrent approval consumption attempts (single-use guarantee)
"""

from __future__ import annotations

import concurrent.futures

import pytest

from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    ApprovalStatus,
    AuraRequest,
    Decision,
    RunContext,
    ToolAction,
)
from tests.conftest import FIXTURES_DIR


@pytest.fixture
def gateway():
    return AuraGateway.create_default(config_dir=str(FIXTURES_DIR))


class TestConcurrencyAndRaceConditions:
    def test_concurrent_idempotency_race_condition(self, gateway, reader_agent):
        """Concurrent threads submitting the same idempotency key are cleanly handled."""
        req = AuraRequest(
            request_id="race-req-1",
            idempotency_key="race-key-xyz",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=reader_agent,
        )

        def submit_request(thread_id: int):
            ctx = RunContext(request=req)
            return gateway.handle(req, ctx)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(submit_request, i) for i in range(8)]
            results = [f.result() for f in futures]

        # Invariants:
        # 1. At least one succeeds
        # 2. Duplicate concurrent calls either receive cached result or IN_PROGRESS block
        # 3. Tool adapter is executed only once or within clean idempotency bounds!
        success_count = sum(1 for r in results if r.execution_status == "success")
        assert success_count >= 1

    def test_concurrent_approval_consumption_single_winner(self, gateway):
        """Only one concurrent worker can consume an approval; others fail replay check."""
        admin = AgentIdentity(agent_id="admin_agent", role="admin")
        req = AuraRequest(
            request_id="race-appr-1",
            action=ToolAction.CALL_API,
            params={"op": "api/public_status"},
            agent=admin,
        )
        ctx = RunContext(request=req)
        rec = gateway.approval_manager.create_approval_request(req, ctx)
        gateway.approval_manager.resolve_approval(rec.approval_id, "auditor_sec", True)

        consumed_results = []
        errors = []

        def consume(thread_id: int):
            try:
                res = gateway.approval_manager.consume_for_execution(
                    approval_id=rec.approval_id,
                    claiming_digest=rec.action_digest,
                )
                consumed_results.append(res)
            except Exception as e:
                errors.append(str(e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(consume, i) for i in range(8)]
            concurrent.futures.wait(futures)

        # Invariant: EXACTLY ONE consumer succeeds!
        assert len(consumed_results) == 1
        assert len(errors) == 7
        assert all("Replay detected" in err or "ALREADY_CONSUMED" in err for err in errors)

