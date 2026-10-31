"""Concurrency Stress Testing for AURA."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest

from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    RunContext,
    ToolAction,
)
from tests.conftest import FIXTURES_DIR


class TestConcurrencyStress:
    def test_high_concurrency_fast_path(self, tmp_path):
        """Stress test with 32 concurrent workers processing 320 requests."""
        db_path = tmp_path / "concurrent_stress.db"
        gw = AuraGateway.create_default(config_dir=str(FIXTURES_DIR), db_path=db_path)
        # Ensure high rate limit
        gw.rate_limiter.default_limit = 100000
        gw.rate_limiter.role_limits["admin"] = 100000

        admin = AgentIdentity(agent_id="admin_agent", role="admin")

        def task(i: int):
            req = AuraRequest(
                request_id=f"stress-{i}",
                action=ToolAction.READ_FILE,
                params={"doc_id": "public/readme"},
                agent=admin,
            )
            ctx = RunContext(request=req)
            return gw.handle(req, ctx)

        num_tasks = 320
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            futures = [executor.submit(task, i) for i in range(num_tasks)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == num_tasks
        assert all(r.decision == Decision.ALLOW for r in results)
        assert all(r.execution_status == "success" for r in results)

        # Invariant: Hash chain remains 100% verified under high concurrent load
        is_valid, err = gw.audit_logger.verify_integrity()
        assert is_valid is True
        assert err is None

        gw.store.close()

