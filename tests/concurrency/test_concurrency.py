"""Concurrency, Idempotency, and Hash-Chain Verification Tests."""

import threading
import pytest
from aura.gateway import AuraGateway
from aura.models import Decision, ExecutionStatus, RunContext, ToolRequest


@pytest.fixture
def gateway(tmp_path):
    db_file = str(tmp_path / "test_concurrency.db")
    jsonl_file = str(tmp_path / "test_concurrency.jsonl")
    return AuraGateway(config_dir="config", db_path=db_file, jsonl_path=jsonl_file)


def test_idempotency_duplicate_detection(gateway):
    """Same idempotency key with same digest returns duplicate without re-executing."""
    gateway.tools.reset_all_counters()
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    req = ToolRequest(
        agent_id="research_agent",
        tool_name="read_file",
        parameters={"doc_id": "doc:public_report"},
        idempotency_key="unique_key_123",
    )

    res1 = gateway.handle(req, ctx)
    assert res1.decision == Decision.ALLOW
    assert gateway.tools.read_file.call_count == 1

    # Second request with identical key and parameters
    res2 = gateway.handle(req, ctx)
    assert res2.decision == Decision.ALLOW
    assert res2.reason_code == "IDEMPOTENT_DUPLICATE"
    # Call count should NOT increase!
    assert gateway.tools.read_file.call_count == 1


def test_idempotency_key_reuse_different_payload(gateway):
    """Same key with different payload must be rejected."""
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    req1 = ToolRequest(
        agent_id="research_agent",
        tool_name="read_file",
        parameters={"doc_id": "doc:public_report"},
        idempotency_key="key_conflict_test",
    )
    res1 = gateway.handle(req1, ctx)
    assert res1.decision == Decision.ALLOW

    # Different parameters with same key
    req2 = ToolRequest(
        agent_id="research_agent",
        tool_name="read_file",
        parameters={"doc_id": "doc:internal_memo"},
        idempotency_key="key_conflict_test",
    )
    res2 = gateway.handle(req2, ctx)
    assert res2.decision == Decision.BLOCK
    assert "IDEMPOTENCY_KEY_REUSED" in res2.reason_code


def test_audit_hash_chain_verification(gateway):
    """Ensure the cryptographic SHA-256 hash chain is tamper-evident and verifies cleanly."""
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    for i in range(5):
        req = ToolRequest(
            agent_id="research_agent",
            tool_name="read_file",
            parameters={"doc_id": "doc:public_report"},
        )
        gateway.handle(req, ctx)

    valid, err = gateway.audit.verify_integrity()
    assert valid is True
    assert err is None

