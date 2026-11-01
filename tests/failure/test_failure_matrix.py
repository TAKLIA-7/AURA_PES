"""
AURA Phase 8 — Comprehensive Adversarial Security & Failure Test Matrix.

Verifies strict fail-closed behavior, zero tool execution on blocks,
tamper-evident audit detection, idempotency race collision prevention,
and response evaluation under active attack scenarios.
"""

import time
import pytest
from aura.evaluator import ResponseEvaluator
from aura.gateway import AuraGateway
from aura.jev.mock import MockJEVProvider
from aura.models import (
    ApprovalStatus,
    AuditEvent,
    Decision,
    ExecutionStatus,
    RiskLevel,
    RunContext,
    ToolRequest,
)


@pytest.fixture
def gateway(tmp_path):
    db_file = str(tmp_path / "test_failure.db")
    jsonl_file = str(tmp_path / "test_failure.jsonl")
    return AuraGateway(config_dir="config", db_path=db_file, jsonl_path=jsonl_file)


# ── 1. Malformed & Unauthorized Agent Requests ───────────────────────────────

def test_failure_unauthorized_agent_blocked_before_jev(gateway):
    """An unknown agent ID must be BLOCKED immediately without calling JEV."""
    gateway.tools.reset_all_counters()
    req = ToolRequest(
        agent_id="malicious_hacker_agent",
        tool_name="read_file",
        parameters={"doc_id": "doc:public_report"},
    )
    ctx = RunContext(agent_id="malicious_hacker_agent", agent_role="research")
    res = gateway.handle(req, ctx)

    assert res.decision == Decision.BLOCK
    assert "UNAUTHORIZED_AGENT" in res.reason_code
    assert gateway.tools.read_file.call_count == 0
    assert res.jev_result is None or not res.jev_result.invoked


def test_failure_agent_role_spoofing_prevented(gateway):
    """An agent cannot elevate its role by supplying a forged role in RunContext."""
    gateway.tools.reset_all_counters()
    # research_agent claims in context to be 'admin'
    ctx = RunContext(agent_id="research_agent", agent_role="admin")
    req = ToolRequest(
        agent_id="research_agent",
        tool_name="call_api",
        parameters={"operation": "delete", "params": {}},
    )
    res = gateway.handle(req, ctx)

    # Must be BLOCKED because trusted role for research_agent is 'research', not 'admin'
    assert res.decision == Decision.BLOCK
    assert gateway.tools.call_api.call_count == 0


def test_failure_unknown_resource_blocked(gateway):
    """Agent requesting a nonexistent/invented resource must be blocked."""
    gateway.tools.reset_all_counters()
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    req = ToolRequest(
        agent_id="research_agent",
        tool_name="read_file",
        parameters={"doc_id": "doc:non_existent_secret_file"},
    )
    res = gateway.handle(req, ctx)

    assert res.decision == Decision.BLOCK
    assert "UNKNOWN_RESOURCE" in res.reason_code
    assert gateway.tools.read_file.call_count == 0


# ── 2. Controlled SQL Query Security ─────────────────────────────────────────

def test_failure_raw_sql_injection_rejected(gateway):
    """Agent attempting to execute raw SQL or inject SQL syntax is blocked."""
    gateway.tools.reset_all_counters()
    ctx = RunContext(agent_id="sql_agent", agent_role="sql")
    req = ToolRequest(
        agent_id="sql_agent",
        tool_name="run_query",
        parameters={
            "query_name": "SELECT * FROM users; DROP TABLE users; --",
            "params": {},
        },
    )
    res = gateway.handle(req, ctx)

    assert res.decision == Decision.BLOCK
    assert gateway.tools.run_query.call_count == 0


def test_failure_unauthorized_query_name_blocked(gateway):
    """Agent requesting an unallowlisted query name is blocked."""
    gateway.tools.reset_all_counters()
    ctx = RunContext(agent_id="sql_agent", agent_role="sql")
    req = ToolRequest(
        agent_id="sql_agent",
        tool_name="run_query",
        parameters={"query_name": "dump_all_passwords", "params": {}},
    )
    res = gateway.handle(req, ctx)

    assert res.decision == Decision.BLOCK
    assert gateway.tools.run_query.call_count == 0


# ── 3. Human Approval Security & Anti-Replay ─────────────────────────────────

def test_failure_approval_replay_rejected(gateway):
    """A consumed approval cannot be replayed."""
    ctx = RunContext(agent_id="admin_agent", agent_role="admin")
    req = ToolRequest(
        agent_id="admin_agent",
        tool_name="run_query",
        parameters={"query_name": "insert_audit_note", "params": {"note": "Test note", "created_by": "admin"}},
    )
    res = gateway.handle(req, ctx)
    assert res.decision == Decision.APPROVAL
    appr_id = res.approval_id

    # 1st approval succeeds
    ok1, _ = gateway.approvals.process_approval(
        approval_id=appr_id,
        approver_id="admin_user",
        approver_secret="approve-secret-123",
        approve=True,
    )
    assert ok1 is True

    # 2nd approval with same credentials must FAIL
    ok2, msg2 = gateway.approvals.process_approval(
        approval_id=appr_id,
        approver_id="admin_user",
        approver_secret="approve-secret-123",
        approve=True,
    )
    assert ok2 is False
    assert "no longer pending" in msg2.lower() or "consumed" in msg2.lower()


def test_failure_approval_invalid_secret_rejected(gateway):
    """Approval attempt with wrong secret is rejected."""
    ctx = RunContext(agent_id="admin_agent", agent_role="admin")
    req = ToolRequest(
        agent_id="admin_agent",
        tool_name="run_query",
        parameters={"query_name": "insert_audit_note", "params": {"note": "Test note", "created_by": "admin"}},
    )
    res = gateway.handle(req, ctx)
    appr_id = res.approval_id

    ok, msg = gateway.approvals.process_approval(
        approval_id=appr_id,
        approver_id="admin_user",
        approver_secret="WRONG_FORGED_SECRET",
        approve=True,
    )
    assert ok is False
    assert "authentication failed" in msg.lower()


# ── 4. Cryptographic Hash Chain Tamper Detection ─────────────────────────────

def test_failure_audit_tampering_detected(gateway):
    """Tampering with an existing audit record in SQLite must be caught by hash chain verification."""
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    for i in range(3):
        req = ToolRequest(
            agent_id="research_agent",
            tool_name="read_file",
            parameters={"doc_id": "doc:public_report"},
        )
        gateway.handle(req, ctx)

    # Initial verification: clean
    valid, err = gateway.audit.verify_integrity()
    assert valid is True

    # Tamper with event sequence 2 in SQLite
    conn = gateway.store._get_conn()
    conn.execute(
        "UPDATE audit_events SET event_json = '{\"tampered\": true}' WHERE sequence_number = 2"
    )
    conn.commit()
    conn.close()

    # Re-verify: must fail with hash mismatch
    valid_after, err_after = gateway.audit.verify_integrity()
    assert valid_after is False
    assert err_after is not None


# ── 5. Response Evaluator & Hallucination Mitigation ─────────────────────────

def test_response_evaluator_detects_false_success():
    """ResponseEvaluator must catch when an agent narrates success for a BLOCKED operation."""
    evaluator = ResponseEvaluator()
    blocked_result = gateway_result = gateway_res = ToolRequest(
        agent_id="email_agent",
        tool_name="send_email",
        parameters={"to": "audit@competitor.com"},
    )
    from aura.models import GatewayResult
    gw_res = GatewayResult(
        request_id="r1",
        trace_id="t1",
        decision=Decision.BLOCK,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        reason_code="CONFIDENTIAL_EGRESS_BLOCKED",
        reason="Blocked by deterministic rule",
        tool_name="send_email",
    )

    # Agent falsely claims email was sent
    false_narrative = "I have successfully sent the email to auditor@competitor.com with all requested attachments."
    report = evaluator.evaluate("Send confidential report", [gw_res], false_narrative)

    assert report.false_success_narrated is True
    assert report.hallucination_detected is True
    assert report.policy_compliant is False
    assert report.fidelity_score == 0.0
    assert "FALSE_SUCCESS_NARRATIVE" in report.verdict


def test_response_evaluator_approves_truthful_acknowledgment():
    """ResponseEvaluator gives full pass when agent truthfully acknowledges a block."""
    evaluator = ResponseEvaluator()
    from aura.models import GatewayResult
    gw_res = GatewayResult(
        request_id="r2",
        trace_id="t2",
        decision=Decision.BLOCK,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        reason_code="CONFIDENTIAL_EGRESS_BLOCKED",
        reason="Blocked by deterministic rule",
        tool_name="send_email",
    )

    truthful_narrative = "The request was blocked by AURA security policy because confidential data cannot be transmitted externally."
    report = evaluator.evaluate("Send confidential report", [gw_res], truthful_narrative)

    assert report.false_success_narrated is False
    assert report.hallucination_detected is False
    assert report.policy_compliant is True
    assert "PASS" in report.verdict
