"""Unit tests for AURA Pydantic domain models."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from aura.models import (
    AgentIdentity,
    ApprovalRecord,
    ApprovalStatus,
    AuditEntry,
    AuraRequest,
    AuraResult,
    Decision,
    JEVResult,
    PolicyDecision,
    ResourceInfo,
    ResourceSensitivity,
    RiskLevel,
    RuleResult,
    RunContext,
    TaintState,
    ToolAction,
    compute_request_digest,
)


# ────────────────────────────────────────────────────────────────────
# Decision enum
# ────────────────────────────────────────────────────────────────────

class TestDecision:
    def test_values(self):
        assert set(Decision) == {
            Decision.BLOCK, Decision.ALLOW, Decision.APPROVAL, Decision.DEFER,
        }

    def test_string_comparison(self):
        assert Decision.BLOCK == "BLOCK"
        assert Decision.ALLOW == "ALLOW"


# ────────────────────────────────────────────────────────────────────
# RiskLevel enum
# ────────────────────────────────────────────────────────────────────

class TestRiskLevel:
    def test_ordering(self):
        assert RiskLevel.NONE < RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH < RiskLevel.CRITICAL

    def test_monotone_max(self):
        """Risk combines monotonically via max()."""
        assert max(RiskLevel.LOW, RiskLevel.HIGH) == RiskLevel.HIGH
        assert max(RiskLevel.CRITICAL, RiskLevel.NONE) == RiskLevel.CRITICAL

    def test_int_values(self):
        assert int(RiskLevel.NONE) == 0
        assert int(RiskLevel.CRITICAL) == 4


# ────────────────────────────────────────────────────────────────────
# ToolAction enum
# ────────────────────────────────────────────────────────────────────

class TestToolAction:
    def test_all_actions(self):
        assert set(ToolAction) == {
            ToolAction.READ_FILE, ToolAction.SEND_EMAIL,
            ToolAction.RUN_QUERY, ToolAction.CALL_API,
        }

    def test_values(self):
        assert ToolAction.READ_FILE.value == "read_file"
        assert ToolAction.SEND_EMAIL.value == "send_email"


# ────────────────────────────────────────────────────────────────────
# AgentIdentity
# ────────────────────────────────────────────────────────────────────

class TestAgentIdentity:
    def test_valid(self):
        agent = AgentIdentity(agent_id="agent-1", role="admin")
        assert agent.agent_id == "agent-1"
        assert agent.role == "admin"

    def test_rejects_empty_agent_id(self):
        with pytest.raises(ValidationError):
            AgentIdentity(agent_id="", role="admin")

    def test_rejects_empty_role(self):
        with pytest.raises(ValidationError):
            AgentIdentity(agent_id="agent-1", role="")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValidationError):
            AgentIdentity(agent_id="   ", role="admin")

    def test_serialization_roundtrip(self):
        agent = AgentIdentity(agent_id="agent-1", role="analyst")
        data = agent.model_dump()
        restored = AgentIdentity.model_validate(data)
        assert restored == agent


# ────────────────────────────────────────────────────────────────────
# ResourceInfo
# ────────────────────────────────────────────────────────────────────

class TestResourceInfo:
    def test_valid(self):
        info = ResourceInfo(
            resource_id="public/readme",
            sensitivity=ResourceSensitivity.PUBLIC,
            resource_type="file",
        )
        assert info.exists is True
        assert info.sensitivity == ResourceSensitivity.PUBLIC

    def test_rejects_empty_resource_id(self):
        with pytest.raises(ValidationError):
            ResourceInfo(
                resource_id="",
                sensitivity=ResourceSensitivity.PUBLIC,
                resource_type="file",
            )

    def test_sensitivity_values(self):
        for level in ResourceSensitivity:
            info = ResourceInfo(
                resource_id=f"test/{level.value}",
                sensitivity=level,
                resource_type="file",
            )
            assert info.sensitivity == level


# ────────────────────────────────────────────────────────────────────
# TaintState
# ────────────────────────────────────────────────────────────────────

class TestTaintState:
    def test_default_untainted(self):
        taint = TaintState()
        assert taint.tainted is False
        assert taint.taint_source is None

    def test_apply_taint(self):
        taint = TaintState()
        new_taint = taint.apply_taint(
            source="confidential/hr_records",
            reason="read confidential file",
            level=ResourceSensitivity.CONFIDENTIAL,
        )
        assert new_taint.tainted is True
        assert new_taint.taint_source == "confidential/hr_records"
        assert new_taint.taint_level == ResourceSensitivity.CONFIDENTIAL

    def test_taint_is_monotonic(self):
        """Taint at CONFIDENTIAL is not overridden by INTERNAL."""
        taint = TaintState(
            tainted=True,
            taint_source="secret",
            taint_reason="read secret",
            taint_level=ResourceSensitivity.CONFIDENTIAL,
        )
        new_taint = taint.apply_taint(
            source="other",
            reason="read internal",
            level=ResourceSensitivity.INTERNAL,
        )
        # Should keep the higher taint level.
        assert new_taint.taint_level == ResourceSensitivity.CONFIDENTIAL
        assert new_taint.taint_source == "secret"

    def test_taint_escalates(self):
        """INTERNAL taint can be escalated to RESTRICTED."""
        taint = TaintState(
            tainted=True,
            taint_source="internal",
            taint_reason="read internal",
            taint_level=ResourceSensitivity.INTERNAL,
        )
        new_taint = taint.apply_taint(
            source="restricted",
            reason="read restricted",
            level=ResourceSensitivity.RESTRICTED,
        )
        assert new_taint.taint_level == ResourceSensitivity.RESTRICTED
        assert new_taint.taint_source == "restricted"


# ────────────────────────────────────────────────────────────────────
# AuraRequest
# ────────────────────────────────────────────────────────────────────

class TestAuraRequest:
    def test_valid_request(self):
        req = AuraRequest(
            request_id="req-001",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=AgentIdentity(agent_id="agent-1", role="reader"),
        )
        assert req.request_id == "req-001"
        assert req.action == ToolAction.READ_FILE
        assert req.trace_id == "req-001"  # defaults to request_id

    def test_custom_trace_id(self):
        req = AuraRequest(
            request_id="req-001",
            trace_id="trace-abc",
            action=ToolAction.READ_FILE,
            params={},
            agent=AgentIdentity(agent_id="agent-1", role="reader"),
        )
        assert req.trace_id == "trace-abc"

    def test_rejects_empty_request_id(self):
        with pytest.raises(ValidationError):
            AuraRequest(
                request_id="",
                action=ToolAction.READ_FILE,
                params={},
                agent=AgentIdentity(agent_id="agent-1", role="reader"),
            )

    def test_canonical_digest_deterministic(self):
        """Same inputs produce the same digest."""
        req1 = AuraRequest(
            request_id="req-1",
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "hello"},
            agent=AgentIdentity(agent_id="agent-1", role="mailer"),
        )
        req2 = AuraRequest(
            request_id="req-2",  # different request_id
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "hello"},
            agent=AgentIdentity(agent_id="agent-1", role="mailer"),
        )
        assert req1.canonical_digest() == req2.canonical_digest()

    def test_canonical_digest_differs_on_params(self):
        req1 = AuraRequest(
            request_id="req-1",
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "hello"},
            agent=AgentIdentity(agent_id="agent-1", role="mailer"),
        )
        req2 = AuraRequest(
            request_id="req-1",
            action=ToolAction.SEND_EMAIL,
            params={"to": "other@example.com", "body": "hello"},
            agent=AgentIdentity(agent_id="agent-1", role="mailer"),
        )
        assert req1.canonical_digest() != req2.canonical_digest()

    def test_has_timestamp(self):
        req = AuraRequest(
            request_id="req-1",
            action=ToolAction.READ_FILE,
            params={},
            agent=AgentIdentity(agent_id="a", role="r"),
        )
        assert isinstance(req.timestamp, datetime)


# ────────────────────────────────────────────────────────────────────
# RunContext
# ────────────────────────────────────────────────────────────────────

class TestRunContext:
    def test_defaults(self, make_request):
        req = make_request()
        ctx = RunContext(request=req)
        assert ctx.taint.tainted is False
        assert ctx.step_count == 0
        assert ctx.max_steps == 8
        assert ctx.max_duration_seconds == 60.0
        assert ctx.resource_info is None


# ────────────────────────────────────────────────────────────────────
# RuleResult & PolicyDecision
# ────────────────────────────────────────────────────────────────────

class TestRuleResult:
    def test_valid(self):
        rr = RuleResult(
            rule_id="test_rule",
            decision=Decision.ALLOW,
            reason_code="TEST_ALLOW",
        )
        assert rr.risk_level == RiskLevel.NONE

    def test_rejects_empty_rule_id(self):
        with pytest.raises(ValidationError):
            RuleResult(rule_id="", decision=Decision.ALLOW, reason_code="X")

    def test_rejects_empty_reason_code(self):
        with pytest.raises(ValidationError):
            RuleResult(rule_id="rule", decision=Decision.ALLOW, reason_code="")


class TestPolicyDecision:
    def test_with_rule_results(self):
        pd = PolicyDecision(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.HIGH,
            rule_results=[
                RuleResult(rule_id="r1", decision=Decision.BLOCK, reason_code="DENIED"),
            ],
            policy_version="1.0",
            deciding_rule_id="r1",
            reason_code="DENIED",
        )
        assert pd.decision == Decision.BLOCK
        assert len(pd.rule_results) == 1


# ────────────────────────────────────────────────────────────────────
# JEVResult
# ────────────────────────────────────────────────────────────────────

class TestJEVResult:
    def test_defaults(self):
        jev = JEVResult()
        assert jev.decision == Decision.DEFER
        assert jev.risk_level == RiskLevel.NONE
        assert jev.error is None


# ────────────────────────────────────────────────────────────────────
# AuraResult
# ────────────────────────────────────────────────────────────────────

class TestAuraResult:
    def test_blocked_result(self):
        result = AuraResult(
            request_id="req-1",
            decision=Decision.BLOCK,
            risk_level=RiskLevel.HIGH,
            execution_status="blocked",
        )
        assert result.decision == Decision.BLOCK
        assert result.execution_result is None


# ────────────────────────────────────────────────────────────────────
# AuditEntry hash chain
# ────────────────────────────────────────────────────────────────────

class TestAuditEntry:
    def _make_entry(self, seq: int) -> AuditEntry:
        return AuditEntry(
            sequence_number=seq,
            request_id=f"req-{seq}",
            trace_id=f"trace-{seq}",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            action=ToolAction.READ_FILE,
            agent_id="agent-1",
            agent_role="reader",
            decision=Decision.ALLOW,
            risk_level=RiskLevel.NONE,
            policy_version="1.0",
        )

    def test_hash_deterministic(self):
        entry = self._make_entry(0)
        h1 = entry.compute_hash("")
        h2 = entry.compute_hash("")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_hash_chain(self):
        entry1 = self._make_entry(0)
        h1 = entry1.compute_hash("")
        entry2 = self._make_entry(1)
        h2 = entry2.compute_hash(h1)
        assert h1 != h2

    def test_hash_changes_on_tamper(self):
        entry = self._make_entry(0)
        h_original = entry.compute_hash("")
        # "Tamper" by changing the decision.
        tampered = entry.model_copy(update={"decision": Decision.BLOCK})
        h_tampered = tampered.compute_hash("")
        assert h_original != h_tampered

    def test_rejects_negative_sequence(self):
        with pytest.raises(ValidationError):
            AuditEntry(
                sequence_number=-1,
                request_id="r",
                trace_id="t",
                timestamp=datetime.now(timezone.utc),
                action=ToolAction.READ_FILE,
                agent_id="a",
                agent_role="r",
                decision=Decision.ALLOW,
                risk_level=RiskLevel.NONE,
            )


# ────────────────────────────────────────────────────────────────────
# ApprovalRecord
# ────────────────────────────────────────────────────────────────────

class TestApprovalRecord:
    def test_defaults(self):
        approval = ApprovalRecord(
            approval_id="apr-001",
            request_id="req-001",
            action_digest="abc123",
            requester_agent_id="agent-1",
        )
        assert approval.status == ApprovalStatus.PENDING
        assert approval.ttl_seconds == 3600

    def test_rejects_zero_ttl(self):
        with pytest.raises(ValidationError):
            ApprovalRecord(
                approval_id="apr-001",
                request_id="req-001",
                action_digest="abc123",
                requester_agent_id="agent-1",
                ttl_seconds=0,
            )


# ────────────────────────────────────────────────────────────────────
# compute_request_digest utility
# ────────────────────────────────────────────────────────────────────

class TestComputeRequestDigest:
    def test_deterministic(self):
        d1 = compute_request_digest("read_file", {"doc_id": "x"}, "agent-1")
        d2 = compute_request_digest("read_file", {"doc_id": "x"}, "agent-1")
        assert d1 == d2

    def test_differs_on_action(self):
        d1 = compute_request_digest("read_file", {"doc_id": "x"}, "agent-1")
        d2 = compute_request_digest("send_email", {"doc_id": "x"}, "agent-1")
        assert d1 != d2

    def test_differs_on_agent(self):
        d1 = compute_request_digest("read_file", {"doc_id": "x"}, "agent-1")
        d2 = compute_request_digest("read_file", {"doc_id": "x"}, "agent-2")
        assert d1 != d2

    def test_param_order_independent(self):
        """JSON sort_keys ensures determinism regardless of dict order."""
        d1 = compute_request_digest("send_email", {"to": "a", "body": "b"}, "ag")
        d2 = compute_request_digest("send_email", {"body": "b", "to": "a"}, "ag")
        assert d1 == d2

