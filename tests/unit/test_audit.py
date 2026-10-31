"""Unit tests for AuditLogger and payload sanitization."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aura.audit import AuditLogger, sanitize_summary
from aura.models import (
    AgentIdentity,
    AuraRequest,
    AuraResult,
    Decision,
    PolicyDecision,
    RiskLevel,
    RuleResult,
    RunContext,
    ToolAction,
)
from aura.store import AuraStore


@pytest.fixture
def store(tmp_path):
    st = AuraStore(tmp_path / "audit_test.db")
    yield st
    st.close()


@pytest.fixture
def audit_logger(store):
    return AuditLogger(store)


# ────────────────────────────────────────────────────────────────────
# Sanitization Tests
# ────────────────────────────────────────────────────────────────────

class TestSanitizeSummary:
    def test_masks_api_key(self):
        text = "Request failed with api_key=AIzaSyD1234567890abcdef"
        sanitized = sanitize_summary(text)
        assert "AIzaSyD1234567890abcdef" not in sanitized
        assert "***REDACTED***" in sanitized

    def test_masks_bearer_token(self):
        text = "Header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        sanitized = sanitize_summary(text)
        assert "eyJhbGci" not in sanitized
        assert "***REDACTED***" in sanitized

    def test_masks_password(self):
        text = "database error connecting with password='SuperSecretPassword123'"
        sanitized = sanitize_summary(text)
        assert "SuperSecretPassword123" not in sanitized
        assert "***REDACTED***" in sanitized

    def test_truncates_long_text(self):
        long_str = "x" * 500
        sanitized = sanitize_summary(long_str, max_len=100)
        assert len(sanitized) <= 125
        assert "[TRUNCATED]" in sanitized

    def test_none_returns_none(self):
        assert sanitize_summary(None) is None


# ────────────────────────────────────────────────────────────────────
# AuditLogger Operations
# ────────────────────────────────────────────────────────────────────

class TestAuditLogger:
    def test_log_operation_durable(self, audit_logger):
        agent = AgentIdentity(agent_id="test_ag", role="analyst")
        req = AuraRequest(
            request_id="req-audit-1",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=agent,
        )
        ctx = RunContext(request=req)
        result = AuraResult(
            request_id="req-audit-1",
            decision=Decision.ALLOW,
            risk_level=RiskLevel.NONE,
            policy_decision=PolicyDecision(
                decision=Decision.ALLOW,
                risk_level=RiskLevel.NONE,
                rule_results=[RuleResult(rule_id="r1", decision=Decision.ALLOW, reason_code="OK")],
                policy_version="1.0",
            ),
            execution_status="success",
            execution_result={"doc_id": "public/readme", "content": "Sensitive Payload Text"},
        )

        entry = audit_logger.log_operation(req, ctx, result, execution_duration_ms=12.5)

        assert entry.sequence_number == 0
        assert entry.request_id == "req-audit-1"
        assert entry.decision == Decision.ALLOW
        assert entry.execution_duration_ms == 12.5
        # Ensure full payload content is not leaked in summary
        assert "Sensitive Payload Text" not in entry.safe_result_summary
        assert "Dict with keys" in entry.safe_result_summary

        # Verify integrity
        is_valid, _ = audit_logger.verify_integrity()
        assert is_valid is True

    def test_get_trace(self, audit_logger):
        agent = AgentIdentity(agent_id="ag1", role="reader")
        req = AuraRequest(
            request_id="r1",
            trace_id="trace-xyz",
            action=ToolAction.READ_FILE,
            params={},
            agent=agent,
        )
        ctx = RunContext(request=req)
        result = AuraResult(request_id="r1", decision=Decision.ALLOW, risk_level=RiskLevel.NONE)

        audit_logger.log_operation(req, ctx, result)
        trace = audit_logger.get_trace("trace-xyz")
        assert len(trace) == 1
        assert trace[0].trace_id == "trace-xyz"

