"""Unit tests for Real JEV Providers (Gemini, OpenRouter, Structured Schema)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from aura.jev.gemini import GeminiJEVProvider
from aura.jev.openrouter import OpenRouterJEVProvider
from aura.jev.schema import JEVStructuredResponse
from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    RiskLevel,
    RunContext,
    ToolAction,
)


# ────────────────────────────────────────────────────────────────────
# Cross-Field Consistency Tests for JEVStructuredResponse
# ────────────────────────────────────────────────────────────────────

class TestJEVStructuredResponse:
    def test_valid_allow(self):
        resp = JEVStructuredResponse(
            decision=Decision.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="Read is benign",
            findings="No sensitive leakage",
            confidence_score=0.95,
        )
        assert resp.decision == Decision.ALLOW
        assert resp.risk_level == RiskLevel.LOW

    def test_valid_block(self):
        resp = JEVStructuredResponse(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            reason="Exfiltration detected",
            findings="Direct credential send",
            confidence_score=0.99,
        )
        assert resp.decision == Decision.BLOCK

    def test_inconsistent_critical_risk_with_allow_fails(self):
        """Cross-field check: CRITICAL risk cannot have ALLOW decision."""
        with pytest.raises(ValidationError, match="risk is CRITICAL but decision is 'ALLOW'"):
            JEVStructuredResponse(
                decision=Decision.ALLOW,
                risk_level=RiskLevel.CRITICAL,
                reason="Inconsistent",
                findings="test",
                confidence_score=0.9,
            )

    def test_inconsistent_block_with_none_risk_fails(self):
        """Cross-field check: BLOCK cannot have NONE risk."""
        with pytest.raises(ValidationError, match="decision is BLOCK but risk level is 'NONE'"):
            JEVStructuredResponse(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.NONE,
                reason="Inconsistent",
                findings="test",
                confidence_score=0.9,
            )

    def test_inconsistent_allow_with_high_risk_fails(self):
        """Cross-field check: ALLOW cannot have HIGH risk."""
        with pytest.raises(ValidationError, match="decision is ALLOW but risk level is 'HIGH'"):
            JEVStructuredResponse(
                decision=Decision.ALLOW,
                risk_level=RiskLevel.HIGH,
                reason="Inconsistent",
                findings="test",
                confidence_score=0.9,
            )


# ────────────────────────────────────────────────────────────────────
# GeminiJEVProvider Tests
# ────────────────────────────────────────────────────────────────────

class TestGeminiJEVProvider:
    def test_missing_api_key_fails_closed(self):
        """In production, missing key fails closed without falling back to mock."""
        provider = GeminiJEVProvider(api_key="")
        req = AuraRequest(
            request_id="r1",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=AgentIdentity(agent_id="ag1", role="reader"),
        )
        ctx = RunContext(request=req)

        result = provider.evaluate(req, ctx)
        assert result.decision == Decision.BLOCK
        assert "JEV_UNAVAILABLE" in (result.error or "")

    def test_context_cap_exceeded_fails_closed(self):
        """Payload exceeding hard context cap (1500 chars) fails closed."""
        provider = GeminiJEVProvider(api_key="fake-key-for-test")
        req = AuraRequest(
            request_id="r2",
            action=ToolAction.READ_FILE,
            params={"doc_id": "a" * 2000},  # Oversized context!
            agent=AgentIdentity(agent_id="ag1", role="reader"),
        )
        ctx = RunContext(request=req)

        result = provider.evaluate(req, ctx)
        assert result.decision == Decision.BLOCK
        assert "CONTEXT_CAP_EXCEEDED" in (result.error or "")

    @patch("google.genai.Client")
    def test_successful_gemini_evaluation(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_resp = MagicMock()
        mock_resp.text = json.dumps({
            "decision": "BLOCK",
            "risk_level": 3,  # HIGH
            "reason": "Exfiltration risk",
            "findings": "External unverified email send",
            "confidence_score": 0.94,
        })
        mock_resp.usage_metadata.total_token_count = 120
        mock_client.models.generate_content.return_value = mock_resp

        provider = GeminiJEVProvider(api_key="valid-test-key")
        req = AuraRequest(
            request_id="r3",
            action=ToolAction.SEND_EMAIL,
            params={"to": "external@evil.com", "body": "some text"},
            agent=AgentIdentity(agent_id="ag1", role="mailer"),
        )
        ctx = RunContext(request=req)

        result = provider.evaluate(req, ctx)
        assert result.decision == Decision.BLOCK
        assert result.risk_level == RiskLevel.HIGH
        assert result.token_usage == 120
        assert "Exfiltration risk" in result.findings
        assert result.error is None


# ────────────────────────────────────────────────────────────────────
# OpenRouterJEVProvider Tests
# ────────────────────────────────────────────────────────────────────

class TestOpenRouterJEVProvider:
    def test_missing_api_key_fails_closed(self):
        provider = OpenRouterJEVProvider(api_key="")
        req = AuraRequest(
            request_id="r4",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=AgentIdentity(agent_id="ag1", role="reader"),
        )
        ctx = RunContext(request=req)

        result = provider.evaluate(req, ctx)
        assert result.decision == Decision.BLOCK
        assert "JEV_UNAVAILABLE" in (result.error or "")

    @patch("httpx.Client.post")
    def test_openrouter_timeout_fails_closed(self, mock_post):
        mock_post.side_effect = Exception("Connection timed out after 5000ms")

        provider = OpenRouterJEVProvider(api_key="openrouter-test-key")
        req = AuraRequest(
            request_id="r5",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=AgentIdentity(agent_id="ag1", role="reader"),
        )
        ctx = RunContext(request=req)

        result = provider.evaluate(req, ctx, timeout_seconds=0.01)
        assert result.decision == Decision.BLOCK
        assert "JEV_ERROR" in (result.error or "") or "JEV_TIMEOUT" in (result.error or "")

