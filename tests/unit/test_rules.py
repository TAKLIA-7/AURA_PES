"""Unit tests for AURA deterministic rules."""

from __future__ import annotations

import pytest

from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    ResourceInfo,
    ResourceSensitivity,
    RiskLevel,
    RunContext,
    TaintState,
    ToolAction,
)
from aura.rbac import RBACManager
from aura.resources import ResourceRegistry
from aura.rules import (
    ConfidentialEgressRule,
    PermissionCheckRule,
    RateLimitRule,
    ResourceExistenceRule,
    TaintPropagationRule,
)


# ────────────────────────────────────────────────────────────────────
# PermissionCheckRule
# ────────────────────────────────────────────────────────────────────

class TestPermissionCheckRule:
    def test_admin_allowed(self, rbac_manager, admin_agent, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=rbac_manager)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "confidential/hr_records"},
            agent=admin_agent,
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.ALLOW
        assert result.reason_code == "PERMISSION_GRANTED"

    def test_reader_denied_send_email(self, rbac_manager, reader_agent, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=rbac_manager)
        req = make_request(
            action=ToolAction.SEND_EMAIL,
            params={"to": "someone@example.com", "body": "hi"},
            agent=reader_agent,
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK
        assert result.reason_code == "PERMISSION_DENIED"

    def test_analyst_allowed_read_internal(self, rbac_manager, analyst_agent, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=rbac_manager)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "internal/report_q4"},
            agent=analyst_agent,
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.ALLOW

    def test_analyst_denied_confidential(self, rbac_manager, analyst_agent, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=rbac_manager)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "confidential/hr_records"},
            agent=analyst_agent,
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK
        assert result.reason_code == "PERMISSION_DENIED"

    def test_unknown_agent_denied(self, rbac_manager, unknown_agent, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=rbac_manager)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=unknown_agent,
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK

    def test_rbac_not_configured(self, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=None)
        req = make_request()
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK
        assert result.reason_code == "RBAC_NOT_CONFIGURED"

    def test_role_mismatch_denied(self, rbac_manager, make_request, make_context):
        """Agent claims a role that doesn't match config — denied."""
        spoofed = AgentIdentity(agent_id="admin_agent", role="reader")
        rule = PermissionCheckRule(rbac_manager=rbac_manager)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=spoofed,
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK


# ────────────────────────────────────────────────────────────────────
# ResourceExistenceRule
# ────────────────────────────────────────────────────────────────────

class TestResourceExistenceRule:
    def test_resource_found(self, resource_registry, make_request, make_context):
        rule = ResourceExistenceRule(resource_registry=resource_registry)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.ALLOW
        assert result.reason_code == "RESOURCE_FOUND"
        # Check that resource_info was set on context.
        assert ctx.resource_info is not None
        assert ctx.resource_info.resource_id == "public/readme"

    def test_resource_not_found(self, resource_registry, make_request, make_context):
        rule = ResourceExistenceRule(resource_registry=resource_registry)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "nonexistent/file"},
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK
        assert result.reason_code == "RESOURCE_NOT_FOUND"

    def test_no_resource_id_skipped(self, resource_registry, make_request, make_context):
        rule = ResourceExistenceRule(resource_registry=resource_registry)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={},  # no doc_id
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        # Empty resource_id → rule not applicable.
        assert result is None

    def test_registry_not_configured(self, make_request, make_context):
        rule = ResourceExistenceRule(resource_registry=None)
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK
        assert result.reason_code == "REGISTRY_NOT_CONFIGURED"


# ────────────────────────────────────────────────────────────────────
# TaintPropagationRule
# ────────────────────────────────────────────────────────────────────

class TestTaintPropagationRule:
    def test_confidential_read_signals_taint(self, make_request, make_context):
        rule = TaintPropagationRule()
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "confidential/hr_records"},
        )
        ctx = make_context(
            request=req,
            resource_info=ResourceInfo(
                resource_id="confidential/hr_records",
                sensitivity=ResourceSensitivity.CONFIDENTIAL,
                resource_type="file",
            ),
        )
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.ALLOW
        assert result.reason_code == "TAINT_REQUIRED"
        assert result.risk_level == RiskLevel.MEDIUM

    def test_public_read_no_taint(self, make_request, make_context):
        rule = TaintPropagationRule()
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
        )
        ctx = make_context(
            request=req,
            resource_info=ResourceInfo(
                resource_id="public/readme",
                sensitivity=ResourceSensitivity.PUBLIC,
                resource_type="file",
            ),
        )
        result = rule.evaluate(req, ctx)
        assert result is None

    def test_non_read_skipped(self, make_request, make_context):
        rule = TaintPropagationRule()
        req = make_request(
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "hi"},
        )
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is None

    def test_no_resource_info_skipped(self, make_request, make_context):
        rule = TaintPropagationRule()
        req = make_request(action=ToolAction.READ_FILE, params={"doc_id": "x"})
        ctx = make_context(request=req, resource_info=None)
        result = rule.evaluate(req, ctx)
        assert result is None


# ────────────────────────────────────────────────────────────────────
# ConfidentialEgressRule
# ────────────────────────────────────────────────────────────────────

class TestConfidentialEgressRule:
    def test_tainted_send_email_blocked(self, make_request, make_context):
        rule = ConfidentialEgressRule()
        req = make_request(
            action=ToolAction.SEND_EMAIL,
            params={"to": "external@example.com", "body": "secret data"},
        )
        ctx = make_context(
            request=req,
            tainted=True,
            taint_source="confidential/hr_records",
            taint_level=ResourceSensitivity.CONFIDENTIAL,
        )
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK
        assert result.reason_code == "CONFIDENTIAL_EGRESS_BLOCKED"
        assert result.risk_level == RiskLevel.CRITICAL

    def test_tainted_call_api_blocked(self, make_request, make_context):
        rule = ConfidentialEgressRule()
        req = make_request(
            action=ToolAction.CALL_API,
            params={"op": "external_webhook"},
        )
        ctx = make_context(
            request=req,
            tainted=True,
            taint_source="confidential/financial_data",
            taint_level=ResourceSensitivity.CONFIDENTIAL,
        )
        result = rule.evaluate(req, ctx)
        assert result is not None
        assert result.decision == Decision.BLOCK

    def test_untainted_send_email_allowed(self, make_request, make_context):
        rule = ConfidentialEgressRule()
        req = make_request(
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "hello"},
        )
        ctx = make_context(request=req, tainted=False)
        result = rule.evaluate(req, ctx)
        assert result is None  # Not applicable — not tainted.

    def test_tainted_read_file_not_blocked(self, make_request, make_context):
        """Read actions are not egress — should not be blocked by this rule."""
        rule = ConfidentialEgressRule()
        req = make_request(
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
        )
        ctx = make_context(
            request=req,
            tainted=True,
            taint_source="confidential/hr_records",
            taint_level=ResourceSensitivity.CONFIDENTIAL,
        )
        result = rule.evaluate(req, ctx)
        assert result is None  # Read is not an egress action.


# ────────────────────────────────────────────────────────────────────
# RateLimitRule (stub)
# ────────────────────────────────────────────────────────────────────

class TestRateLimitRule:
    def test_stub_returns_none(self, make_request, make_context):
        rule = RateLimitRule()
        req = make_request()
        ctx = make_context(request=req)
        result = rule.evaluate(req, ctx)
        assert result is None  # Stub: not yet implemented.


# ────────────────────────────────────────────────────────────────────
# Rule disabled flag
# ────────────────────────────────────────────────────────────────────

class TestRuleEnabled:
    def test_disabled_rule(self, rbac_manager, make_request, make_context):
        rule = PermissionCheckRule(rbac_manager=rbac_manager, enabled=False)
        assert rule.enabled is False
