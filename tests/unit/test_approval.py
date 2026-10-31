"""Unit tests for AURA Persistent Digest-Bound Approval System (Scenario 3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aura.approval import (
    ApprovalDigestMismatchError,
    ApprovalExpiredError,
    ApprovalManager,
    ApprovalReplayError,
    SelfApprovalError,
)
from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    ApprovalStatus,
    AuraRequest,
    Decision,
    RunContext,
    ToolAction,
)
from aura.store import AuraStore
from tests.conftest import FIXTURES_DIR


@pytest.fixture
def store(tmp_path):
    st = AuraStore(tmp_path / "test_approvals.db")
    yield st
    st.close()


@pytest.fixture
def approval_manager(store):
    return ApprovalManager(store)


@pytest.fixture
def gateway():
    return AuraGateway.create_default(config_dir=str(FIXTURES_DIR))


# ────────────────────────────────────────────────────────────────────
# ApprovalManager Unit Tests
# ────────────────────────────────────────────────────────────────────

class TestApprovalManager:
    def test_create_and_resolve_approval(self, approval_manager):
        agent = AgentIdentity(agent_id="agent_requester", role="analyst")
        req = AuraRequest(
            request_id="req-appr-1",
            action=ToolAction.CALL_API,
            params={"op": "api/internal_deploy"},
            agent=agent,
        )
        ctx = RunContext(request=req)

        rec = approval_manager.create_approval_request(req, ctx)
        assert rec.status == ApprovalStatus.PENDING
        assert rec.requester_agent_id == "agent_requester"
        assert rec.action_digest == req.canonical_digest()

        # Different agent approves
        resolved = approval_manager.resolve_approval(
            approval_id=rec.approval_id,
            approver_id="security_officer",
            approved=True,
        )
        assert resolved.status == ApprovalStatus.APPROVED
        assert resolved.approver_id == "security_officer"

    def test_self_approval_prevented(self, approval_manager):
        """Security Invariant: Requester is strictly forbidden from approving their own request."""
        agent = AgentIdentity(agent_id="agent_requester", role="analyst")
        req = AuraRequest(
            request_id="req-appr-2",
            action=ToolAction.CALL_API,
            params={"op": "api/internal_deploy"},
            agent=agent,
        )
        ctx = RunContext(request=req)
        rec = approval_manager.create_approval_request(req, ctx)

        with pytest.raises(SelfApprovalError):
            approval_manager.resolve_approval(
                approval_id=rec.approval_id,
                approver_id="agent_requester",  # Self-approval!
                approved=True,
            )

    def test_replay_prevention_on_consumption(self, approval_manager):
        """Security Invariant: Single-use consumption; replay is rejected."""
        agent = AgentIdentity(agent_id="agent_requester", role="analyst")
        req = AuraRequest(
            request_id="req-appr-3",
            action=ToolAction.CALL_API,
            params={"op": "api/internal_deploy"},
            agent=agent,
        )
        ctx = RunContext(request=req)
        rec = approval_manager.create_approval_request(req, ctx)

        # Approve
        approval_manager.resolve_approval(rec.approval_id, "admin_user", True)

        # First consumption claim succeeds
        consumed = approval_manager.consume_for_execution(
            approval_id=rec.approval_id,
            claiming_digest=rec.action_digest,
        )
        assert consumed.status == ApprovalStatus.CONSUMED

        # Second consumption claim fails with replay error
        with pytest.raises(ApprovalReplayError):
            approval_manager.consume_for_execution(
                approval_id=rec.approval_id,
                claiming_digest=rec.action_digest,
            )

    def test_digest_mismatch_rejected(self, approval_manager):
        """Security Invariant: Execution claim must match approved action digest."""
        agent = AgentIdentity(agent_id="agent_requester", role="analyst")
        req = AuraRequest(
            request_id="req-appr-4",
            action=ToolAction.CALL_API,
            params={"op": "api/internal_deploy"},
            agent=agent,
        )
        ctx = RunContext(request=req)
        rec = approval_manager.create_approval_request(req, ctx)
        approval_manager.resolve_approval(rec.approval_id, "admin_user", True)

        with pytest.raises(ApprovalDigestMismatchError):
            approval_manager.consume_for_execution(
                approval_id=rec.approval_id,
                claiming_digest="tampered_different_digest",
            )

    def test_expired_approval_rejected(self, approval_manager):
        """Security Invariant: Expired requests cannot be approved or consumed."""
        agent = AgentIdentity(agent_id="agent_requester", role="analyst")
        req = AuraRequest(
            request_id="req-appr-5",
            action=ToolAction.CALL_API,
            params={"op": "api/internal_deploy"},
            agent=agent,
        )
        ctx = RunContext(request=req)
        # 1-second TTL
        rec = approval_manager.create_approval_request(req, ctx, ttl_seconds=1)

        # Manually alter created_at to simulate expiration
        rec.created_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        approval_manager.store.save_approval(rec)

        with pytest.raises(ApprovalExpiredError):
            approval_manager.resolve_approval(rec.approval_id, "admin_user", True)


# ────────────────────────────────────────────────────────────────────
# Scenario 3: End-to-End Approval Lifecycle & Execution
# ────────────────────────────────────────────────────────────────────

class TestScenario3ApprovalLifecycle:
    def test_scenario3_sensitive_operation_approval_flow(self, gateway, admin_agent):
        """Scenario 3: Sensitive operation requires approval, digest/TTL/replay checks, atomic consumption, then execution."""
        api_adapter = gateway.tool_registry.get(ToolAction.CALL_API)
        api_adapter.reset_counter()

        requester = admin_agent
        approver_id = "compliance_manager"

        # Step 1: Requester proposes sensitive action that policy marks as APPROVAL
        # We simulate policy engine returning APPROVAL
        from aura.models import RuleResult
        from aura.policy import PolicyEngine
        from aura.rules import Rule

        class ApprovalRequiringRule(Rule):
            def evaluate(self, request, context):
                if request.action == ToolAction.CALL_API and request.params.get("op") == "api/internal_deploy":
                    return RuleResult(
                        rule_id="require_approval",
                        decision=Decision.APPROVAL,
                        reason_code="SENSITIVE_DEPLOY_OP",
                    )
                return None

        gateway.policy_engine._rules.insert(0, ApprovalRequiringRule("require_approval"))

        req = AuraRequest(
            request_id="scen3-req-1",
            action=ToolAction.CALL_API,
            params={"op": "api/internal_deploy"},
            agent=requester,
        )
        ctx = RunContext(request=req)

        # Gateway handles: outcomes in Decision.APPROVAL
        res = gateway.handle(req, ctx)
        assert res.decision == Decision.APPROVAL
        assert res.execution_status == "pending_approval"
        # Tool adapter NOT called
        assert api_adapter.call_count == 0

        # Extract approval_id from error message
        approval_id = res.error.split("approval_id=")[-1]

        # Step 2: Approver reviews and approves
        resolved_rec = gateway.approval_manager.resolve_approval(
            approval_id=approval_id,
            approver_id=approver_id,
            approved=True,
        )
        assert resolved_rec.status == ApprovalStatus.APPROVED

        # Step 3: Gateway executes the approved action
        exec_res = gateway.execute_approved_action(
            approval_id=approval_id,
            claiming_agent=requester,
            run_ctx=ctx,
        )

        assert exec_res.decision == Decision.ALLOW
        assert exec_res.execution_status == "success"
        # Tool executed exactly once!
        assert api_adapter.call_count == 1
        assert "api/internal_deploy" in api_adapter.called_ops

        # Step 4: Replay attempt fails and does not execute tool again
        replay_res = gateway.execute_approved_action(
            approval_id=approval_id,
            claiming_agent=requester,
            run_ctx=ctx,
        )
        assert replay_res.decision == Decision.BLOCK
        assert "APPROVAL_ALREADY_CONSUMED_REPLAY_REJECTED" in replay_res.error
        # Adapter count remains 1!
        assert api_adapter.call_count == 1
