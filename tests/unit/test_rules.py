"""Unit tests for AURA deterministic policy rules."""

import pytest
from aura.models import Decision, RiskLevel, RunContext, ToolRequest
from aura.policy import PolicyEngine


@pytest.fixture
def policy_engine():
    return PolicyEngine(config_path="config/policy.yaml")


def test_rule_agent_auth_unauthorized(policy_engine):
    """Unknown agent must be blocked immediately."""
    req = ToolRequest(agent_id="malicious_intruder_agent", tool_name="read_file", parameters={"doc_id": "doc:public_report"})
    ctx = RunContext(agent_id="malicious_intruder_agent", agent_role="research")
    res = policy_engine.evaluate(req, ctx)
    assert res.final_decision == Decision.BLOCK
    assert any(r.reason_code == "UNAUTHORIZED_AGENT" for r in res.rule_results)


def test_rule_resource_access_unknown_resource(policy_engine):
    """Unknown resource ID must be blocked."""
    req = ToolRequest(agent_id="research_agent", tool_name="read_file", parameters={"doc_id": "doc:non_existent_file"})
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    res = policy_engine.evaluate(req, ctx)
    assert res.final_decision == Decision.BLOCK
    assert any(r.reason_code == "UNKNOWN_RESOURCE" for r in res.rule_results)


def test_rule_confidential_egress_blocks_tainted_data(policy_engine):
    """Tainted context attempting email to external recipient must be blocked before JEV."""
    req = ToolRequest(
        agent_id="email_agent",
        tool_name="send_email",
        parameters={"to": "external@competitor.com", "subject": "Leak", "body": "Secret"},
    )
    ctx = RunContext(agent_id="email_agent", agent_role="email", tainted=True, confidential_data_accessed=True)
    res = policy_engine.evaluate(req, ctx)
    assert res.final_decision == Decision.BLOCK
    assert any(r.reason_code == "CONFIDENTIAL_EGRESS_BLOCKED" for r in res.rule_results)


def test_rule_destination_restrict_blocked_domain(policy_engine):
    """Destination on blocked list must be blocked."""
    req = ToolRequest(
        agent_id="email_agent",
        tool_name="send_email",
        parameters={"to": "bad@competitor.com", "subject": "Test", "body": "Hello"},
    )
    ctx = RunContext(agent_id="email_agent", agent_role="email")
    res = policy_engine.evaluate(req, ctx)
    assert res.final_decision == Decision.BLOCK
    assert any(r.reason_code == "BLOCKED_DESTINATION" for r in res.rule_results)


def test_rule_execution_constraints_oversized_payload(policy_engine):
    """Oversized parameter must trigger constraint block."""
    oversized = "A" * 15000  # max_param_value_length is 10000
    req = ToolRequest(
        agent_id="research_agent",
        tool_name="read_file",
        parameters={"doc_id": "doc:public_report", "extra_param": oversized},
    )
    ctx = RunContext(agent_id="research_agent", agent_role="research")
    res = policy_engine.evaluate(req, ctx)
    assert res.final_decision == Decision.BLOCK
    assert any(r.reason_code in ("REQUEST_TOO_LARGE", "PARAMETER_VALUE_TOO_LONG") for r in res.rule_results)


def test_jev_high_risk_escalates_to_approval(policy_engine):
    """When JEV assesses risk as HIGH, the policy must escalate to APPROVAL."""
    from aura.models import JEVAssessment, JEVResult, PolicyResult
    
    # A deferred policy result
    initial_policy = PolicyResult(
        final_decision=Decision.DEFER,
        final_risk_level=RiskLevel.MEDIUM,
        requires_jev=True,
    )
    # JEV marks HIGH risk
    jev_result = JEVResult(
        invoked=True,
        assessment=JEVAssessment(
            risk_level=RiskLevel.HIGH,
            findings=["Ambiguous external data transfer detected"],
            recommendation=Decision.APPROVAL,
            confidence=0.9,
            reasoning="Requires human authorization",
        ),
    )
    combined = policy_engine.combine_with_jev(initial_policy, jev_result)
    assert combined.final_decision == Decision.APPROVAL
    assert combined.requires_approval is True
    assert combined.final_risk_level == RiskLevel.HIGH
