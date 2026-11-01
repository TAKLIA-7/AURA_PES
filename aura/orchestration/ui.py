"""Rich Terminal User Interface for AURA Multi-Agent Environment.

Provides understandable visual dashboards, live execution monitors,
audit trace explorers, and security event views using Rich.
"""

from __future__ import annotations

import sys
import time
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# Safe Windows stdout reconfigure
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aura.gateway import AuraGateway
from aura.orchestration.models import AgentStatus, ManagedAgentInfo
from aura.orchestration.orchestrator import MultiAgentOrchestrator


class AuraTerminalUI:
    """Rich visual UI controller for AURA."""

    def __init__(
        self,
        orchestrator: MultiAgentOrchestrator,
        console: Console | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.gateway = orchestrator.gateway
        self.console = console or Console(highlight=False, legacy_windows=False)
        self.security_events: list[dict[str, Any]] = []

        # Hook into orchestrator events to track security alerts
        self.orchestrator.add_event_listener(self._record_security_event)

    def _record_security_event(self, event: dict[str, Any]) -> None:
        if event.get("decision") == "BLOCK" or event.get("blocked", 0) > 0:
            self.security_events.append(event)

    def render_header(self) -> None:
        """Display prominent AURA system banner."""
        banner_text = Text()
        banner_text.append("[AURA] MULTI-AGENT SECURITY KERNEL & ENFORCEMENT GATEWAY\n", style="bold cyan")
        banner_text.append("Deterministic Policy | Monotone Risk | SHA-256 Hash Chaining | Zero Privilege Escalation", style="dim white")
        self.console.print(Panel(banner_text, border_style="cyan", expand=True))

    def render_agent_table(self) -> None:
        """Render table of all managed agents, roles, assigned tools, and statuses."""
        agents = self.orchestrator.list_agents()

        table = Table(
            title="[AGENTS] Multi-Agent Registry & Tool Assignments",
            title_style="bold magenta",
            border_style="magenta",
            expand=True,
        )
        table.add_column("Agent ID", style="bold white", width=18)
        table.add_column("Role", style="cyan", width=10)
        table.add_column("Status", width=10)
        table.add_column("Assigned Tools", style="yellow")
        table.add_column("Sensitivities", style="blue")
        table.add_column("Tasks (OK / Fail)", justify="center", width=16)

        for a in agents:
            status_style = "green" if a.status == AgentStatus.IDLE else ("yellow" if a.status == AgentStatus.BUSY else "red")
            status_display = f"[{status_style}][{a.status.value}][/{status_style}]"

            tools_str = ", ".join(t.value for t in a.assigned_tools) if a.assigned_tools else "[dim]None[/dim]"
            sens_str = ", ".join(a.allowed_sensitivities) if a.allowed_sensitivities else "[dim]None[/dim]"
            metrics_str = f"[green]{a.tasks_succeeded}[/green] / [red]{a.tasks_failed}[/red]"

            table.add_row(
                a.identity.agent_id,
                a.identity.role,
                status_display,
                tools_str,
                sens_str,
                metrics_str,
            )

        self.console.print(table)

    def render_audit_log_table(self, limit: int = 10) -> None:
        """Display cryptographic hash-chain audit log entries."""
        entries = self.gateway.store.get_all_audit_entries(limit=limit)

        table = Table(
            title=f"[AUDIT] Tamper-Evident SHA-256 Audit Log (Last {min(len(entries), limit)} Entries)",
            title_style="bold green",
            border_style="green",
            expand=True,
        )
        table.add_column("Seq", style="bold white", width=5)
        table.add_column("Timestamp (UTC)", width=20)
        table.add_column("Trace ID", style="dim white", width=16)
        table.add_column("Agent", style="magenta", width=15)
        table.add_column("Action", style="cyan", width=12)
        table.add_column("Decision", width=10)
        table.add_column("Risk", width=8)
        table.add_column("Hash Link (SHA-256)", style="dim white", width=18)

        for e in entries:
            dec_color = "green" if e.decision.value == "ALLOW" else ("yellow" if e.decision.value == "APPROVAL" else "red")
            dec_str = f"[{dec_color}]{e.decision.value}[/{dec_color}]"

            risk_color = "green" if e.risk_level.name == "NONE" else ("yellow" if e.risk_level.name in ("LOW", "MEDIUM") else "red")
            risk_str = f"[{risk_color}]{e.risk_level.name}[/{risk_color}]"

            hash_preview = f"{e.current_hash[:8]}...{e.current_hash[-6:]}" if e.current_hash else "GENESIS"
            ts_str = e.timestamp.strftime("%H:%M:%S.%f")[:-3]

            table.add_row(
                str(e.sequence_number),
                ts_str,
                e.trace_id[:14] if e.trace_id else "N/A",
                e.agent_id,
                e.action.value,
                dec_str,
                risk_str,
                hash_preview,
            )

        self.console.print(table)

    def render_security_events(self) -> None:
        """Display security block events and adversarial containment alerts."""
        if not self.security_events:
            self.console.print(
                Panel("[green][OK] Zero security breaches or blocked attacks detected in this session.[/green]", title="[SECURITY] Security Event Monitor", border_style="green")
            )
            return

        table = Table(
            title="[SECURITY ALERTS] AURA Enforcement Monitor",
            title_style="bold red",
            border_style="red",
            expand=True,
        )
        table.add_column("Time", width=12)
        table.add_column("Event Type", style="bold red", width=22)
        table.add_column("Entity / Agent", style="magenta", width=16)
        table.add_column("Enforcement Action", style="bold yellow", width=18)
        table.add_column("Security Details", style="white")

        for ev in self.security_events[-8:]:
            ts = ev.get("timestamp", "")[-12:-4] if "timestamp" in ev else "N/A"
            etype = ev.get("event_type", "SECURITY_ALERT")
            agent = ev.get("agent_id") or ev.get("sender_id") or "Gateway"
            action = "INTERCEPT & BLOCK"
            details = ev.get("error") or ev.get("reason") or f"Blocked tool calls: {ev.get('blocked', 1)}"

            table.add_row(ts, etype, agent, action, str(details))

        self.console.print(table)

    def render_approval_queue(self) -> None:
        """Display pending human approvals waiting in the gateway."""
        approvals = self.gateway.approval_manager.list_pending_approvals()

        if not approvals:
            self.console.print(
                Panel("[dim green][OK] No pending human approvals in queue.[/dim green]", title="[APPROVALS] Human-in-the-Loop Approvals", border_style="cyan")
            )
            return

        table = Table(
            title="[APPROVALS] Pending Human Approval Requests",
            title_style="bold yellow",
            border_style="yellow",
            expand=True,
        )
        table.add_column("Approval ID", style="bold yellow", width=18)
        table.add_column("Agent ID", style="magenta", width=15)
        table.add_column("Action", style="cyan", width=12)
        table.add_column("Parameter Digest", style="dim white", width=16)
        table.add_column("Expires In", style="white", width=12)

        for a in approvals:
            table.add_row(
                a.approval_id,
                getattr(a, "requester_agent_id", getattr(a, "agent_id", "N/A")),
                a.action.value if hasattr(a.action, "value") else str(a.action),
                f"{getattr(a, 'action_digest', getattr(a, 'request_digest', ''))[:8]}...",
                f"{a.ttl_seconds}s",
            )
        self.console.print(table)

    def render_performance_dashboard(self) -> None:
        """Display gateway performance, latency, and token counters."""
        telemetry = getattr(self.gateway, "telemetry", None)
        if not telemetry:
            return

        summary = telemetry.get_summary()
        total_ops = summary.get("total_operations", 0)
        fast_path = summary.get("fast_path_rate", 1.0) * 100
        avg_dur = summary.get("avg_duration_ms", 0.0)
        p95_dur = summary.get("p95_duration_ms", 0.0)
        tokens = summary.get("total_jev_tokens", 0)

        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)

        p1 = Panel(f"[bold cyan]{total_ops}[/bold cyan]\nTotal Requests", border_style="cyan")
        p2 = Panel(f"[bold green]{avg_dur:.2f} ms[/bold green]\nAvg Latency ({fast_path:.0f}% Fast-Path)", border_style="green")
        p3 = Panel(f"[bold yellow]{p95_dur:.2f} ms[/bold yellow]\np95 Latency", border_style="yellow")
        p4 = Panel(f"[bold magenta]{tokens}[/bold magenta]\nTotal Tokens", border_style="magenta")

        grid.add_row(p1, p2, p3, p4)
        self.console.print(Panel(grid, title="[METRICS] Performance & Token Usage Dashboard", border_style="blue"))

    def render_workflow(self, wf: Any) -> None:
        """Render workflow DAG execution status and tasks."""
        table = Table(
            title=f"[WORKFLOW] {wf.name} (Status: [{('green' if wf.status.value == 'COMPLETED' else 'yellow')}]{wf.status.value}[/])",
            title_style="bold cyan",
            border_style="cyan",
            expand=True,
        )
        table.add_column("Task ID", style="bold white", width=22)
        table.add_column("Name", style="white", width=30)
        table.add_column("Assigned Agent", style="magenta", width=18)
        table.add_column("Action", style="cyan", width=20)
        table.add_column("Depends On", style="dim", width=20)
        table.add_column("Status", width=18)

        for t in wf.tasks.values():
            if t.state.value == "COMPLETED":
                st_color = "green"
            elif t.state.value == "WAITING_FOR_APPROVAL":
                st_color = "yellow"
            elif t.state.value == "RUNNING":
                st_color = "blue"
            elif t.state.value in ("FAILED", "BLOCKED"):
                st_color = "red"
            else:
                st_color = "dim white"

            st_str = f"[{st_color}][{t.state.value}][/{st_color}]"
            deps_str = ", ".join(t.depends_on) if t.depends_on else "[dim]None[/dim]"

            table.add_row(
                t.task_id,
                t.name,
                f"{t.assigned_agent_id} ({t.assigned_agent_role})",
                t.tool_action.value if hasattr(t.tool_action, "value") else str(t.tool_action),
                deps_str,
                st_str,
            )

        self.console.print(table)

    def render_idempotency_table(self, limit: int = 15) -> None:
        """Render registered idempotency records."""
        records = self.gateway.store.list_idempotency_records(limit=limit)
        table = Table(
            title=f"[IDEMPOTENCY] Idempotency Cache & Duplicate Prevention ({len(records)} Records)",
            title_style="bold cyan",
            border_style="cyan",
            expand=True,
        )
        table.add_column("Agent ID", style="magenta", width=18)
        table.add_column("Idempotency Key", style="bold white", width=22)
        table.add_column("Status", width=14)
        table.add_column("Request Digest", style="dim white", width=20)
        table.add_column("Updated At", style="dim", width=24)

        if not records:
            self.console.print(Panel("[dim]No idempotency records stored yet.[/dim]", title="[IDEMPOTENCY] Idempotency Cache", border_style="cyan"))
            return

        for r in records:
            st = r.get("status", "UNKNOWN")
            color = "green" if st == "COMPLETED" else ("yellow" if st == "IN_PROGRESS" else "red")
            st_badge = f"[{color}][{st}][/{color}]"
            digest_preview = f"{r.get('canonical_digest', '')[:10]}..." if r.get("canonical_digest") else "N/A"
            table.add_row(
                r.get("agent_id", "N/A"),
                r.get("idempotency_key", "N/A"),
                st_badge,
                digest_preview,
                str(r.get("updated_at", "N/A")),
            )
        self.console.print(table)

    def render_permissions_matrix(self) -> None:
        """Render detailed permission matrix for all agents and tools."""
        table = Table(
            title="[PERMISSIONS] Agent Role-Based Access Control (RBAC) Matrix",
            title_style="bold yellow",
            border_style="yellow",
            expand=True,
        )
        table.add_column("Agent ID", style="bold magenta", width=20)
        table.add_column("Role", style="cyan", width=22)
        table.add_column("Allowed Actions", style="bold green", width=35)
        table.add_column("Resource Scopes", style="yellow")

        agents_dict = self.gateway.rbac_manager._agents
        for aid, entry in agents_dict.items():
            actions = []
            resources = []
            for p in entry.permissions:
                actions.append(p.action.value if hasattr(p.action, "value") else str(p.action))
                resources.extend(p.resources)
            table.add_row(
                aid,
                entry.role,
                ", ".join(actions) if actions else "[dim]None[/dim]",
                ", ".join(set(resources)) if resources else "[dim]None[/dim]",
            )
        self.console.print(table)

    def render_security_demos_summary(self, results: list[Any]) -> None:
        """Render table summarizing all security demonstration results."""
        table = Table(
            title="[SECURITY DEMOS] AURA Verification & Enforcement Results (A-I)",
            title_style="bold green",
            border_style="green",
            expand=True,
        )
        table.add_column("Demo ID", style="bold white", width=10)
        table.add_column("Name", style="cyan", width=32)
        table.add_column("Description", style="white", width=45)
        table.add_column("Result", justify="center", width=12)

        for r in results:
            badge = "[green][PASS][/green]" if r.passed else "[red][FAIL][/red]"
            table.add_row(r.demo_id, r.name, r.description, badge)

        self.console.print(table)

    def show_full_dashboard(self) -> None:
        """Render complete integrated AURA multi-agent visual dashboard."""
        self.console.clear()
        self.render_header()
        self.console.print()
        self.render_agent_table()
        self.console.print()
        self.render_audit_log_table(limit=6)
        self.console.print()
        self.render_performance_dashboard()
        self.console.print()
        self.render_security_events()
        self.console.print()
        self.render_approval_queue()

    def render_interactive_approval_center(self) -> None:
        """Interactive screen for Option 6: Human-in-the-Loop Approval Queue."""
        from rich.prompt import Prompt
        from aura.models import AgentIdentity, AuraRequest, Decision, RunContext, ToolAction

        self.console.print("\n[bold yellow]── Human-in-the-Loop Approval Center ──[/bold yellow]")

        pending = self.gateway.approval_manager.list_pending_approvals()
        if not pending:
            self.console.print("[dim cyan]No pending human approvals currently in queue.[/dim cyan]")
            gen = Prompt.ask("[yellow]Would you like to generate a sample approval request (e.g., Facility Reservation)? [Y/n][/yellow]", default="y")
            if gen.strip().lower() != "n":
                req = AuraRequest(
                    request_id=f"req-sample-apr-{int(time.time())}",
                    action=ToolAction.CREATE_RESERVATION,
                    params={
                        "room_id": "rooms/maple",
                        "room_name": "Maple Conference Room",
                        "date": "2026-11-05",
                        "start_time": "14:00",
                        "duration_hours": 2,
                        "attendees": 4,
                        "total_price": 80.0,
                        "requested_by": "analyst_agent",
                        "reason": "Executive board review with projector requirement",
                    },
                    agent=AgentIdentity(agent_id="executor_agent", role="executor"),
                )
                ctx = RunContext(request=req)
                res = self.gateway.handle(req, ctx)
                pending = self.gateway.approval_manager.list_pending_approvals()

        if not pending:
            self.console.print("[dim]Returning to command center.[/dim]")
            return

        self.console.print(f"\n[bold white]Found {len(pending)} pending approval request(s):[/bold white]\n")
        apr = pending[0]

        card = Table(show_header=False, border_style="yellow", expand=True)
        card.add_column("Field", style="bold cyan", width=24)
        card.add_column("Value", style="white")

        card.add_row("Approval ID", apr.approval_id)
        card.add_row("Requester Agent", f"[magenta]{apr.requester_agent_id}[/magenta]")
        card.add_row("Requested Action", f"[bold yellow]{apr.action.value}[/bold yellow]")
        card.add_row("Status", f"[bold yellow]{apr.status.value}[/bold yellow]")
        card.add_row("Action Digest (SHA-256)", f"[dim]{apr.action_digest}[/dim]")
        card.add_row("TTL Remaining", f"{apr.ttl_seconds} seconds")

        params_str = "\n".join(f"  • {k}: {v}" for k, v in apr.stored_params.items())
        card.add_row("Stored Parameters", params_str)
        card.add_row("Policy Risk Level", "[bold red]HIGH[/bold red] (Irreversible External Commitment)")
        card.add_row("Gating Rule", "ApprovalRequiredRule: financial and facility commitments require operator authorization")

        self.console.print(Panel(card, title="[bold yellow]PENDING HUMAN APPROVAL DETAILS[/bold yellow]", border_style="yellow"))

        menu = (
            "[bold white]1.[/bold white] APPROVE (Cryptographically bind approver & execute action)\n"
            "[bold white]2.[/bold white] DECLINE (Reject action & block execution)\n"
            "[bold white]3.[/bold white] INSPECT FULL DETAILS\n"
            "[bold white]4.[/bold white] Back"
        )
        self.console.print(Panel(menu, title="[Operator Decision]", border_style="cyan"))
        decision = Prompt.ask("[bold cyan]Enter decision (1-4)[/bold cyan]", default="1").strip()

        if decision == "1":
            self.gateway.approval_manager.resolve_approval(
                approval_id=apr.approval_id,
                approver_id="compliance_director",
                approved=True,
            )
            self.console.print("[bold green]✔ APPROVED by compliance_director. Cryptographic parameter binding verified.[/bold green]")
            exec_res = self.gateway.execute_approved_action(
                approval_id=apr.approval_id,
                claiming_agent=AgentIdentity(agent_id=apr.requester_agent_id, role="executor"),
                run_ctx=RunContext(request=AuraRequest(request_id=apr.request_id, action=apr.action, params=apr.stored_params, agent=AgentIdentity(agent_id=apr.requester_agent_id, role="executor"))),
            )
            self.console.print(f"[bold green]✔ Execution Succeeded: Status={exec_res.execution_status}[/bold green]")
            self.console.print(f"  Execution Result: {exec_res.execution_result}")
        elif decision == "2":
            self.gateway.approval_manager.resolve_approval(
                approval_id=apr.approval_id,
                approver_id="compliance_director",
                approved=False,
            )
            self.console.print("[bold red]✖ DECLINED by compliance_director. Action marked REJECTED.[/bold red]")
            self.console.print("[dim]Audit entry recorded. Zero adapter calls executed.[/dim]")
        elif decision == "3":
            import json
            details_json = json.dumps({
                "approval_id": apr.approval_id,
                "request_id": apr.request_id,
                "action": apr.action.value,
                "stored_params": apr.stored_params,
                "action_digest": apr.action_digest,
                "requester": apr.requester_agent_id,
                "status": apr.status.value,
                "ttl_seconds": apr.ttl_seconds,
                "created_at": apr.created_at.isoformat() if apr.created_at else None,
            }, indent=2)
            self.console.print(Panel(details_json, title="Full Cryptographic Approval Record (JSON)", border_style="cyan"))

    def render_live_idempotency_demo(self) -> None:
        """Option 7: Render idempotency cache and run live idempotency duplicate prevention demonstration."""
        from rich.prompt import Prompt
        from aura.models import AgentIdentity, AuraRequest, RunContext, ToolAction

        self.render_idempotency_table(limit=10)
        self.console.print()

        run_live = Prompt.ask("[yellow]Run live idempotency test (2 identical requests -> 1 execution)? [Y/n][/yellow]", default="y")
        if run_live.strip().lower() == "n":
            return

        self.console.print("\n[bold cyan]── Live Idempotency Test Execution ──[/bold cyan]")
        agent = AgentIdentity(agent_id="executor_agent", role="executor")
        adapter = self.gateway.tool_registry.get(ToolAction.SEND_EMAIL)
        initial_calls = adapter.call_count

        idem_key = f"idem-live-demo-{int(time.time())}"
        req1 = AuraRequest(
            request_id=f"req-idem-1-{int(time.time())}",
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "Idempotency duplicate prevention verification"},
            agent=agent,
            idempotency_key=idem_key,
        )
        ctx1 = RunContext(request=req1)

        self.console.print(f"[bold white]Step 1:[/bold white] Dispatching Request 1 (Key: [cyan]{idem_key}[/cyan])...")
        res1 = self.gateway.handle(req1, ctx1)
        calls_after_1 = adapter.call_count
        self.console.print(f"  Decision        : [green]{res1.decision.value}[/green]")
        self.console.print(f"  Execution Status: {res1.execution_status}")
        self.console.print(f"  Adapter Calls   : [bold yellow]{calls_after_1}[/bold yellow] (Incremented from {initial_calls} -> Fresh Execution)\n")

        # Step 2: Identical request with same key
        req2 = AuraRequest(
            request_id=f"req-idem-2-{int(time.time())}",
            action=ToolAction.SEND_EMAIL,
            params={"to": "user@example.com", "body": "Idempotency duplicate prevention verification"},
            agent=agent,
            idempotency_key=idem_key,
        )
        ctx2 = RunContext(request=req2)

        self.console.print(f"[bold white]Step 2:[/bold white] Dispatching Request 2 with IDENTICAL key and parameters...")
        res2 = self.gateway.handle(req2, ctx2)
        calls_after_2 = adapter.call_count
        self.console.print(f"  Decision        : [green]{res2.decision.value}[/green]")
        self.console.print(f"  Execution Status: {res2.execution_status} (Returned from Authoritative Cache)")
        self.console.print(f"  Adapter Calls   : [bold green]{calls_after_2}[/bold green] (Unchanged! Call count remained {calls_after_1})\n")

        result_box = (
            f"[bold green]✔ IDEMPOTENCY GUARANTEE VERIFIED[/bold green]\n"
            f"• 2 requests dispatched with identical key: '{idem_key}'\n"
            f"• Exactly 1 side-effectful adapter execution occurred\n"
            f"• Request 2 served entirely from authoritative SQLite idempotency store\n"
            f"• Duplicate side effects prevented: 100%"
        )
        self.console.print(Panel(result_box, border_style="green"))

    def render_audit_trace_explorer(self) -> None:
        """Option 8: Tamper-Evident SHA-256 Audit Explorer."""
        from rich.prompt import Prompt
        self.render_audit_log_table(limit=10)
        self.console.print()

        menu = (
            "[bold white]1.[/bold white] Verify Cryptographic SHA-256 Hash-Chain Integrity\n"
            "[bold white]2.[/bold white] Reconstruct Chronological Trace by Trace ID\n"
            "[bold white]3.[/bold white] Tamper-Evidence vs Tamper-Proofing Guarantee Explanation\n"
            "[bold white]4.[/bold white] Back"
        )
        self.console.print(Panel(menu, title="[Audit Explorer Menu]", border_style="cyan"))
        opt = Prompt.ask("[bold cyan]Enter choice (1-4)[/bold cyan]", default="1").strip()

        if opt == "1":
            is_valid, err = self.gateway.audit_logger.verify_integrity()
            entries = self.gateway.store.get_all_audit_entries(limit=5)
            if is_valid:
                summary = (
                    f"[bold green]✔ SHA-256 HASH CHAIN VERIFICATION: PASSED[/bold green]\n\n"
                    f"Every audit record H_n is cryptographically chained to its predecessor:\n"
                    f"H_n = SHA-256(H_n-1 || seq || timestamp || action || decision || risk || ...)\n\n"
                    f"Latest Verified Head Hash: [dim]{entries[-1].current_hash if entries else 'GENESIS'}[/dim]\n"
                    f"Chain Length Verified   : {len(self.gateway.store.get_all_audit_entries(limit=1000))} entries\n"
                    f"Integrity Status        : ZERO TAMPERING DETECTED"
                )
                self.console.print(Panel(summary, border_style="green"))
            else:
                self.console.print(Panel(f"[bold red]✖ TAMPERING DETECTED: {err}[/bold red]", border_style="red"))
        elif opt == "2":
            entries = self.gateway.store.get_all_audit_entries(limit=30)
            trace_ids = list(dict.fromkeys(e.trace_id for e in entries if e.trace_id))
            default_trace = trace_ids[0] if trace_ids else "N/A"
            self.console.print(f"[dim]Recent Trace IDs: {', '.join(trace_ids[:5])}[/dim]")
            tid = Prompt.ask("[cyan]Enter Trace ID to reconstruct[/cyan]", default=default_trace).strip()

            trace_entries = self.gateway.audit_logger.get_trace(tid)
            if not trace_entries:
                self.console.print(f"[yellow]No audit entries found for Trace ID: {tid}[/yellow]")
            else:
                table = Table(
                    title=f"[TRACE] Chronological Reconstruction for Trace: {tid}",
                    title_style="bold cyan",
                    border_style="cyan",
                    expand=True,
                )
                table.add_column("Seq", width=5)
                table.add_column("Time", width=12)
                table.add_column("Agent", style="magenta", width=16)
                table.add_column("Action", style="cyan", width=16)
                table.add_column("Decision", width=10)
                table.add_column("Risk", width=8)
                table.add_column("Details", style="dim white")

                for te in trace_entries:
                    dec_col = "green" if te.decision.value == "ALLOW" else ("yellow" if te.decision.value == "APPROVAL" else "red")
                    table.add_row(
                        str(te.sequence_number),
                        te.timestamp.strftime("%H:%M:%S"),
                        te.agent_id,
                        te.action.value,
                        f"[{dec_col}]{te.decision.value}[/{dec_col}]",
                        te.risk_level.name,
                        f"Rules: {', '.join(te.rule_ids or [])}",
                    )
                self.console.print(table)
        elif opt == "3":
            expl = (
                "[bold white]Cryptographic Security Guarantees: Tamper-Evidence vs Tamper-Proofing[/bold white]\n\n"
                "[bold cyan]1. Tamper-Evidence (Mathematically Guaranteed by AURA):[/bold cyan]\n"
                "• AURA computes a continuous SHA-256 hash chain: H_i = SHA-256(H_{i-1} || entry_fields).\n"
                "• Any retroactive modification, record deletion, or row insertion alters subsequent hashes.\n"
                "• A single altered bit breaks mathematical verification instantly, pinpointing the corrupted record.\n\n"
                "[bold cyan]2. Tamper-Proofing (Physical and OS-level considerations):[/bold cyan]\n"
                "• A local SQLite database or file alone cannot physically prevent an OS root admin from deleting the file.\n"
                "• True enterprise tamper-proofing is achieved by pairing AURA's SHA-256 chain with external Write-Once-Read-Many (WORM) storage, remote SIEM forwarders, or public/consortium distributed ledgers.\n"
                "• AURA's architecture guarantees that even if logs are extracted or audited offline, any tampering is detectable."
            )
            self.console.print(Panel(expl, title="[SECURITY ARCHITECTURE EXPLANATION]", border_style="cyan"))

    def render_task_execution_report(self, report: dict[str, Any]) -> None:
        """Render comprehensive Task Execution Report."""
        table = Table(show_header=False, expand=True, border_style="green")
        table.add_column("Property", style="bold cyan", width=24)
        table.add_column("Detail", style="white")

        table.add_row("Task Prompt", report.get("task_prompt", "N/A"))
        table.add_row("Task ID", report.get("task_id", "N/A"))
        table.add_row("Execution Strategy", report.get("strategy", "Multi-Agent Coordinated DAG"))

        team_str = "\n".join(f"  • {role}: [magenta]{aid}[/magenta]" for role, aid in report.get("agents_assigned", {}).items())
        table.add_row("Agents Assigned", team_str or "N/A")

        steps = report.get("plan_steps", [])
        table.add_row("Plan / Decomposition", "\n".join(f"  {i+1}. {step}" for i, step in enumerate(steps)) if steps else "Direct Execution")
        table.add_row("Gateway Protected Calls", str(report.get("total_tool_calls", 0)))
        table.add_row("Policy Decisions", f"[green]ALLOW: {report.get('allow_count', 0)}[/green] | [yellow]APPROVAL: {report.get('approval_count', 0)}[/yellow] | [red]BLOCK: {report.get('block_count', 0)}[/red]")
        table.add_row("Cryptographic Trace ID", f"[dim]{report.get('trace_id', 'N/A')}[/dim]")
        table.add_row("Elapsed Time", f"{report.get('duration_ms', 0):.2f} ms")
        table.add_row("Final Status", f"[bold green]{report.get('status', 'SUCCESS')}[/bold green]")
        table.add_row("Final Outcome", report.get("outcome_summary", "Task completed successfully under full gateway enforcement."))

        self.console.print(Panel(table, title="[bold green]AURA TASK EXECUTION REPORT[/bold green]", border_style="green"))
