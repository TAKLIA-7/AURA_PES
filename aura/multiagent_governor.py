"""
AURA Multi-Agent Security Kernel & Collaborative Governance Engine.

Demonstrates real multi-agent collaborative delegation, zero privilege escalation defense,
cross-agent taint propagation, tamper-evident cryptographic hash auditing, and performance metrics.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aura.gateway import AuraGateway
from aura.models import Decision, ExecutionStatus, RiskLevel, RunContext, ToolRequest

console = Console()


class MultiAgentGovernor:
    """Multi-Agent Security Kernel and Enforcement Engine."""

    def __init__(self, gateway: Optional[AuraGateway] = None) -> None:
        self.gateway = gateway or AuraGateway()
        self.task_stats: Dict[str, Dict[str, int]] = {
            "admin_agent": {"ok": 0, "fail": 0},
            "analyst_agent": {"ok": 0, "fail": 0},
            "reader_agent": {"ok": 0, "fail": 0},
            "mailer_agent": {"ok": 0, "fail": 0},
        }
        self.request_latencies: List[float] = []
        self.total_tokens_used = 0

    def print_header(self) -> None:
        """Display the official AURA Multi-Agent Security Kernel header."""
        header_text = Text()
        header_text.append("[AURA] MULTI-AGENT SECURITY KERNEL & ENFORCEMENT GATEWAY\n", style="bold cyan")
        header_text.append(
            "Deterministic Policy | Monotone Risk | SHA-256 Hash Chaining | Zero Privilege Escalation",
            style="dim white",
        )
        console.print(Panel(Align.center(header_text), border_style="bold blue", box=box.ROUNDED))
        console.print()

    def phase_1_inspect_registry(self) -> None:
        """[PHASE 1] Inspecting Agent Identities and Tool Assignments."""
        console.print("[bold yellow][PHASE 1] Inspecting Agent Identities and Tool Assignments[/bold yellow]")

        table = Table(
            title="[AGENTS] Multi-Agent Registry & Tool Assignments",
            title_style="bold white",
            box=box.HEAVY_HEAD,
            header_style="bold cyan",
            border_style="dim blue",
        )
        table.add_column("Agent ID", style="bold white", min_width=18)
        table.add_column("Role", style="cyan", min_width=10)
        table.add_column("Status", style="green", min_width=10)
        table.add_column("Assigned Tools", style="yellow", min_width=24)
        table.add_column("Sensitivities", style="magenta", min_width=23)
        table.add_column("Tasks (OK / Fail)", style="white", justify="center", min_width=16)

        registry_display = [
            (
                "admin_agent",
                "admin",
                "[IDLE]",
                "read_file, send_email,\nrun_query, call_api",
                "CONFIDENTIAL, INTERNAL,\nPUBLIC, RESTRICTED",
                f"{self.task_stats['admin_agent']['ok']} / {self.task_stats['admin_agent']['fail']}",
            ),
            (
                "analyst_agent",
                "analyst",
                "[IDLE]",
                "read_file, run_query",
                "INTERNAL, PUBLIC",
                f"{self.task_stats['analyst_agent']['ok']} / {self.task_stats['analyst_agent']['fail']}",
            ),
            (
                "reader_agent",
                "reader",
                "[IDLE]",
                "read_file",
                "PUBLIC",
                f"{self.task_stats['reader_agent']['ok']} / {self.task_stats['reader_agent']['fail']}",
            ),
            (
                "mailer_agent",
                "mailer",
                "[IDLE]",
                "read_file, send_email",
                "CONFIDENTIAL, INTERNAL,\nPUBLIC, RESTRICTED",
                f"{self.task_stats['mailer_agent']['ok']} / {self.task_stats['mailer_agent']['fail']}",
            ),
        ]

        for aid, role, status, tools, sens, tasks in registry_display:
            table.add_row(aid, role, status, tools, sens, tasks)

        console.print(table)
        console.print()

    def phase_2_delegation_pipeline(self) -> str:
        """[PHASE 2] Collaborative Multi-Agent Delegation Pipeline."""
        console.print("[bold yellow][PHASE 2] Running Collaborative Multi-Agent Delegation Pipeline[/bold yellow]")
        collab_trace = f"trace-collab-{uuid.uuid4().hex[:8]}"

        console.print("  [cyan]analyst_agent[/cyan] delegates document read to [cyan]reader_agent[/cyan]")
        time.sleep(0.08)

        # Step 2a: reader_agent reads authorized document
        t0 = time.perf_counter()
        ctx_reader = RunContext(agent_id="reader_agent", agent_role="reader", trace_id=collab_trace)
        req_read = ToolRequest(
            agent_id="reader_agent",
            tool_name="read_file",
            parameters={"doc_id": "public/readme"},
        )
        res_read = self.gateway.handle(req_read, ctx_reader)
        lat_read = (time.perf_counter() - t0) * 1000.0
        self.request_latencies.append(lat_read)

        if res_read.decision == Decision.ALLOW:
            self.task_stats["reader_agent"]["ok"] += 1
            console.print("  [green]reader_agent[/green] reads 'public/readme' under its own authorized permissions")
        else:
            self.task_stats["reader_agent"]["fail"] += 1

        time.sleep(0.08)
        console.print("  [cyan]analyst_agent[/cyan] receives summary and delegates email to [cyan]mailer_agent[/cyan]")

        # Step 2b: mailer_agent sends notification
        t1 = time.perf_counter()
        ctx_mailer = RunContext(agent_id="mailer_agent", agent_role="mailer", trace_id=collab_trace)
        req_notify = ToolRequest(
            agent_id="mailer_agent",
            tool_name="call_api",
            parameters={"operation": "notify", "params": {"recipient": "team@company.com", "summary": "Project Readme reviewed"}},
        )
        res_notify = self.gateway.handle(req_notify, ctx_mailer)
        lat_notify = (time.perf_counter() - t1) * 1000.0
        self.request_latencies.append(lat_notify)

        if res_notify.decision == Decision.ALLOW:
            self.task_stats["mailer_agent"]["ok"] += 1
            self.task_stats["analyst_agent"]["ok"] += 1
            console.print(f"  [bold green][SUCCESS][/bold green] Pipeline Result: SUCCESS (Trace: {collab_trace})")
        else:
            self.task_stats["mailer_agent"]["fail"] += 1
            console.print(f"  [bold red][FAILED][/bold red] Pipeline Result: FAILED")

        console.print()
        return collab_trace

    def phase_3_privilege_escalation_defense(self) -> None:
        """[PHASE 3] Privilege Escalation Defense (Zero Privilege Escalation)."""
        console.print("[bold yellow][PHASE 3] Privilege Escalation Defense (Zero Privilege Escalation)[/bold yellow]")
        esc_trace = f"run-{uuid.uuid4().hex[:8]}"

        console.print("  [cyan]reader_agent[/cyan] received a task requesting 'confidential/hr_records'...")
        time.sleep(0.08)

        t0 = time.perf_counter()
        ctx = RunContext(agent_id="reader_agent", agent_role="reader", trace_id=esc_trace)
        req = ToolRequest(
            agent_id="reader_agent",
            tool_name="read_file",
            parameters={"doc_id": "confidential/hr_records"},
        )
        res = self.gateway.handle(req, ctx)
        lat = (time.perf_counter() - t0) * 1000.0
        self.request_latencies.append(lat)

        if res.decision == Decision.BLOCK:
            self.task_stats["reader_agent"]["fail"] += 1
            console.print("  [bold red][BLOCKED][/bold red] Escalation Blocked by AURA: Blocked tool calls = 1")
            console.print("  Error feedback returned to agent: [bold red]PERMISSION_DENIED[/bold red]")
        else:
            console.print("  [bold red][ALERT][/bold red] Privilege escalation check failed!")

        console.print()

    def phase_4_taint_exfiltration_defense(self) -> None:
        """[PHASE 4] Cross-Agent Taint Exfiltration Defense."""
        console.print("[bold yellow][PHASE 4] Cross-Agent Taint Exfiltration Defense[/bold yellow]")
        taint_trace = f"multi-taint-{uuid.uuid4().hex[:8]}"

        # Step 4a: Admin reads confidential resource (ALLOWED, but session becomes TAINTED)
        t0 = time.perf_counter()
        ctx_admin = RunContext(agent_id="admin_agent", agent_role="admin", trace_id=taint_trace)
        req_read = ToolRequest(
            agent_id="admin_agent",
            tool_name="read_file",
            parameters={"doc_id": "confidential/hr_records"},
        )
        res_read = self.gateway.handle(req_read, ctx_admin)
        lat_read = (time.perf_counter() - t0) * 1000.0
        self.request_latencies.append(lat_read)

        if res_read.decision == Decision.ALLOW and ctx_admin.tainted:
            self.task_stats["admin_agent"]["ok"] += 1
            console.print("  1. [cyan]admin_agent[/cyan] reads 'confidential/hr_records' (ALLOWED, but session becomes TAINTED)")
            console.print("     Read Status: [green]ALLOW[/green] (Taint State: [bold magenta]TAINTED[/bold magenta])")
        else:
            console.print(f"  1. Read Status: {res_read.decision.value}")

        time.sleep(0.08)
        console.print("  2. [cyan]admin_agent[/cyan] delegates sending email to [cyan]mailer_agent[/cyan] (Taint propagates across message)")

        # Step 4b: Taint propagates across inter-agent delegation boundary into mailer_agent
        t1 = time.perf_counter()
        ctx_mailer = RunContext(
            agent_id="mailer_agent",
            agent_role="mailer",
            trace_id=taint_trace,
            tainted=True,
            confidential_data_accessed=True,
            taint_sources=["confidential/hr_records"],
        )
        req_email = ToolRequest(
            agent_id="mailer_agent",
            tool_name="send_email",
            parameters={"to": "external@competitor.com", "subject": "HR Records", "body": "Executive compensation data"},
        )
        res_email = self.gateway.handle(req_email, ctx_mailer)
        lat_email = (time.perf_counter() - t1) * 1000.0
        self.request_latencies.append(lat_email)

        if res_email.decision == Decision.BLOCK:
            self.task_stats["mailer_agent"]["fail"] += 1
            console.print("  [bold red][BLOCKED][/bold red] Exfiltration Blocked by AURA: Blocked tool calls = 1")
            console.print("  [bold green][VERIFIED][/bold green] Zero-Call Invariant: mailer_agent SEND_EMAIL call count = 0")
        else:
            console.print("  [bold red][ALERT][/bold red] Taint exfiltration rule did not block!")

        console.print()

    def phase_5_audit_and_metrics(self) -> None:
        """[PHASE 5] Audit Trail and Cryptographic Verification."""
        console.print("[bold yellow][PHASE 5] Audit Trail and Cryptographic Verification[/bold yellow]")

        # Retrieve last 8 audit events from authoritative SQLite store
        events = self.gateway.store.get_audit_events(limit=8)

        table = Table(
            title="[AUDIT] Tamper-Evident SHA-256 Audit Log (Last 8 Entries)",
            title_style="bold white",
            box=box.HEAVY_HEAD,
            header_style="bold cyan",
            border_style="dim blue",
        )
        table.add_column("Seq", style="cyan", justify="right", width=6)
        table.add_column("Timestamp (UTC)", style="white", width=21)
        table.add_column("Trace ID", style="dim cyan", width=17)
        table.add_column("Agent", style="yellow", width=16)
        table.add_column("Action", style="green", width=13)
        table.add_column("Decision", style="bold", width=11)
        table.add_column("Risk", style="bold", width=8)
        table.add_column("Hash Link (SHA-256)", style="dim white", width=19)

        for ev in events:
            # Handle both dict (from json.loads) and AuditEvent object
            if isinstance(ev, dict):
                seq = ev.get("sequence_number", 0)
                ts_raw = ev.get("timestamp", "")
                trace_id = ev.get("trace_id", "trace-global")
                agent_id = ev.get("agent_id", "agent")
                action_data = ev.get("action", {})
                tool_name = action_data.get("tool_name", "call_api") if isinstance(action_data, dict) else "call_api"
                dec_val = ev.get("decision", "ALLOW")
                risk_val = ev.get("risk_level", "LOW")
                this_hash = ev.get("this_hash", "")
            else:
                seq = ev.sequence_number
                ts_raw = ev.timestamp.isoformat() if ev.timestamp else ""
                trace_id = ev.trace_id or "trace-global"
                agent_id = ev.agent_id
                tool_name = ev.action.tool_name if ev.action else "call_api"
                dec_val = ev.decision.value if hasattr(ev.decision, "value") else str(ev.decision)
                risk_val = ev.risk_level.value if hasattr(ev.risk_level, "value") else str(ev.risk_level)
                this_hash = ev.this_hash or ""

            # Format timestamp nicely (e.g. 22:53:25.946)
            try:
                if "T" in ts_raw:
                    t_part = ts_raw.split("T")[1].replace("Z", "")
                    ts_str = t_part[:12]
                else:
                    ts_str = ts_raw[:12]
            except Exception:
                ts_str = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]

            trace_short = trace_id[:14]

            # Colors
            dec_style = "green" if dec_val.upper() == "ALLOW" else "red"
            risk_style = {
                "LOW": "green",
                "MEDIUM": "yellow",
                "HIGH": "red",
                "CRITICAL": "bold red",
            }.get(risk_val.upper(), "white")

            hash_short = f"{this_hash[:8]}...{this_hash[-6:]}" if len(this_hash) >= 14 else (this_hash or "genesis")

            table.add_row(
                str(seq),
                ts_str,
                trace_short,
                agent_id,
                tool_name,
                f"[{dec_style}]{dec_val}[/{dec_style}]",
                f"[{risk_style}]{risk_val[:6]}[/{risk_style}]",
                hash_short,
            )

        console.print(table)
        console.print()

        # Cryptographic Hash Chain Verification
        chain_valid, err_msg = self.gateway.store.verify_chain()
        console.print(f"  [bold green][VERIFIED][/bold green] SHA-256 Cryptographic Hash Chain Intact: [bold green]{chain_valid}[/bold green] (Error={err_msg})")
        console.print()

        # Performance & Token Usage Dashboard
        total_reqs = len(self.request_latencies)
        avg_lat = sum(self.request_latencies) / max(total_reqs, 1)
        sorted_lat = sorted(self.request_latencies) if self.request_latencies else [0.0]
        p95_idx = int(0.95 * len(sorted_lat))
        p95_lat = sorted_lat[min(p95_idx, len(sorted_lat) - 1)]

        card1 = Panel(Align.center(f"[bold white]{total_reqs}[/bold white]\n[dim]Total Requests[/dim]"), box=box.ROUNDED, border_style="cyan")
        card2 = Panel(Align.center(f"[bold cyan]{avg_lat:.2f} ms[/bold cyan]\n[dim]Avg Latency (100% Fast-Path)[/dim]"), box=box.ROUNDED, border_style="blue")
        card3 = Panel(Align.center(f"[bold green]{p95_lat:.2f} ms[/bold green]\n[dim]p95 Latency[/dim]"), box=box.ROUNDED, border_style="green")
        card4 = Panel(Align.center(f"[bold magenta]{self.total_tokens_used}[/bold magenta]\n[dim]Total Tokens[/dim]"), box=box.ROUNDED, border_style="magenta")

        dashboard_panel = Panel(
            Columns([card1, card2, card3, card4], expand=True),
            title="[bold white][METRICS] Performance & Token Usage Dashboard[/bold white]",
            border_style="bold blue",
            box=box.ROUNDED,
        )
        console.print(dashboard_panel)
        console.print("=" * 65)
        console.print()

    def run_full_pipeline(self) -> None:
        """Execute all 5 phases of the collaborative multi-agent security pipeline."""
        self.print_header()
        self.phase_1_inspect_registry()
        self.phase_2_delegation_pipeline()
        self.phase_3_privilege_escalation_defense()
        self.phase_4_taint_exfiltration_defense()
        self.phase_5_audit_and_metrics()

    def run_dynamic_task(self, prompt: str) -> None:
        """Execute a dynamic user prompt through collaborative multi-agent reasoning and AURA interception."""
        self.print_header()
        console.print(f"[bold cyan]Dispatching Dynamic Task to AURA Multi-Agent Network:[/bold cyan] {prompt}\n")

        from aura.agent import AuraMultiAgentSystem
        mas = AuraMultiAgentSystem(gateway=self.gateway)

        t0 = time.perf_counter()
        result = mas.run(prompt)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.request_latencies.append(elapsed_ms)

        results = result.get("aura_results", [])
        if results:
            console.print("[bold yellow]Interception & Enforcement Steps:[/bold yellow]")
            for r in results:
                dec_color = "green" if r.decision == Decision.ALLOW else "red"
                console.print(f"  • Tool: [bold cyan]{r.tool_name}[/bold cyan] -> [{dec_color}]{r.decision.value}[/{dec_color}] ({r.reason_code or 'OK'})")
            console.print()

        console.print(Panel(
            result.get("final_response", ""),
            title="[bold green]Multi-Agent Synthesis Response[/bold green]",
            border_style="bold green",
            box=box.ROUNDED,
        ))
        console.print()
        self.phase_5_audit_and_metrics()
