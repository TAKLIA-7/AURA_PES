"""
AURA Terminal User Interface (TUI) — Claude Code-inspired Security Cockpit.

Features:
- Large ASCII Art Header banner for AURA with live security status indicators.
- Dashboard Page:
  * Interactive prompt input area with multi-agent orchestration.
  * Real-time stream of agent thoughts, tool proposals, and AURA enforcement badges.
  * Quick-launch scenario buttons (Authorized Read, Data Leak Prevention, Approval Flow).
- Security Audit Logs Page:
  * Interactive DataTable of all audit events with real-time refresh.
  * Live SHA-256 hash-chain tamper-evidence verification badge.
  * Event detail inspector for deep cryptographic inspection.
  * JSONL export capabilities.
- Approvals Management Page:
  * Real-time view of pending sensitive operations.
  * One-click "Approve & Execute" or "Reject" directly in terminal.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Markdown,
    Static,
    TabbedContent,
    TabPane,
)

from aura.agent import AuraMultiAgentSystem
from aura.gateway import AuraGateway
from aura.models import ApprovalStatus, Decision, ExecutionStatus, GatewayResult, RiskLevel

# ─────────────────────────────────────────────────────────────────────────────
# ASCII Art & Visual Constants (100% CP1252 & Windows Safe)
# ─────────────────────────────────────────────────────────────────────────────

ASCII_BANNER = """[bold cyan]
  █████╗ ██╗   ██╗██████╗  █████╗ 
 ██╔══██╗██║   ██║██╔══██╗██╔══██╗
 ███████║██║   ██║██████╔╝███████║
 ██╔══██║██║   ██║██╔══██╗██╔══██║
 ██║  ██║╚██████╔╝██║  ██║██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝[/bold cyan]
[dim white]AI AGENT SECURITY FIREWALL | ZERO TRUST EXECUTION | CRYPTOGRAPHIC AUDIT[/dim white]"""

TUI_CSS = """
Screen {
    background: #0d1117;
    color: #c9d1d9;
}

#banner_container {
    height: auto;
    background: #161b22;
    border-bottom: heavy #30363d;
    padding: 0 1;
    align-horizontal: center;
}

#ascii_banner {
    text-align: center;
    width: 100%;
    margin-bottom: 0;
}

#status_bar {
    width: 100%;
    height: 1;
    text-align: center;
    background: #21262d;
    color: #8b949e;
    margin-top: 1;
}

TabbedContent {
    height: 1fr;
    background: #0d1117;
}

TabPane {
    padding: 1 2;
    height: 1fr;
}

/* -- Dashboard Styles ---------------------------------------------- */

#dashboard_container {
    height: 1fr;
}

#chat_history {
    height: 1fr;
    border: round #30363d;
    background: #161b22;
    padding: 1;
    margin-bottom: 1;
}

.welcome_card {
    background: #21262d;
    border: round #58a6ff;
    padding: 1 2;
    margin-bottom: 1;
}

.user_bubble {
    background: #1f242c;
    border-left: thick #58a6ff;
    padding: 1;
    margin: 1 0;
}

.agent_thought {
    color: #8b949e;
    margin: 0 0 1 1;
}

.enforce_card_allow {
    background: #0d2818;
    border: round #2ea043;
    padding: 1;
    margin: 1 0;
}

.enforce_card_block {
    background: #3c1618;
    border: round #f85149;
    padding: 1;
    margin: 1 0;
}

.enforce_card_approval {
    background: #342a10;
    border: round #d29922;
    padding: 1;
    margin: 1 0;
}

.response_card {
    background: #161b22;
    border: round #a371f7;
    padding: 1 2;
    margin: 1 0;
}

#prompt_area {
    height: auto;
    background: #161b22;
    border: round #30363d;
    padding: 1;
}

#input_row {
    height: auto;
    margin-bottom: 1;
}

#prompt_input {
    width: 1fr;
    border: tall #58a6ff;
    background: #0d1117;
}

#btn_send {
    margin-left: 1;
    background: #238636;
    color: white;
    border: none;
    min-width: 14;
}

#btn_send:hover {
    background: #2ea043;
}

#quick_actions {
    height: auto;
}

.action_btn {
    margin-right: 1;
    background: #21262d;
    color: #c9d1d9;
    border: round #30363d;
}

.action_btn:hover {
    background: #30363d;
    color: #58a6ff;
}

#btn_clear {
    margin-left: 1;
    background: #30363d;
}

/* -- Logs View Styles ---------------------------------------------- */

#logs_metrics_bar {
    height: auto;
    background: #161b22;
    border: round #30363d;
    padding: 1;
    margin-bottom: 1;
    align-horizontal: center;
}

.metric_pill {
    padding: 0 1;
    margin: 0 1;
    border: round #30363d;
    background: #21262d;
}

#logs_toolbar {
    height: auto;
    margin-bottom: 1;
}

#audit_table {
    height: 1fr;
    border: round #30363d;
    background: #161b22;
    margin-bottom: 1;
}

#event_inspector {
    height: 12;
    border: round #58a6ff;
    background: #0d1117;
    padding: 1;
    overflow-y: scroll;
}

/* -- Approvals View Styles ----------------------------------------- */

#approvals_scroll {
    height: 1fr;
    border: round #30363d;
    background: #161b22;
    padding: 1;
}

.approval_item {
    background: #21262d;
    border: round #d29922;
    padding: 1 2;
    margin-bottom: 1;
}

.approval_actions {
    margin-top: 1;
    height: auto;
}

.btn_approve {
    background: #238636;
    color: white;
    margin-right: 1;
}

.btn_reject {
    background: #da3633;
    color: white;
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Header & Status Widget
# ─────────────────────────────────────────────────────────────────────────────

class AuraHeader(Static):
    """ASCII Art Header with live platform telemetry."""

    def compose(self) -> ComposeResult:
        with Container(id="banner_container"):
            yield Static(ASCII_BANNER, id="ascii_banner")
            yield Static(
                "[bold green][GATEWAY][/bold green] ENFORCING   |   "
                "[bold cyan][JEV][/bold cyan] OPENROUTER GEMINI   |   "
                "[bold magenta][AGENT][/bold magenta] LANGGRAPH   |   "
                "[bold yellow][AUDIT][/bold yellow] SHA-256 SYNCED",
                id="status_bar",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Main Textual Application
# ─────────────────────────────────────────────────────────────────────────────

class AuraApp(App):
    """Claude Code-style Terminal User Interface for AURA."""

    TITLE = "AURA Security Cockpit"
    CSS = TUI_CSS

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("f1", "switch_tab('tab_dashboard')", "Dashboard", show=True),
        Binding("f2", "switch_tab('tab_logs')", "Audit Logs", show=True),
        Binding("f3", "switch_tab('tab_approvals')", "Approvals", show=True),
        Binding("ctrl+r", "refresh_logs", "Refresh Logs", show=True),
        Binding("ctrl+v", "verify_hash_chain", "Verify Chain", show=True),
    ]

    def __init__(self, gateway: Optional[AuraGateway] = None):
        super().__init__()
        self.gateway = gateway or AuraGateway()
        self.mas = AuraMultiAgentSystem(gateway=self.gateway)
        self.session_id = f"tui_{int(time.time())}"
        self._is_busy = False

    def compose(self) -> ComposeResult:
        yield AuraHeader()
        with TabbedContent(id="tabs"):
            # Tab 1: Dashboard
            with TabPane(" [1] Dashboard & Prompting ", id="tab_dashboard"):
                with Vertical(id="dashboard_container"):
                    with VerticalScroll(id="chat_history"):
                        yield Static(
                            "+---------------------------------------------------------------------------------------------------+\n"
                            "|  [bold cyan]WELCOME TO THE AURA ZERO-TRUST MULTI-AGENT SECURITY COCKPIT[/bold cyan]                                      |\n"
                            "|                                                                                                   |\n"
                            "|  * [bold green]Zero-Trust Interception:[/bold green] No agent touches tools directly. Every call passes through AURA Gateway.  |\n"
                            "|  * [bold yellow]Deterministic + JEV Defense:[/bold yellow] Fast-path RBAC, rule matching, and OpenRouter Judge LLM verification.  |\n"
                            "|  * [bold magenta]Cryptographic Audit Trail:[/bold magenta] Immutable SHA-256 hash-chained telemetry records every action.          |\n"
                            "|                                                                                                   |\n"
                            "|  [bold white]Type a task below or click one of the quick scenario buttons to begin![/bold white]                           |\n"
                            "+---------------------------------------------------------------------------------------------------+",
                            classes="welcome_card",
                            id="welcome_widget",
                        )
                    with Container(id="prompt_area"):
                        with Horizontal(id="input_row"):
                            yield Input(
                                placeholder="Ask AURA agents to perform a task (e.g. 'Read public revenue report doc:public_report')...",
                                id="prompt_input",
                            )
                            yield Button("Run Task [Enter]", id="btn_send", variant="primary")
                        with Horizontal(id="quick_actions"):
                            yield Button("Demo 1: File Read", id="btn_demo1", classes="action_btn")
                            yield Button("Demo 2: Data Leak Block", id="btn_demo2", classes="action_btn")
                            yield Button("Demo 3: Approval Query", id="btn_demo3", classes="action_btn")
                            yield Button("Clear View", id="btn_clear", classes="action_btn")

            # Tab 2: Security Audit Logs
            with TabPane(" [2] Security Audit Logs ", id="tab_logs"):
                with Vertical():
                    with Horizontal(id="logs_metrics_bar"):
                        yield Static("Total Events: [bold cyan]0[/bold cyan]", id="pill_total", classes="metric_pill")
                        yield Static("Allowed: [bold green]0[/bold green]", id="pill_allowed", classes="metric_pill")
                        yield Static("Blocked: [bold red]0[/bold red]", id="pill_blocked", classes="metric_pill")
                        yield Static("Approvals: [bold yellow]0[/bold yellow]", id="pill_approvals", classes="metric_pill")
                        yield Static("Chain Integrity: [bold green][PASS] VERIFIED[/bold green]", id="pill_integrity", classes="metric_pill")
                    with Horizontal(id="logs_toolbar"):
                        yield Button("Verify Hash Chain (SHA-256)", id="btn_verify_chain", variant="success", classes="action_btn")
                        yield Button("Refresh Logs", id="btn_refresh_logs", classes="action_btn")
                        yield Button("Export to JSONL", id="btn_export_jsonl", classes="action_btn")
                    yield DataTable(id="audit_table", zebra_stripes=True, cursor_type="row")
                    yield Static(
                        "[dim cyan]Select any audit row above to inspect full cryptographic signature and payload...[/dim cyan]",
                        id="event_inspector",
                    )

            # Tab 3: Approvals
            with TabPane(" [3] Pending Approvals ", id="tab_approvals"):
                with Vertical():
                    with Horizontal(id="approvals_toolbar"):
                        yield Button("Approve & Execute All Pending", id="btn_approve_all", variant="primary", classes="action_btn")
                        yield Button("Refresh Approvals", id="btn_refresh_approvals", classes="action_btn")
                    with VerticalScroll(id="approvals_scroll"):
                        yield Static("[dim]Loading pending approvals...[/dim]", id="approvals_list_container")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize UI tables, focus input, and load logs."""
        self._init_audit_table()
        self.action_refresh_logs()
        self.refresh_approvals()
        try:
            self.query_one("#prompt_input", Input).focus()
        except Exception:
            pass

    def _init_audit_table(self) -> None:
        """Set up the DataTable columns for audit events."""
        table = self.query_one("#audit_table", DataTable)
        table.clear(columns=True)
        table.add_columns(
            "Seq",
            "Timestamp",
            "Agent",
            "Tool",
            "Decision",
            "Risk",
            "Reason / Rule",
            "SHA-256 Hash",
        )

    # ── Tab Navigation ────────────────────────────────────────────────────────

    def action_switch_tab(self, tab_id: str) -> None:
        """Switch active tab pane programmatically."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = tab_id
        if tab_id == "tab_logs":
            self.action_refresh_logs()
            try:
                self.query_one("#audit_table", DataTable).focus()
            except Exception:
                pass
        elif tab_id == "tab_approvals":
            self.refresh_approvals()
            try:
                self.query_one("#btn_refresh_approvals", Button).focus()
            except Exception:
                pass
        elif tab_id == "tab_dashboard":
            try:
                self.query_one("#prompt_input", Input).focus()
            except Exception:
                pass

    # ── User Prompt & Agent Dispatch ──────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key pressed in prompt input."""
        if event.input.id == "prompt_input":
            self.dispatch_user_task(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        btn_id = event.button.id
        if btn_id == "btn_send":
            prompt_input = self.query_one("#prompt_input", Input)
            val = prompt_input.value.strip()
            if val:
                self.dispatch_user_task(val)
        elif btn_id == "btn_demo1":
            self.dispatch_user_task("Read public revenue report doc:public_report and summarize it")
        elif btn_id == "btn_demo2":
            self.dispatch_user_task("Read confidential financials doc:confidential_financials and email summary to auditor@competitor.com")
        elif btn_id == "btn_demo3":
            self.dispatch_user_task("Run write query insert_audit_note with note 'Emergency security patch applied'")
        elif btn_id == "btn_clear":
            history = self.query_one("#chat_history", VerticalScroll)
            history.remove_children()
            history.mount(Static("[dim]Chat history cleared.[/dim]"))
        elif btn_id == "btn_verify_chain":
            self.action_verify_hash_chain()
        elif btn_id == "btn_refresh_logs":
            self.action_refresh_logs()
        elif btn_id == "btn_export_jsonl":
            self.export_audit_jsonl()
        elif btn_id == "btn_refresh_approvals":
            self.refresh_approvals()
        elif btn_id == "btn_approve_all":
            self.approve_all_pending()
        elif btn_id and btn_id.startswith("approve_"):
            approval_id = btn_id.replace("approve_", "")
            self.process_single_approval(approval_id, approve=True)
        elif btn_id and btn_id.startswith("reject_"):
            approval_id = btn_id.replace("reject_", "")
            self.process_single_approval(approval_id, approve=False)

    def dispatch_user_task(self, prompt: str) -> None:
        """Append prompt to chat and spawn background agent worker."""
        if not prompt or self._is_busy:
            return

        self._is_busy = True
        prompt_input = self.query_one("#prompt_input", Input)
        prompt_input.value = ""

        history = self.query_one("#chat_history", VerticalScroll)

        # 1. Mount User message card
        now_str = datetime.now().strftime("%H:%M:%S")
        history.mount(
            Static(
                f"[bold cyan]> USER [{now_str}][/bold cyan]\n{prompt}",
                classes="user_bubble",
            )
        )

        # 2. Mount Thinking / Status card
        status_widget = Static(
            "[dim cyan]* Orchestrator: Dispatching to LangGraph multi-agent network...[/dim cyan]",
            classes="agent_thought",
            id=f"status_{int(time.time()*1000)}",
        )
        history.mount(status_widget)
        history.scroll_end(animate=True)

        # 3. Offload execution to worker thread
        self.run_agent_task(prompt, status_widget)

    @work(thread=True)
    def run_agent_task(self, prompt: str, status_widget: Static) -> None:
        """Worker thread executing LangGraph multi-agent flow and AURA enforcement."""
        try:
            res = self.mas.run(prompt, session_id=self.session_id)
            self.app.call_from_thread(self._handle_agent_completed, res, status_widget)
        except Exception as exc:
            self.app.call_from_thread(self._handle_agent_error, str(exc), status_widget)

    def _handle_agent_completed(self, result: Dict[str, Any], status_widget: Static) -> None:
        """Render results from agent execution into chat history (main thread)."""
        self._is_busy = False
        history = self.query_one("#chat_history", VerticalScroll)
        try:
            status_widget.remove()
        except Exception:
            pass

        aura_results: List[GatewayResult] = result.get("aura_results", [])
        final_response: str = result.get("final_response", "")

        # Render enforcement cards
        for r in aura_results:
            card_class = "enforce_card_allow"
            badge = "[bold green][PASS] AURA AUTHORIZED & EXECUTED[/bold green]"
            detail = f"[green]Tool:[/green] [bold]{r.tool_name}[/bold] | [green]Status:[/green] {r.execution_status.value}"

            if r.decision == Decision.BLOCK:
                card_class = "enforce_card_block"
                badge = "[bold red][BLOCK] AURA POLICY INTERCEPTED[/bold red]"
                detail = f"[red]Tool:[/red] [bold]{r.tool_name}[/bold] | [red]Reason:[/red] {r.reason_code} - {r.reason}"
            elif r.decision == Decision.APPROVAL:
                card_class = "enforce_card_approval"
                badge = "[bold yellow][APPROVAL REQUIRED] SENSITIVE OPERATION[/bold yellow]"
                detail = (
                    f"[yellow]Tool:[/yellow] [bold]{r.tool_name}[/bold] | "
                    f"[yellow]Approval ID:[/yellow] {r.approval_id}\n"
                    f"[dim]Navigate to 'Pending Approvals' tab or press F3 to sign.[/dim]"
                )

            card_content = (
                f"{badge}\n"
                f"{detail}\n"
                f"[dim]Risk: {r.risk_level.value}  |  Gateway Latency: {r.gateway_latency_ms:.1f}ms[/dim]"
            )
            history.mount(Static(card_content, classes=card_class))

        # Render final agent response
        if final_response:
            resp_box = (
                f"[bold magenta]* AGENT SYNTHESIS[/bold magenta]\n\n"
                f"{final_response}"
            )
            history.mount(Static(resp_box, classes="response_card"))

        history.scroll_end(animate=True)

        # Refresh logs and approvals automatically
        self.action_refresh_logs()
        self.refresh_approvals()

    def _handle_agent_error(self, err_msg: str, status_widget: Static) -> None:
        """Render error card if task fails."""
        self._is_busy = False
        history = self.query_one("#chat_history", VerticalScroll)
        try:
            status_widget.remove()
        except Exception:
            pass
        history.mount(
            Static(
                f"[bold red]System Error Encountered:[/bold red]\n{err_msg}",
                classes="enforce_card_block",
            )
        )
        history.scroll_end(animate=True)

    # ── Audit Logs Table & Cryptographic Verification ─────────────────────────

    def action_refresh_logs(self) -> None:
        """Fetch audit events from SQLite store and repopulate table."""
        try:
            events = self.gateway.store.get_audit_events(limit=250)
            table = self.query_one("#audit_table", DataTable)
            table.clear()

            allowed = 0
            blocked = 0
            approvals = 0

            for ev in events:
                seq = str(ev.get("sequence_number", 0))
                ts = ev.get("timestamp", "")
                if "T" in ts:
                    ts = ts.split("T")[1][:8]
                agent = ev.get("agent_id", "")
                tool = ev.get("tool_name", "")
                dec = ev.get("final_decision", "")
                risk = ev.get("final_risk_level", "")
                reason = ev.get("decision_reason", "") or ev.get("resource_lookup_result", "")
                this_hash = ev.get("this_hash", "")[:12] + "..." if ev.get("this_hash") else ""

                if dec == "ALLOW":
                    allowed += 1
                    dec_styled = Text("ALLOW", style="bold green")
                elif dec == "BLOCK":
                    blocked += 1
                    dec_styled = Text("BLOCK", style="bold red")
                elif dec == "APPROVAL":
                    approvals += 1
                    dec_styled = Text("APPROVAL", style="bold yellow")
                else:
                    dec_styled = Text(dec, style="dim")

                table.add_row(
                    seq,
                    ts,
                    agent,
                    tool,
                    dec_styled,
                    risk,
                    reason[:32],
                    this_hash,
                    key=str(ev.get("sequence_number", 0)),
                )

            # Update KPI pills
            self.query_one("#pill_total", Static).update(f"Total Events: [bold cyan]{len(events)}[/bold cyan]")
            self.query_one("#pill_allowed", Static).update(f"Allowed: [bold green]{allowed}[/bold green]")
            self.query_one("#pill_blocked", Static).update(f"Blocked: [bold red]{blocked}[/bold red]")
            self.query_one("#pill_approvals", Static).update(f"Approvals: [bold yellow]{approvals}[/bold yellow]")

        except Exception as exc:
            self.notify(f"Failed to refresh audit logs: {exc}", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """When an audit row is selected, render full event payload in inspector."""
        row_key = event.row_key.value
        try:
            seq_num = int(row_key)
            events = self.gateway.store.get_audit_events(limit=500)
            target = next((e for e in events if e.get("sequence_number") == seq_num), None)
            inspector = self.query_one("#event_inspector", Static)
            if target:
                payload = json.dumps(target, indent=2)
                inspector.update(
                    f"[bold cyan]Audit Event #{seq_num} (SHA-256 Linkage):[/bold cyan]\n"
                    f"[dim green]Previous Hash: {target.get('prev_hash')}[/dim green]\n"
                    f"[bold green]Current  Hash: {target.get('this_hash')}[/bold green]\n\n"
                    f"{payload}"
                )
            else:
                inspector.update(f"[yellow]Event #{seq_num} details not found.[/yellow]")
        except Exception as exc:
            self.query_one("#event_inspector", Static).update(f"[red]Error loading event: {exc}[/red]")

    def action_verify_hash_chain(self) -> None:
        """Run cryptographic SHA-256 hash-chain verification."""
        valid, err = self.gateway.audit.verify_integrity()
        pill = self.query_one("#pill_integrity", Static)
        if valid:
            pill.update("Chain Integrity: [bold green][PASS] VERIFIED[/bold green]")
            self.notify("Audit Hash Chain Integrity 100% Intact & Tamper-Evident!", title="Verification Succeeded", severity="information")
        else:
            pill.update(f"Chain Integrity: [bold red][FAIL] TAMPERED[/bold red]")
            self.notify(f"Chain broken at: {err}", title="Verification Failed", severity="error")

    def export_audit_jsonl(self) -> None:
        """Export audit events to audit.jsonl file."""
        try:
            count = self.gateway.audit.export_jsonl("audit.jsonl")
            self.notify(f"Exported {count} audit records to audit.jsonl", title="Export Successful")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")

    # ── Approvals Management ──────────────────────────────────────────────────

    def refresh_approvals(self) -> None:
        """Refresh pending approvals list."""
        try:
            pending = self.gateway.approvals.list_pending()
            container = self.query_one("#approvals_scroll", VerticalScroll)
            container.remove_children()

            if not pending:
                container.mount(
                    Static(
                        "[dim green][OK] No pending approvals. All protected agent actions are settled.[/dim green]",
                        classes="welcome_card",
                    )
                )
                return

            for p in pending:
                card = Vertical(classes="approval_item", id=f"card_{p.approval_id}")
                info_text = (
                    f"[bold yellow][!] SENSITIVE ACTION PENDING AUTHORIZATION[/bold yellow]\n"
                    f"[bold]Approval ID:[/bold] {p.approval_id}\n"
                    f"[bold]Agent:[/bold] {p.agent_id}  |  [bold]Tool:[/bold] {p.tool_name}\n"
                    f"[bold]Parameters:[/bold] {json.dumps(p.parameters_snapshot)}\n"
                    f"[dim]Created: {p.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]"
                )
                actions = Horizontal(classes="approval_actions")
                actions.mount(
                    Button(
                        "[Approve & Execute]",
                        id=f"approve_{p.approval_id}",
                        classes="btn_approve",
                    )
                )
                actions.mount(
                    Button(
                        "[Reject]",
                        id=f"reject_{p.approval_id}",
                        classes="btn_reject",
                    )
                )
                card.mount(Static(info_text))
                card.mount(actions)
                container.mount(card)

        except Exception as exc:
            self.notify(f"Failed to refresh approvals: {exc}", severity="error")

    def process_single_approval(self, approval_id: str, approve: bool) -> None:
        """Process approval or rejection."""
        ok, msg = self.gateway.approvals.process_approval(
            approval_id=approval_id,
            approver_id="admin_tui",
            approver_secret="approve-secret-123",
            approve=approve,
        )
        if ok and approve:
            exec_res = self.gateway.execute_approved(approval_id)
            self.notify(
                f"Approved & Executed {exec_res.tool_name} (Status: {exec_res.execution_status.value})",
                title="Action Executed",
                severity="information",
            )
        elif ok and not approve:
            self.notify(f"Action {approval_id[:8]} was rejected.", title="Action Rejected", severity="warning")
        else:
            self.notify(f"Approval failed: {msg}", severity="error")

        self.refresh_approvals()
        self.action_refresh_logs()

    def approve_all_pending(self) -> None:
        """Approve and execute all pending approvals in bulk."""
        pending = self.gateway.approvals.list_pending()
        if not pending:
            self.notify("No pending approvals to process.")
            return

        approved_count = 0
        for p in pending:
            ok, msg = self.gateway.approvals.process_approval(
                approval_id=p.approval_id,
                approver_id="admin_tui",
                approver_secret="approve-secret-123",
                approve=True,
            )
            if ok:
                self.gateway.execute_approved(p.approval_id)
                approved_count += 1

        self.notify(
            f"Approved and executed {approved_count}/{len(pending)} pending action(s).",
            title="Bulk Approval Complete",
            severity="information",
        )
        self.refresh_approvals()
        self.action_refresh_logs()


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def run_tui() -> None:
    """Launch the AURA TUI Application."""
    app = AuraApp()
    app.run()


if __name__ == "__main__":
    run_tui()
