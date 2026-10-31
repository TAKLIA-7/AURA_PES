"""
AURA Terminal User Interface (TUI) — Agent Control Plane Security Cockpit.

Design:
- Purplish-blue gradient ASCII logo with authoritative tagline.
- Modern dark indigo/slate theme inspired by A.U.R.A Agent Control Plane.
- Human-in-the-Loop interactive Approval Modal Popup dialog.
- Dashboard with query and tool execution outputs rendered for every prompt.
- Real-time cryptographic audit log DataTable and SHA-256 chain verification.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
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
# Purplish-Blue Gradient Logo & Tagline (From A.U.R.A UI Reference)
# ─────────────────────────────────────────────────────────────────────────────

AURA_LOGO_LINES = [
    "  ██████╗   ██╗   ██╗  ██████╗    ██████╗  ",
    "  ██╔══██╗  ██║   ██║  ██╔══██╗  ██╔══██╗  ",
    "  ███████║  ██║   ██║  ██████╔╝  ███████║  ",
    "  ██╔══██║  ██║   ██║  ██╔══██╗  ██╔══██║  ",
    "  ██║  ██║  ╚██████╔╝  ██║  ██║  ██║  ██║  ",
    "  ╚═╝  ╚═╝   ╚═════╝   ╚═╝  ╚═╝  ╚═╝  ╚═╝  ",
]

PURPLISH_BLUE_GRADIENT = [
    "#4338ca",  # deep indigo
    "#4f46e5",  # indigo
    "#6366f1",  # purplish blue
    "#7c3aed",  # violet
    "#8b5cf6",  # purple
    "#a78bfa",  # light purplish blue
]


def make_gradient_logo() -> Text:
    """Return a Rich Text object with vibrant purplish-blue gradient AURA logo."""
    t = Text()
    num_lines = len(AURA_LOGO_LINES)
    for i, line in enumerate(AURA_LOGO_LINES):
        frac = i / max(num_lines - 1, 1)
        idx = int(frac * (len(PURPLISH_BLUE_GRADIENT) - 1))
        color = PURPLISH_BLUE_GRADIENT[idx]
        t.append(line + "\n", style=f"bold {color}")

    # Tagline
    t.append("  A", style="bold #4f46e5")
    t.append(" U", style="bold #6366f1")
    t.append(" R", style="bold #8b5cf6")
    t.append(" A", style="bold #a78bfa")
    t.append("  //  ", style="dim #818cf8")
    t.append("AGENT CONTROL PLANE\n", style="bold #e0e7ff")
    t.append("  Contextual decisions  |  Controlled execution  |  Complete observability", style="dim #818cf8")
    return t


# ─────────────────────────────────────────────────────────────────────────────
# Textual CSS Styling (Theme Palette Inspired by A.U.R.A UI)
# ─────────────────────────────────────────────────────────────────────────────

TUI_CSS = """
Screen {
    background: #0a0a14;
    color: #c9d1d9;
}

#banner_container {
    height: auto;
    background: #0d0d22;
    border-bottom: solid #4338ca;
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
    background: #111128;
    color: #8b949e;
    margin-top: 1;
}

TabbedContent {
    height: 1fr;
    background: #0a0a14;
}

Tabs {
    background: #0d0d22;
    height: 3;
    border-bottom: solid #222244;
}

Tab {
    color: #666688;
    padding: 0 2;
    height: 3;
    background: #0d0d22;
}

Tab:hover {
    color: #a78bfa;
    background: #161633;
}

Tab.-active {
    color: #a78bfa;
    background: #1a1a3a;
    text-style: bold;
    border-bottom: tall #6366f1;
}

TabPane {
    padding: 1 2;
    height: 1fr;
    background: #0a0a14;
}

/* -- Dashboard Styles ---------------------------------------------- */

#dashboard_container {
    height: 1fr;
}

#chat_history {
    height: 1fr;
    border: round #222244;
    background: #0d0d22;
    padding: 1;
    margin-bottom: 1;
}

.welcome_card {
    background: #12122b;
    border: round #6366f1;
    padding: 1 2;
    margin-bottom: 1;
}

.user_bubble {
    background: #151533;
    border-left: thick #6366f1;
    padding: 1;
    margin: 1 0;
}

.agent_thought {
    color: #818cf8;
    margin: 0 0 1 1;
}

.enforce_card_allow {
    background: #072317;
    border: round #10b981;
    padding: 1;
    margin: 1 0;
}

.enforce_card_block {
    background: #331116;
    border: round #ef4444;
    padding: 1;
    margin: 1 0;
}

.enforce_card_approval {
    background: #2b1f09;
    border: round #f59e0b;
    padding: 1;
    margin: 1 0;
}

.query_output_card {
    background: #0a172c;
    border: round #38bdf8;
    padding: 1 2;
    margin: 1 0;
}

.response_card {
    background: #12122b;
    border: round #a78bfa;
    padding: 1 2;
    margin: 1 0;
}

#prompt_area {
    height: auto;
    background: #0d0d22;
    border: round #222244;
    padding: 1;
}

#input_row {
    height: auto;
    margin-bottom: 1;
}

#prompt_input {
    width: 1fr;
    border: tall #6366f1;
    background: #0a0a14;
}

#btn_send {
    margin-left: 1;
    background: #4f46e5;
    color: white;
    border: none;
    min-width: 16;
    text-style: bold;
}

#btn_send:hover {
    background: #6366f1;
}

#quick_actions {
    height: auto;
}

.action_btn {
    margin-right: 1;
    background: #161633;
    color: #c9d1d9;
    border: round #222244;
}

.action_btn:hover {
    background: #222244;
    color: #a78bfa;
}

#btn_clear {
    margin-left: 1;
    background: #222244;
}

/* -- Logs View Styles ---------------------------------------------- */

#logs_metrics_bar {
    height: auto;
    background: #0d0d22;
    border: round #222244;
    padding: 1;
    margin-bottom: 1;
    align-horizontal: center;
}

.metric_pill {
    padding: 0 1;
    margin: 0 1;
    border: round #222244;
    background: #161633;
}

#logs_toolbar {
    height: auto;
    margin-bottom: 1;
}

#audit_table {
    height: 1fr;
    border: round #222244;
    background: #0d0d22;
    margin-bottom: 1;
}

#event_inspector {
    height: 12;
    border: round #6366f1;
    background: #060614;
    padding: 1;
    overflow-y: scroll;
}

/* -- Approvals View Styles ----------------------------------------- */

#approvals_scroll {
    height: 1fr;
    border: round #222244;
    background: #0d0d22;
    padding: 1;
}

.approval_item {
    background: #161633;
    border: round #f59e0b;
    padding: 1 2;
    margin-bottom: 1;
}

.approval_actions {
    margin-top: 1;
    height: auto;
}

.btn_approve {
    background: #10b981;
    color: white;
    margin-right: 1;
    text-style: bold;
}

.btn_reject {
    background: #ef4444;
    color: white;
    text-style: bold;
}

/* -- Modal Popup Styles -------------------------------------------- */

ApprovalModalScreen {
    align: center middle;
    background: rgba(8, 8, 18, 0.88);
}

#modal_dialog {
    width: 84;
    height: auto;
    max-height: 85%;
    border: thick #f59e0b;
    background: #0d0d22;
    padding: 1 2;
}

#modal_title {
    text-align: center;
    color: #f59e0b;
    text-style: bold;
    margin-bottom: 1;
}

#modal_info {
    height: auto;
    margin-bottom: 1;
}

#modal_args_panel {
    background: #060614;
    border: solid #222244;
    padding: 1 1;
    margin: 1 0;
    max-height: 12;
    overflow-y: auto;
}

#modal_actions {
    align: center middle;
    height: 3;
    margin-top: 1;
}

#btn_modal_approve {
    margin-right: 2;
    min-width: 20;
    background: #10b981;
    color: #ffffff;
    text-style: bold;
}
#btn_modal_approve:hover {
    background: #059669;
}

#btn_modal_deny {
    min-width: 20;
    background: #ef4444;
    color: #ffffff;
    text-style: bold;
}
#btn_modal_deny:hover {
    background: #dc2626;
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Header & Status Widget
# ─────────────────────────────────────────────────────────────────────────────

class AuraHeader(Static):
    """ASCII Art Header with live platform telemetry."""

    def compose(self) -> ComposeResult:
        with Container(id="banner_container"):
            yield Static(make_gradient_logo(), id="ascii_banner")
            yield Static(
                "[bold #6366f1][CONTROL PLANE][/bold #6366f1] ACTIVE   |   "
                "[bold #10b981][GATEWAY][/bold #10b981] ENFORCING   |   "
                "[bold #a78bfa][JEV][/bold #a78bfa] OPENROUTER GEMINI   |   "
                "[bold #f59e0b][AUDIT][/bold #f59e0b] SHA-256 SYNCED",
                id="status_bar",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Human-in-the-Loop Approval Modal Screen (Popup)
# ─────────────────────────────────────────────────────────────────────────────

class ApprovalModalScreen(ModalScreen[bool]):
    """Modal popup screen that appears whenever an intercepted agent action requires human approval."""

    BINDINGS = [
        Binding("a", "approve", "Approve", show=True),
        Binding("d", "deny", "Deny", show=True),
        Binding("escape", "deny", "Cancel", show=True),
    ]

    def __init__(
        self,
        approval_id: str,
        tool: str,
        args: Dict[str, Any],
        reason: str,
        risk_level: str = "HIGH",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.approval_id = approval_id
        self.tool = tool
        self.args = args
        self.reason = reason
        self.risk_level = risk_level
        self._resolved = False

    def compose(self) -> ComposeResult:
        with Vertical(id="modal_dialog"):
            yield Static("⚠ HUMAN APPROVAL REQUIRED — ACTION INTERCEPTED", id="modal_title")
            yield Static(self._render_details(), id="modal_info")
            with Container(id="modal_args_panel"):
                yield Static(self._render_payload(), id="modal_payload")
            with Horizontal(id="modal_actions"):
                yield Button("✓ Approve (A)", id="btn_modal_approve", variant="success")
                yield Button("✗ Deny (D)", id="btn_modal_deny", variant="error")

    def _render_details(self) -> Text:
        t = Text()
        t.append("The AI Agent requested execution of an action that requires operator sign-off.\n\n", style="dim")
        t.append("  Tool:       ", style="dim")
        t.append(f"{self.tool}\n", style="bold #38bdf8")
        t.append("  Request ID: ", style="dim")
        t.append(f"{self.approval_id}\n", style="#818cf8")
        risk_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f87171",
            "MEDIUM": "#f59e0b",
            "LOW": "#10b981",
        }.get(self.risk_level.upper(), "#f59e0b")
        t.append("  Risk Level: ", style="dim")
        t.append(f"[{self.risk_level.upper()}]\n", style=f"bold {risk_color}")
        t.append("  Reason:     ", style="dim")
        t.append(f"{self.reason}\n", style="#fbbf24")
        return t

    def _render_payload(self) -> Text:
        t = Text()
        if "query_name" in self.args:
            t.append("SQL QUERY TO EXECUTE:\n", style="bold cyan")
            t.append(f"{self.args.get('query_name')}\n", style="bold white")
            t.append("PARAMETERS:\n", style="bold cyan")
            t.append(json.dumps(self.args.get("params", {}), indent=2), style="dim white")
        elif "query" in self.args:
            t.append("SQL STATEMENT TO EXECUTE:\n", style="bold cyan")
            t.append(f"{self.args['query']}\n", style="bold white")
        else:
            t.append("ACTION ARGUMENTS / PAYLOAD:\n", style="bold cyan")
            t.append(json.dumps(self.args, indent=2, default=str), style="dim white")
        return t

    def action_approve(self) -> None:
        if not self._resolved:
            self._resolved = True
            self.dismiss(True)

    def action_deny(self) -> None:
        if not self._resolved:
            self._resolved = True
            self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_modal_approve":
            self.action_approve()
        elif event.button.id == "btn_modal_deny":
            self.action_deny()


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
                            "|  [bold #a78bfa]WELCOME TO THE AURA ZERO-TRUST MULTI-AGENT SECURITY CONTROL PLANE[/bold #a78bfa]                         |\n"
                            "|                                                                                                   |\n"
                            "|  * [bold #10b981]Zero-Trust Interception:[/bold #10b981] No agent touches tools directly. Every call passes through AURA Gateway.  |\n"
                            "|  * [bold #f59e0b]Deterministic + JEV Defense:[/bold #f59e0b] Fast-path RBAC, rule matching, and OpenRouter Judge LLM verification.  |\n"
                            "|  * [bold #818cf8]Cryptographic Audit Trail:[/bold #818cf8] Immutable SHA-256 hash-chained telemetry records every action.          |\n"
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
                            yield Button("Demo 4: Query Analytics", id="btn_demo4", classes="action_btn")
                            yield Button("Clear View", id="btn_clear", classes="action_btn")

            # Tab 2: Security Audit Logs
            with TabPane(" [2] Security Audit Logs ", id="tab_logs"):
                with Vertical():
                    with Horizontal(id="logs_metrics_bar"):
                        yield Static("Total Events: [bold cyan]0[/bold cyan]", id="pill_total", classes="metric_pill")
                        yield Static("Allowed: [bold #10b981]0[/bold #10b981]", id="pill_allowed", classes="metric_pill")
                        yield Static("Blocked: [bold #ef4444]0[/bold #ef4444]", id="pill_blocked", classes="metric_pill")
                        yield Static("Approvals: [bold #f59e0b]0[/bold #f59e0b]", id="pill_approvals", classes="metric_pill")
                        yield Static("Chain Integrity: [bold #10b981][PASS] VERIFIED[/bold #10b981]", id="pill_integrity", classes="metric_pill")
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
        elif btn_id == "btn_demo4":
            self.dispatch_user_task("Run database query get_revenue_summary for 2024")
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
        elif btn_id and btn_id.startswith("modal_review_"):
            approval_id = btn_id.replace("modal_review_", "")
            self.popup_approval_modal(approval_id)
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
                f"[bold #6366f1]> USER [{now_str}][/bold #6366f1]\n{prompt}",
                classes="user_bubble",
            )
        )

        # 2. Mount Thinking / Status card
        status_widget = Static(
            "[dim #a78bfa]* Orchestrator: Dispatching to LangGraph multi-agent network...[/dim #a78bfa]",
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
        pending_approval_id: Optional[str] = None
        pending_approval_tool: str = ""
        pending_approval_reason: str = ""
        pending_approval_risk: str = "HIGH"

        for r in aura_results:
            card_class = "enforce_card_allow"
            badge = "[bold #10b981][PASS] AURA AUTHORIZED & EXECUTED[/bold #10b981]"
            detail = f"[green]Tool:[/green] [bold]{r.tool_name}[/bold] | [green]Status:[/green] {r.execution_status.value}"

            if r.decision == Decision.BLOCK:
                card_class = "enforce_card_block"
                badge = "[bold #ef4444][BLOCK] AURA POLICY INTERCEPTED[/bold #ef4444]"
                detail = f"[red]Tool:[/red] [bold]{r.tool_name}[/bold] | [red]Reason:[/red] {r.reason_code} - {r.reason}"
            elif r.decision == Decision.APPROVAL:
                card_class = "enforce_card_approval"
                badge = "[bold #f59e0b][APPROVAL REQUIRED] SENSITIVE OPERATION INTERCEPTED[/bold #f59e0b]"
                detail = (
                    f"[yellow]Tool:[/yellow] [bold]{r.tool_name}[/bold] | "
                    f"[yellow]Approval ID:[/yellow] {r.approval_id}\n"
                    f"[dim]Click button below or use popup to authorize.[/dim]"
                )
                pending_approval_id = r.approval_id
                pending_approval_tool = r.tool_name
                pending_approval_reason = r.reason
                pending_approval_risk = r.risk_level.value

            card_content = (
                f"{badge}\n"
                f"{detail}\n"
                f"[dim]Risk: {r.risk_level.value}  |  Gateway Latency: {r.gateway_latency_ms:.1f}ms[/dim]"
            )
            card_children = [Static(card_content)]

            # Add Review & Authorize button for approval cards
            if r.decision == Decision.APPROVAL and r.approval_id:
                card_children.append(
                    Button(
                        "⚡ Review & Authorize (Popup)",
                        id=f"modal_review_{r.approval_id}",
                        classes="btn_approve",
                    )
                )

            history.mount(Vertical(*card_children, classes=card_class))

            # Display Output Data directly on Dashboard for each prompt
            if r.decision == Decision.ALLOW and r.execution_status == ExecutionStatus.COMPLETED and r.result_data:
                output_body = ""
                header_title = "[bold cyan][QUERY / TOOL OUTPUT][/bold cyan]"

                if r.tool_name == "run_query" and isinstance(r.result_data, dict):
                    q_name = r.result_data.get("query_name", "query")
                    rows = r.result_data.get("results", [])
                    header_title = f"[bold cyan][DATABASE QUERY OUTPUT: {q_name}][/bold cyan] [dim]({len(rows)} row(s) returned)[/dim]"
                    if rows:
                        output_body = json.dumps(rows, indent=2)
                    else:
                        output_body = "(Empty result set)"

                elif r.tool_name == "read_file" and isinstance(r.result_data, dict):
                    doc_id = r.result_data.get("doc_id", "document")
                    content = r.result_data.get("content", "")
                    header_title = f"[bold cyan][DOCUMENT CONTENT: {doc_id}][/bold cyan]"
                    output_body = content

                elif isinstance(r.result_data, (dict, list)):
                    header_title = f"[bold cyan][OPERATION OUTPUT: {r.tool_name}][/bold cyan]"
                    output_body = json.dumps(r.result_data, indent=2, default=str)
                else:
                    header_title = f"[bold cyan][OPERATION OUTPUT: {r.tool_name}][/bold cyan]"
                    output_body = str(r.result_data)

                output_card = f"{header_title}\n\n{output_body}"
                history.mount(Static(output_card, classes="query_output_card"))

        # Render final agent response
        if final_response:
            resp_box = (
                f"[bold #a78bfa]* AGENT SYNTHESIS[/bold #a78bfa]\n\n"
                f"{final_response}"
            )
            history.mount(Static(resp_box, classes="response_card"))

        history.scroll_end(animate=True)

        # Refresh logs and approvals automatically
        self.action_refresh_logs()
        self.refresh_approvals()

        # AUTOMATIC POPUP: If an action requires approval, pop up the modal screen!
        if pending_approval_id:
            self.popup_approval_modal(
                approval_id=pending_approval_id,
                tool=pending_approval_tool,
                reason=pending_approval_reason,
                risk_level=pending_approval_risk,
            )

    def popup_approval_modal(
        self,
        approval_id: str,
        tool: str = "",
        reason: str = "",
        risk_level: str = "HIGH",
    ) -> None:
        """Trigger the interactive human-in-the-loop approval modal popup."""
        # Query approval record for args snapshot
        record = self.gateway.approvals.get_stored_action(approval_id)
        args_payload: Dict[str, Any] = {}
        if record:
            tool = record.tool_name
            args_payload = record.parameters_snapshot
        elif not tool:
            tool = "sensitive_operation"

        def on_modal_dismissed(approved: Optional[bool]) -> None:
            if approved is True:
                self.process_single_approval(approval_id, approve=True)
            elif approved is False:
                self.process_single_approval(approval_id, approve=False)

        modal = ApprovalModalScreen(
            approval_id=approval_id,
            tool=tool,
            args=args_payload,
            reason=reason or "Sensitive write operation requires human approval.",
            risk_level=risk_level,
        )
        self.push_screen(modal, callback=on_modal_dismissed)

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
                    dec_styled = Text("ALLOW", style="bold #10b981")
                elif dec == "BLOCK":
                    blocked += 1
                    dec_styled = Text("BLOCK", style="bold #ef4444")
                elif dec == "APPROVAL":
                    approvals += 1
                    dec_styled = Text("APPROVAL", style="bold #f59e0b")
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
            self.query_one("#pill_allowed", Static).update(f"Allowed: [bold #10b981]{allowed}[/bold #10b981]")
            self.query_one("#pill_blocked", Static).update(f"Blocked: [bold #ef4444]{blocked}[/bold #ef4444]")
            self.query_one("#pill_approvals", Static).update(f"Approvals: [bold #f59e0b]{approvals}[/bold #f59e0b]")

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
            pill.update("Chain Integrity: [bold #10b981][PASS] VERIFIED[/bold #10b981]")
            self.notify("Audit Hash Chain Integrity 100% Intact & Tamper-Evident!", title="Verification Succeeded", severity="information")
        else:
            pill.update(f"Chain Integrity: [bold #ef4444][FAIL] TAMPERED[/bold #ef4444]")
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
                    f"[bold #f59e0b][!] SENSITIVE ACTION PENDING AUTHORIZATION[/bold #f59e0b]\n"
                    f"[bold]Approval ID:[/bold] {p.approval_id}\n"
                    f"[bold]Agent:[/bold] {p.agent_id}  |  [bold]Tool:[/bold] {p.tool_name}\n"
                    f"[bold]Parameters:[/bold] {json.dumps(p.parameters_snapshot)}\n"
                    f"[dim]Created: {p.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]"
                )
                actions = Horizontal(classes="approval_actions")
                actions.mount(
                    Button(
                        "⚡ Review & Authorize (Popup)",
                        id=f"modal_review_{p.approval_id}",
                        classes="btn_approve",
                    )
                )
                actions.mount(
                    Button(
                        "[✓ Approve Directly]",
                        id=f"approve_{p.approval_id}",
                        classes="btn_approve",
                    )
                )
                actions.mount(
                    Button(
                        "[✗ Reject]",
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
        """Process approval or rejection and display execution output on dashboard."""
        ok, msg = self.gateway.approvals.process_approval(
            approval_id=approval_id,
            approver_id="admin_tui",
            approver_secret="approve-secret-123",
            approve=approve,
        )
        history = self.query_one("#chat_history", VerticalScroll)

        if ok and approve:
            exec_res = self.gateway.execute_approved(approval_id)
            self.notify(
                f"Approved & Executed {exec_res.tool_name} (Status: {exec_res.execution_status.value})",
                title="Action Executed",
                severity="information",
            )
            # Mount approval execution card directly into Chat timeline!
            exec_card = (
                f"[bold #10b981][APPROVED & EXECUTED][/bold #10b981]\n"
                f"Tool: [bold]{exec_res.tool_name}[/bold] | Status: {exec_res.execution_status.value}\n"
                f"Output: {json.dumps(exec_res.result_data, indent=2, default=str)}"
            )
            history.mount(Static(exec_card, classes="query_output_card"))
            history.scroll_end(animate=True)

        elif ok and not approve:
            self.notify(f"Action {approval_id[:8]} was rejected.", title="Action Rejected", severity="warning")
            rej_card = (
                f"[bold #ef4444][OPERATOR REJECTED][/bold #ef4444]\n"
                f"Approval ID {approval_id[:8]} was explicitly denied by human operator."
            )
            history.mount(Static(rej_card, classes="enforce_card_block"))
            history.scroll_end(animate=True)
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
