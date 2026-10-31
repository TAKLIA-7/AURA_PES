"""
Unit tests for AURA Terminal User Interface (TUI).
"""

import asyncio
import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent

from aura.models import Decision, ExecutionStatus, GatewayResult, RiskLevel
from aura.tui import ApprovalModalScreen, AuraApp, make_gradient_logo


@pytest.mark.asyncio
async def test_tui_initialization_and_widgets():
    """Verify AuraApp mounts with purplish-blue logo and Claude Code-style components."""
    app = AuraApp()
    async with app.run_test() as pilot:
        # Check banner
        banner = app.query_one("#ascii_banner", Static)
        assert banner is not None

        # Check tabs
        tabbed = app.query_one(TabbedContent)
        assert tabbed is not None
        assert app.query_one("#tab_dashboard") is not None
        assert app.query_one("#tab_logs") is not None
        assert app.query_one("#tab_approvals") is not None

        # Check input and buttons
        prompt_input = app.query_one("#prompt_input", Input)
        assert prompt_input is not None
        assert app.query_one("#btn_send") is not None
        assert app.query_one("#btn_demo1") is not None
        assert app.query_one("#btn_demo4") is not None

        # Check Audit DataTable
        table = app.query_one("#audit_table", DataTable)
        assert table is not None
        assert len(table.columns) == 8


@pytest.mark.asyncio
async def test_tui_tab_navigation_and_hash_verification():
    """Verify tab switching and cryptographic hash chain verification."""
    app = AuraApp()
    async with app.run_test() as pilot:
        # Switch to logs
        app.action_switch_tab("tab_logs")
        await pilot.pause()
        assert app.query_one(TabbedContent).active == "tab_logs"

        # Verify hash chain
        app.action_verify_hash_chain()
        await pilot.pause()
        integrity_pill = app.query_one("#pill_integrity", Static)
        assert "VERIFIED" in str(integrity_pill.render())

        # Switch to approvals
        app.action_switch_tab("tab_approvals")
        await pilot.pause()
        assert app.query_one(TabbedContent).active == "tab_approvals"


@pytest.mark.asyncio
async def test_tui_enforcement_rendering():
    """Verify that GatewayResult objects render as distinct visual cards."""
    app = AuraApp()
    async with app.run_test() as pilot:
        fake_gw_result = GatewayResult(
            request_id="req_test_123",
            trace_id="tr_test_123",
            decision=Decision.ALLOW,
            execution_status=ExecutionStatus.COMPLETED,
            risk_level=RiskLevel.LOW,
            tool_name="read_file",
            result_data={"doc_id": "doc:public_report", "content": "Revenue: $5.2M"},
        )
        fake_res = {
            "aura_results": [fake_gw_result],
            "final_response": "The public report shows Q3 revenue of $5.2M.",
        }

        status_widget = Static("status", id="temp_status")
        chat_history = app.query_one("#chat_history")
        chat_history.mount(status_widget)

        app._handle_agent_completed(fake_res, status_widget)
        await pilot.pause()

        # Check chat history has mounted Static cards
        cards = chat_history.query(Static)
        card_texts = [str(c.render()) for c in cards]
        combined = " ".join(card_texts)
        assert "read_file" in combined or "AURA AUTHORIZED" in combined
        assert "Revenue: $5.2M" in combined


@pytest.mark.asyncio
async def test_tui_query_output_card_displayed():
    """Verify that query result data is explicitly displayed on the dashboard."""
    app = AuraApp()
    async with app.run_test() as pilot:
        query_gw_result = GatewayResult(
            request_id="req_sql_456",
            trace_id="tr_sql_456",
            decision=Decision.ALLOW,
            execution_status=ExecutionStatus.COMPLETED,
            risk_level=RiskLevel.LOW,
            tool_name="run_query",
            result_data={
                "query_name": "get_revenue_summary",
                "results": [
                    {"quarter": "Q1", "total": 520000},
                    {"quarter": "Q2", "total": 610000},
                ],
                "row_count": 2,
            },
        )
        fake_res = {
            "aura_results": [query_gw_result],
            "final_response": "Q1 and Q2 revenue amounts to $1.13M.",
        }

        status_widget = Static("status", id="temp_status")
        chat_history = app.query_one("#chat_history")
        chat_history.mount(status_widget)

        app._handle_agent_completed(fake_res, status_widget)
        await pilot.pause()

        # Verify output card is mounted
        output_cards = chat_history.query(".query_output_card")
        assert len(output_cards) == 1
        output_text = str(output_cards[0].render())
        assert "DATABASE QUERY OUTPUT: get_revenue_summary" in output_text
        assert "520000" in output_text
        assert "610000" in output_text


@pytest.mark.asyncio
async def test_tui_approval_modal_popup():
    """Verify that approval requests automatically trigger the interactive popup modal."""
    from aura.models import ToolRequest, RunContext
    app = AuraApp()
    async with app.run_test() as pilot:
        req = ToolRequest(
            agent_id="sql_agent",
            tool_name="run_query",
            parameters={"query_name": "insert_audit_note", "params": {"note": "patch"}},
        )
        ctx = RunContext(agent_id="sql_agent", agent_role="sql")
        record = app.gateway.approvals.create_pending_approval(req, ctx, "v1.0")

        approval_gw_result = GatewayResult(
            request_id="req_sensitive_789",
            trace_id="tr_sensitive_789",
            decision=Decision.APPROVAL,
            execution_status=ExecutionStatus.NOT_EXECUTED,
            risk_level=RiskLevel.HIGH,
            tool_name="run_query",
            approval_id=record.approval_id,
            reason="Sensitive write query requires approval",
        )
        fake_res = {
            "aura_results": [approval_gw_result],
            "final_response": "Operation is pending human approval.",
        }

        status_widget = Static("status", id="temp_status")
        chat_history = app.query_one("#chat_history")
        chat_history.mount(status_widget)

        # Triggers automatic popup
        app._handle_agent_completed(fake_res, status_widget)
        await pilot.pause()

        # Check modal screen is active
        active_screen = app.screen
        assert isinstance(active_screen, ApprovalModalScreen)
        assert active_screen.approval_id == record.approval_id

        # Simulate user approving via modal action
        active_screen.action_approve()
        await pilot.pause()

        # Modal is dismissed
        assert not isinstance(app.screen, ApprovalModalScreen)
