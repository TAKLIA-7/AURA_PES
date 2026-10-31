"""
Unit tests for AURA Terminal User Interface (TUI).
"""

import asyncio
import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent

from aura.models import Decision, ExecutionStatus, GatewayResult, RiskLevel
from aura.tui import AuraApp


@pytest.mark.asyncio
async def test_tui_initialization_and_widgets():
    """Verify AuraApp mounts with all Claude Code-style components."""
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
            result_data="Revenue: $5.2M",
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
        assert "Q3 revenue" in combined
