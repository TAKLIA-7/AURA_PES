"""Integration Tests: Multi-Step End-to-End Workflows for AURA."""

from __future__ import annotations

import pytest

from aura.agent import AgentLoop, LLMResponse, ScriptedLLMClient, ToolCallProposal
from aura.gateway import AuraGateway
from aura.models import AgentIdentity, Decision, ToolAction
from tests.conftest import FIXTURES_DIR


@pytest.fixture
def gateway():
    return AuraGateway.create_default(config_dir=str(FIXTURES_DIR))


class TestEndToEndWorkflows:
    def test_analyst_multi_step_read_and_query(self, gateway, analyst_agent):
        """Workflow: Analyst reads internal report, executes allowlisted query, completes goal."""
        read_adapter = gateway.tool_registry.get(ToolAction.READ_FILE)
        query_adapter = gateway.tool_registry.get(ToolAction.RUN_QUERY)
        read_adapter.reset_counter()
        query_adapter.reset_counter()

        steps = [
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="read_file",
                        arguments={"doc_id": "internal/report_q4"},
                    )
                ]
            ),
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="run_query",
                        arguments={
                            "query_name": "reports/monthly_summary",
                            "params": {"year": 2026},
                        },
                    )
                ]
            ),
            LLMResponse(
                content="Analysis complete: Q4 shows 15% revenue growth, and monthly reports confirm targets met."
            ),
        ]
        loop = AgentLoop(gateway=gateway, llm_client=ScriptedLLMClient(steps))
        run_res = loop.run("Perform Q4 quarterly financial analysis", agent=analyst_agent)

        assert run_res.completed is True
        assert run_res.steps_taken == 3
        assert run_res.total_tool_calls == 2
        assert run_res.blocked_tool_calls == 0
        assert read_adapter.call_count == 1
        assert query_adapter.call_count == 1

        # Check audit trail
        trace = gateway.audit_logger.get_trace(run_res.run_id)
        assert len(trace) == 2
        assert trace[0].action == ToolAction.READ_FILE
        assert trace[1].action == ToolAction.RUN_QUERY

    def test_mailer_multi_step_with_denied_confidential_read(self, gateway, mailer_agent):
        """Workflow: Mailer attempts unauthorized confidential read, is blocked, then sends authorized email."""
        read_adapter = gateway.tool_registry.get(ToolAction.READ_FILE)
        email_adapter = gateway.tool_registry.get(ToolAction.SEND_EMAIL)
        read_adapter.reset_counter()
        email_adapter.reset_counter()

        steps = [
            # 1. Mailer tries to read confidential HR records -> BLOCKED
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="read_file",
                        arguments={"doc_id": "confidential/hr_records"},
                    )
                ]
            ),
            # 2. Mailer sends notification about the error -> ALLOWED
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="send_email",
                        arguments={"to": "security@company.com", "body": "Access was denied as expected."},
                    )
                ]
            ),
            LLMResponse(
                content="Notified security about denied access."
            ),
        ]
        loop = AgentLoop(gateway=gateway, llm_client=ScriptedLLMClient(steps))
        run_res = loop.run("Handle confidential notification", agent=mailer_agent)

        assert run_res.completed is True
        assert run_res.total_tool_calls == 2
        assert run_res.blocked_tool_calls == 1
        # Read adapter counter is 0 because confidential read was blocked!
        assert read_adapter.call_count == 0
        assert email_adapter.call_count == 1

