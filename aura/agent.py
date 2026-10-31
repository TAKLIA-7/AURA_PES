"""AURA Bounded Agent Loop with Manual Tool Dispatch.

Invariants:
  - Automatic SDK function execution is strictly disabled.
  - Every proposed tool call must pass through `AURA.handle(request, run_ctx)`.
  - The loop is bounded to maximum 8 steps and 60 seconds total.
  - A single global deadline spans agent, JEV, and tool operations.
  - Returns the actual AURA result to the agent; never lets it assume a blocked action succeeded.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from pydantic import BaseModel, Field

from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    AuraRequest,
    AuraResult,
    Decision,
    RunContext,
    ToolAction,
)


class ToolCallProposal(BaseModel):
    """A tool call proposed by the LLM."""
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    """Normalized response from an LLM provider."""
    content: str | None = None
    tool_calls: list[ToolCallProposal] = Field(default_factory=list)


class LLMClient(ABC):
    """Abstract interface for LLM interaction."""

    @abstractmethod
    def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        """Generate next agent step with tools provided as JSON schemas."""
        ...


class ScriptedLLMClient(LLMClient):
    """Deterministic scripted LLM client for testing and predictable evaluation."""

    def __init__(self, steps: list[LLMResponse]) -> None:
        self.steps = list(steps)
        self.step_index = 0

    def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        if self.step_index < len(self.steps):
            response = self.steps[self.step_index]
            self.step_index += 1
            return response
        return LLMResponse(content="Task completed.")


class AgentRunResult(BaseModel):
    """Summary of a bounded agent run."""
    run_id: str
    agent_id: str
    completed: bool
    final_answer: str | None = None
    steps_taken: int = 0
    total_tool_calls: int = 0
    blocked_tool_calls: int = 0
    results: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class AgentLoop:
    """Bounded agent execution loop with strict manual enforcement."""

    def __init__(
        self,
        gateway: AuraGateway,
        llm_client: LLMClient,
        max_steps: int = 8,
        max_duration_seconds: float = 60.0,
    ) -> None:
        self.gateway = gateway
        self.llm_client = llm_client
        self.max_steps = max_steps
        self.max_duration_seconds = max_duration_seconds

    def run(
        self,
        goal: str,
        agent: AgentIdentity,
        run_id: str | None = None,
    ) -> AgentRunResult:
        """Execute the bounded agent loop for *goal* under *agent* RBAC."""
        active_run_id = run_id or f"run-{uuid.uuid4().hex[:8]}"
        deadline = datetime.now(timezone.utc) + timedelta(seconds=self.max_duration_seconds)

        # Get pure tool schemas (never adapter callables or credentials)
        tool_schemas = self.gateway.tool_registry.get_schemas()

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": goal},
        ]

        # Shared execution context across steps with global deadline
        dummy_req = AuraRequest(
            request_id=f"{active_run_id}-init",
            trace_id=active_run_id,
            action=ToolAction.READ_FILE,
            agent=agent,
        )
        run_ctx = RunContext(
            request=dummy_req,
            deadline=deadline,
            max_steps=self.max_steps,
            max_duration_seconds=self.max_duration_seconds,
        )

        steps_taken = 0
        total_tool_calls = 0
        blocked_tool_calls = 0
        execution_trace: list[dict[str, Any]] = []

        while steps_taken < self.max_steps:
            # Check global deadline
            if datetime.now(timezone.utc) > deadline:
                return AgentRunResult(
                    run_id=active_run_id,
                    agent_id=agent.agent_id,
                    completed=False,
                    steps_taken=steps_taken,
                    total_tool_calls=total_tool_calls,
                    blocked_tool_calls=blocked_tool_calls,
                    results=execution_trace,
                    error="GLOBAL_DEADLINE_EXCEEDED",
                )

            # Query LLM
            llm_response = self.llm_client.generate(messages, tool_schemas)
            steps_taken += 1

            # If LLM produces final answer with no tool calls, finish
            if not llm_response.tool_calls:
                return AgentRunResult(
                    run_id=active_run_id,
                    agent_id=agent.agent_id,
                    completed=True,
                    final_answer=llm_response.content or "",
                    steps_taken=steps_taken,
                    total_tool_calls=total_tool_calls,
                    blocked_tool_calls=blocked_tool_calls,
                    results=execution_trace,
                )

            # Process proposed tool calls MANUALLY through AURA
            for proposal in llm_response.tool_calls:
                total_tool_calls += 1

                # Validate tool action name
                try:
                    action = ToolAction(proposal.tool_name)
                except ValueError:
                    # Invalid tool proposed: return block message
                    blocked_tool_calls += 1
                    feedback = f"ACTION_BLOCKED: Unknown tool action '{proposal.tool_name}'"
                    messages.append({
                        "role": "tool",
                        "tool_call_id": proposal.call_id,
                        "content": feedback,
                    })
                    execution_trace.append({
                        "tool": proposal.tool_name,
                        "decision": "BLOCK",
                        "error": "UNKNOWN_ACTION",
                    })
                    continue

                step_request = AuraRequest(
                    request_id=f"{active_run_id}-step-{steps_taken}",
                    trace_id=active_run_id,
                    action=action,
                    params=proposal.arguments,
                    agent=agent,
                )
                run_ctx.request = step_request

                # Manual dispatch to AURA.handle()
                aura_result = self.gateway.handle(step_request, run_ctx)

                trace_record = {
                    "tool": action.value,
                    "params": proposal.arguments,
                    "decision": aura_result.decision.value,
                    "status": aura_result.execution_status,
                }

                if aura_result.decision == Decision.ALLOW and aura_result.execution_status == "success":
                    # Successful authorized execution
                    content = str(aura_result.execution_result)
                    trace_record["result"] = aura_result.execution_result
                else:
                    # Security Block / Error: Return real AURA outcome to the agent
                    blocked_tool_calls += 1
                    content = (
                        f"ACTION_BLOCKED: Decision={aura_result.decision.value}, "
                        f"Reason={aura_result.error or 'Security Policy'}"
                    )
                    trace_record["error"] = aura_result.error

                execution_trace.append(trace_record)
                messages.append({
                    "role": "tool",
                    "tool_call_id": proposal.call_id,
                    "content": content,
                })

        # Exceeded max steps
        return AgentRunResult(
            run_id=active_run_id,
            agent_id=agent.agent_id,
            completed=False,
            steps_taken=steps_taken,
            total_tool_calls=total_tool_calls,
            blocked_tool_calls=blocked_tool_calls,
            results=execution_trace,
            error="MAX_STEPS_EXCEEDED",
        )
