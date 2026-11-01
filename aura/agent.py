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
    TaintState,
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


class GeminiLLMClient(LLMClient):
    """Google Gemini LLM client for autonomous agent reasoning with manual tool dispatch."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-2.5-flash",
    ) -> None:
        import os

        self._api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model_name = model_name

    def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        """Call Gemini to reason and propose next actions or final answer."""
        if not self._api_key:
            return LLMResponse(
                content="Error: GEMINI_API_KEY is not configured in .env or environment.",
                tool_calls=[],
            )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self._api_key)

            # Build Function Declarations from tool schemas
            function_declarations = []
            for t in tools:
                decl = types.FunctionDeclaration(
                    name=t["name"],
                    description=t.get("description", ""),
                    parameters_json_schema=t.get("parameters", {}),
                )
                function_declarations.append(decl)

            genai_tools = (
                [types.Tool(function_declarations=function_declarations)]
                if function_declarations
                else None
            )

            # Convert message history to Gemini contents
            system_instruction = None
            contents: list[types.Content] = []

            for msg in messages:
                role = msg.get("role")
                content_text = msg.get("content") or ""

                if role == "system":
                    system_instruction = content_text
                elif role == "user":
                    contents.append(
                        types.Content(
                            role="user",
                            parts=[types.Part.from_text(text=content_text)],
                        )
                    )
                elif role == "assistant":
                    parts = []
                    if content_text:
                        parts.append(types.Part.from_text(text=content_text))
                    tool_calls_raw = msg.get("tool_calls", [])
                    for tc in tool_calls_raw:
                        parts.append(
                            types.Part.from_function_call(
                                name=tc.get("tool_name", "unknown"),
                                args=tc.get("arguments", {}),
                            )
                        )
                    if not parts:
                        parts.append(types.Part.from_text(text=""))
                    contents.append(types.Content(role="model", parts=parts))
                elif role == "tool":
                    tool_name = msg.get("tool_call_id") or "tool"
                    contents.append(
                        types.Content(
                            role="user",
                            parts=[
                                types.Part.from_function_response(
                                    name=tool_name,
                                    response={"output": content_text},
                                )
                            ],
                        )
                    )

            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=genai_tools,
                temperature=0.2,
            )

            response = client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )

            tool_calls: list[ToolCallProposal] = []
            text_content = ""

            if response.function_calls:
                for fc in response.function_calls:
                    tool_calls.append(
                        ToolCallProposal(
                            call_id=fc.name,
                            tool_name=fc.name,
                            arguments=dict(fc.args) if fc.args else {},
                        )
                    )
            elif response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
                text_parts = [p.text for p in response.candidates[0].content.parts if getattr(p, "text", None)]
                text_content = " ".join(text_parts)
            else:
                text_content = response.text or ""

            return LLMResponse(
                content=text_content,
                tool_calls=tool_calls,
            )

        except Exception as exc:
            return LLMResponse(
                content=f"Gemini API Error: {exc}",
                tool_calls=[],
            )


class OpenRouterLLMClient(LLMClient):
    """OpenRouter LLM client (DeepSeek by default) with manual tool dispatch."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str | None = None,
    ) -> None:
        import os

        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self.model_name = (
            model_name
            or os.environ.get("OPENROUTER_MODEL")
            or os.environ.get("DEFAULT_LLM_MODEL")
            or "deepseek/deepseek-chat"
        )

    def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        """Call OpenRouter to reason and propose next actions or final answer."""
        if not self._api_key:
            return LLMResponse(
                content="Error: OPENROUTER_API_KEY is not configured in .env or environment.",
                tool_calls=[],
            )

        import json
        import httpx

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://aura-gateway.local",
            "X-Title": "AURA Multi-Agent Gateway",
        }

        # Convert tool schemas to standard OpenAI/OpenRouter function format
        openrouter_tools = []
        for t in tools:
            openrouter_tools.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {}),
                },
            })

        formatted_messages: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content") or ""
            tc_raw = m.get("tool_calls")
            if tc_raw:
                formatted_messages.append({
                    "role": role,
                    "content": content or None,
                    "tool_calls": [
                        {
                            "id": tc.get("call_id") or tc.get("tool_name", "call_1"),
                            "type": "function",
                            "function": {
                                "name": tc.get("tool_name"),
                                "arguments": json.dumps(tc.get("arguments", {})),
                            },
                        }
                        for tc in tc_raw
                    ],
                })
            elif role == "tool":
                formatted_messages.append({
                    "role": "tool",
                    "tool_call_id": m.get("tool_call_id") or "tool",
                    "content": content,
                })
            else:
                formatted_messages.append({
                    "role": role,
                    "content": content,
                })

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": formatted_messages,
            "temperature": 0.2,
        }
        if openrouter_tools:
            payload["tools"] = openrouter_tools
            payload["tool_choice"] = "auto"

        try:
            with httpx.Client(timeout=35.0) as client:
                resp = client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

            choice = data["choices"][0]["message"]
            text_content = choice.get("content") or ""
            tool_calls: list[ToolCallProposal] = []

            for tc in choice.get("tool_calls") or []:
                fn = tc.get("function", {})
                raw_args = fn.get("arguments", "{}")
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except Exception:
                        args = {}
                else:
                    args = dict(raw_args)

                tool_calls.append(
                    ToolCallProposal(
                        call_id=tc.get("id") or fn.get("name", "call_1"),
                        tool_name=fn.get("name", "unknown"),
                        arguments=args,
                    )
                )

            return LLMResponse(content=text_content, tool_calls=tool_calls)

        except Exception as exc:
            return LLMResponse(
                content=f"Error communicating with OpenRouter ({self.model_name}): {exc}",
                tool_calls=[],
            )



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
    messages: list[dict[str, Any]] = Field(default_factory=list)


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
        initial_taint: TaintState | None = None,
        message_history: list[dict[str, Any]] | None = None,
    ) -> AgentRunResult:
        """Execute the bounded agent loop for *goal* under *agent* RBAC."""
        active_run_id = run_id or f"run-{uuid.uuid4().hex[:8]}"
        deadline = datetime.now(timezone.utc) + timedelta(seconds=self.max_duration_seconds)

        # Get pure tool schemas (never adapter callables or credentials)
        tool_schemas = self.gateway.tool_registry.get_schemas()

        if message_history:
            messages: list[dict[str, Any]] = list(message_history)
            messages.append({"role": "user", "content": goal})
        else:
            messages = [
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
            trace_id=active_run_id,
            deadline=deadline,
            max_steps=self.max_steps,
            max_duration_seconds=self.max_duration_seconds,
            taint=initial_taint.model_copy() if initial_taint else TaintState(),
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
                    messages=messages,
                )

            # Query LLM
            llm_response = self.llm_client.generate(messages, tool_schemas)
            steps_taken += 1

            # If LLM produces final answer with no tool calls, finish
            if not llm_response.tool_calls:
                messages.append({"role": "assistant", "content": llm_response.content or ""})
                return AgentRunResult(
                    run_id=active_run_id,
                    agent_id=agent.agent_id,
                    completed=True,
                    final_answer=llm_response.content or "",
                    steps_taken=steps_taken,
                    total_tool_calls=total_tool_calls,
                    blocked_tool_calls=blocked_tool_calls,
                    results=execution_trace,
                    messages=messages,
                )

            # Record assistant call proposal in messages history
            messages.append({
                "role": "assistant",
                "content": llm_response.content or "",
                "tool_calls": [
                    {"call_id": p.call_id, "tool_name": p.tool_name, "arguments": p.arguments}
                    for p in llm_response.tool_calls
                ],
            })

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
            messages=messages,
        )
