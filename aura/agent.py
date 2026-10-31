"""
AURA Multi-Agent Orchestration — Built with LangChain and LangGraph.

Architecture:
- Supervisor node routes user goals to specialized worker agents:
    * Research Agent (read_file)
    * SQL Agent (run_query)
    * Email Agent (send_email)
    * Admin Agent (call_api, run_query, read_file)
- LLM Provider:
    * Uses Google Gemini (gemini-2.0-flash via GOOGLE_API_KEY) for agent reasoning & synthesis
    * When no API key is set, provides deterministic fallback routing
- Core Security Invariant:
    * NO AGENT directly invokes tools!
    * Every tool proposal is intercepted and dispatched through:
        AURA.handle(ToolRequest(...), run_ctx)
    * The actual AURA GatewayResult is returned to the agent.
    * Bounded agent loop (max 8 steps, 60s deadline).
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Annotated, Any, Literal, Optional, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from aura.gateway import AuraGateway
from aura.models import (
    Decision,
    ExecutionStatus,
    GatewayResult,
    RiskLevel,
    RunContext,
    ToolRequest,
)


class AuraAgentState(TypedDict):
    """The LangGraph state passed between all agent nodes."""
    messages: Annotated[list[BaseMessage], add_messages]
    task: str
    active_agent: str
    step_count: int
    max_steps: int
    deadline: float
    run_ctx: RunContext
    aura_results: list[GatewayResult]
    is_finished: bool
    final_response: str


class AuraMultiAgentSystem:
    """LangGraph-powered Multi-Agent System with AURA Security Enforcement."""

    def __init__(self, gateway: Optional[AuraGateway] = None, max_steps: int = 8, timeout_seconds: float = 60.0):
        self.gateway = gateway or AuraGateway()
        self.max_steps = max_steps
        self.timeout_seconds = timeout_seconds

        # Initialize Gemini LLM if GOOGLE_API_KEY is available
        self.llm = None
        google_api_key = os.environ.get("GOOGLE_API_KEY")
        if google_api_key:
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
                self.llm = ChatGoogleGenerativeAI(
                    model="gemini-2.5-flash",
                    api_key=google_api_key,
                    temperature=0.0,
                )
            except Exception:
                self.llm = None

        self.graph = self._build_graph()

    def _build_graph(self):
        """Construct the LangGraph StateGraph connecting supervisor and specialist agents."""
        workflow = StateGraph(AuraAgentState)

        # Register nodes
        workflow.add_node("supervisor", self._supervisor_node)
        workflow.add_node("research_agent", self._research_agent_node)
        workflow.add_node("sql_agent", self._sql_agent_node)
        workflow.add_node("email_agent", self._email_agent_node)
        workflow.add_node("admin_agent", self._admin_agent_node)
        workflow.add_node("finish", self._finish_node)

        # Edges from START to supervisor
        workflow.add_edge(START, "supervisor")

        # Conditional edges from supervisor to agents or finish
        workflow.add_conditional_edges(
            "supervisor",
            self._route_supervisor,
            {
                "research_agent": "research_agent",
                "sql_agent": "sql_agent",
                "email_agent": "email_agent",
                "admin_agent": "admin_agent",
                "finish": "finish",
            },
        )

        # Worker agents route back to supervisor to report findings or trigger next steps
        workflow.add_edge("research_agent", "supervisor")
        workflow.add_edge("sql_agent", "supervisor")
        workflow.add_edge("email_agent", "supervisor")
        workflow.add_edge("admin_agent", "supervisor")
        workflow.add_edge("finish", END)

        return workflow.compile()

    # ── Supervisor Node ──────────────────────────────────────────

    def _supervisor_node(self, state: AuraAgentState) -> dict[str, Any]:
        """Supervisor node: analyzes conversation state and determines next agent or termination."""
        step = state.get("step_count", 0) + 1
        now = time.time()
        deadline = state.get("deadline", now + 60.0)

        # Guard 1: Step count limit exceeded
        if step > state.get("max_steps", self.max_steps):
            return {
                "step_count": step,
                "active_agent": "finish",
                "messages": [AIMessage(content="[Supervisor] Maximum execution steps reached. Concluding run.")],
            }

        # Guard 2: Deadline reached
        if now >= deadline:
            return {
                "step_count": step,
                "active_agent": "finish",
                "messages": [AIMessage(content="[Supervisor] Global execution deadline reached. Concluding run.")],
            }

        messages = state["messages"]
        last_msg = messages[-1] if messages else HumanMessage(content="")
        text = str(last_msg.content).lower()

        # If last message was from a worker indicating completion or block
        worker_agents = {"research_agent", "sql_agent", "email_agent", "admin_agent"}
        if state.get("active_agent") in worker_agents and any(
            marker in text for marker in ["[aura blocked]", "[aura allowed]", "[aura approval required]", "task complete", "i have reported"]
        ):
            # Check if there is an egress step requested (e.g. prompt injection asking to send email)
            if "send" in text and "email" in text and state.get("active_agent") != "email_agent":
                return {
                    "step_count": step,
                    "active_agent": "email_agent",
                    "messages": [AIMessage(content="[Supervisor] Routing to Email Agent for outbound email request.")],
                }
            return {
                "step_count": step,
                "active_agent": "finish",
                "messages": [AIMessage(content="[Supervisor] Specialist agent finished. Concluding workflow.")],
            }

        # Route initial task
        initial_task = state.get("task", "").lower()
        if any(k in initial_task for k in ["read", "doc", "document", "report", "memo", "financials"]):
            target = "research_agent"
        elif any(k in initial_task for k in ["query", "sql", "count", "revenue", "database"]):
            target = "sql_agent"
        elif any(k in initial_task for k in ["email", "send mail", "notify"]):
            target = "email_agent"
        elif any(k in initial_task for k in ["admin", "api", "delete", "config", "provision"]):
            target = "admin_agent"
        else:
            target = "research_agent"

        return {
            "step_count": step,
            "active_agent": target,
            "messages": [AIMessage(content=f"[Supervisor] Routing task to {target}.")],
        }

    def _route_supervisor(self, state: AuraAgentState) -> str:
        """Route to active agent or finish."""
        return state.get("active_agent", "finish")

    # ── Specialist Agent Nodes ───────────────────────────────────

    def _research_agent_node(self, state: AuraAgentState) -> dict[str, Any]:
        """Research Agent: Authorized to read registered documents. Passes all reads through AURA."""
        run_ctx = state["run_ctx"]
        run_ctx.agent_id = "research_agent"
        run_ctx.agent_role = "research"

        task = state.get("task", "")
        doc_id = "doc:public_report"
        if "internal" in task.lower():
            doc_id = "doc:internal_memo"
        elif "confidential" in task.lower():
            doc_id = "doc:confidential_financials"
        elif "injection" in task.lower() or "partner" in task.lower():
            doc_id = "doc:injected_document"
        elif "secret" in task.lower() or "key" in task.lower():
            doc_id = "doc:top_secret_keys"
        elif "nonexistent" in task.lower() or "fake" in task.lower():
            doc_id = "doc:fake_nonexistent_doc"

        match = re.search(r"\b(doc:[a-zA-Z0-9_]+)\b", task)
        if match:
            doc_id = match.group(1)

        request = ToolRequest(
            agent_id="research_agent",
            tool_name="read_file",
            parameters={"doc_id": doc_id},
        )

        gw_result = self.gateway.handle(request, run_ctx)
        state_results = list(state.get("aura_results", []))
        state_results.append(gw_result)

        agent_msg = gw_result.to_agent_message()
        return {
            "messages": [AIMessage(content=f"[Research Agent] {agent_msg}")],
            "aura_results": state_results,
            "run_ctx": run_ctx,
        }

    def _sql_agent_node(self, state: AuraAgentState) -> dict[str, Any]:
        """SQL Agent: Authorized for allowlisted queries. Passes all queries through AURA."""
        run_ctx = state["run_ctx"]
        run_ctx.agent_id = "sql_agent"
        run_ctx.agent_role = "sql"

        task = state.get("task", "").lower()
        query_name = "get_user_count"
        params: dict[str, Any] = {"active": True}

        if "revenue" in task:
            query_name = "get_revenue_summary"
            params = {"year": 2024}
        elif "product" in task:
            query_name = "get_top_products"
            params = {"limit": 5}
        elif "insert" in task or "note" in task or "write" in task:
            query_name = "insert_audit_note"
            params = {"note": "Automated security test", "created_by": "sql_agent"}
        elif "raw" in task or "select * from users" in task:
            query_name = "raw_unauthorized_query"
            params = {}

        request = ToolRequest(
            agent_id="sql_agent",
            tool_name="run_query",
            parameters={"query_name": query_name, "params": params},
        )

        gw_result = self.gateway.handle(request, run_ctx)
        state_results = list(state.get("aura_results", []))
        state_results.append(gw_result)

        agent_msg = gw_result.to_agent_message()
        return {
            "messages": [AIMessage(content=f"[SQL Agent] {agent_msg}")],
            "aura_results": state_results,
            "run_ctx": run_ctx,
        }

    def _email_agent_node(self, state: AuraAgentState) -> dict[str, Any]:
        """Email Agent: Prepares outbound emails subject to policy and taint restrictions."""
        run_ctx = state["run_ctx"]
        run_ctx.agent_id = "email_agent"
        run_ctx.agent_role = "email"

        task = state.get("task", "")
        to_addr = "partner@company.com"
        subject = "Scheduled Report"
        body = "Here is the summary."

        email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", task)
        if email_match:
            to_addr = email_match.group(0)
        elif "competitor" in task.lower():
            to_addr = "audit@competitor.com"
        elif "external" in task.lower():
            to_addr = "external-partner@partner.org"

        if run_ctx.tainted:
            body = "Confidential document excerpt: Projected revenue $3.2B."

        request = ToolRequest(
            agent_id="email_agent",
            tool_name="send_email",
            parameters={"to": to_addr, "subject": subject, "body": body},
        )

        gw_result = self.gateway.handle(request, run_ctx)
        state_results = list(state.get("aura_results", []))
        state_results.append(gw_result)

        agent_msg = gw_result.to_agent_message()
        return {
            "messages": [AIMessage(content=f"[Email Agent] {agent_msg}")],
            "aura_results": state_results,
            "run_ctx": run_ctx,
        }

    def _admin_agent_node(self, state: AuraAgentState) -> dict[str, Any]:
        """Admin Agent: Performs administrative API calls or management operations."""
        run_ctx = state["run_ctx"]
        run_ctx.agent_id = "admin_agent"
        run_ctx.agent_role = "admin"

        task = state.get("task", "").lower()
        operation = "status_check"
        if "delete" in task:
            operation = "delete"
        elif "permission" in task:
            operation = "update_permissions"

        request = ToolRequest(
            agent_id="admin_agent",
            tool_name="call_api",
            parameters={"operation": operation, "params": {}},
        )

        gw_result = self.gateway.handle(request, run_ctx)
        state_results = list(state.get("aura_results", []))
        state_results.append(gw_result)

        agent_msg = gw_result.to_agent_message()
        return {
            "messages": [AIMessage(content=f"[Admin Agent] {agent_msg}")],
            "aura_results": state_results,
            "run_ctx": run_ctx,
        }

    def _finish_node(self, state: AuraAgentState) -> dict[str, Any]:
        """Finish node: synthesizes final response based exclusively on actual AURA outcomes."""
        results = state.get("aura_results", [])
        if not results:
            response_text = "No protected operations were executed."
        else:
            summaries = []
            for r in results:
                if r.decision == Decision.BLOCK:
                    summaries.append(f"Operation '{r.tool_name}' was BLOCKED by AURA: {r.reason}")
                elif r.decision == Decision.APPROVAL:
                    summaries.append(f"Operation '{r.tool_name}' requires human approval (ID: {r.approval_id}).")
                elif r.decision == Decision.ALLOW and r.execution_status == ExecutionStatus.COMPLETED:
                    summaries.append(f"Operation '{r.tool_name}' completed successfully.")
                else:
                    summaries.append(f"Operation '{r.tool_name}': {r.decision.value} ({r.execution_status.value})")
            response_text = "Execution completed:\n" + "\n".join(f"- {s}" for s in summaries)

        # If Gemini LLM is available, use it to synthesize a comprehensive response
        if self.llm and results:
            prompt = (
                f"You are the AURA Multi-Agent Security Assistant.\n"
                f"User task: {state.get('task', '')}\n\n"
                f"Authoritative AURA Execution Results:\n"
                f"{json.dumps([r.model_dump(include={'tool_name', 'decision', 'execution_status', 'reason_code', 'reason', 'result_data'}) for r in results], default=str)}\n\n"
                f"Provide a concise, helpful response to the user based STRICTLY on the execution results.\n"
                f"CRITICAL SECURITY RULES:\n"
                f"- If an operation was BLOCKED, clearly report it was blocked and why. Never claim it succeeded.\n"
                f"- If an operation requires APPROVAL, state that it is pending human approval.\n"
                f"- Only report success if execution_status is COMPLETED.\n"
            )
            try:
                ai_resp = self.llm.invoke([HumanMessage(content=prompt)])
                response_text = str(ai_resp.content)
            except Exception:
                pass

        return {
            "is_finished": True,
            "final_response": response_text,
            "messages": [AIMessage(content=response_text)],
        }

    # ── Main Run Invocation ──────────────────────────────────────

    def run(self, task: str, session_id: Optional[str] = None) -> dict[str, Any]:
        """Execute a user task across the LangGraph multi-agent network."""
        run_ctx = RunContext(
            agent_id="orchestrator",
            agent_role="supervisor",
            session_id=session_id or f"sess_{int(time.time())}",
            max_steps=self.max_steps,
        )

        initial_state: AuraAgentState = {
            "messages": [HumanMessage(content=task)],
            "task": task,
            "active_agent": "supervisor",
            "step_count": 0,
            "max_steps": self.max_steps,
            "deadline": time.time() + self.timeout_seconds,
            "run_ctx": run_ctx,
            "aura_results": [],
            "is_finished": False,
            "final_response": "",
        }

        final_state = self.graph.invoke(initial_state)
        return final_state
