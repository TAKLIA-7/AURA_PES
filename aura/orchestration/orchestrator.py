"""Multi-Agent Orchestrator and Lifecycle Manager.

Coordinates multiple independent AI agents under central AURA enforcement:
  - Dynamic agent registration and lifecycle management (IDLE, BUSY, STOPPED).
  - RBAC inspection and tool assignment visibility.
  - Controlled message routing through the secure MessageBroker.
  - Zero-privilege inheritance across delegated subtasks.
  - End-to-end trace correlation and cryptographic audit log linking.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from aura.agent import AgentLoop, AgentRunResult, LLMClient, ScriptedLLMClient
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
from aura.orchestration.broker import MessageBroker
from aura.orchestration.models import (
    AgentStatus,
    DelegationPolicy,
    InterAgentMessage,
    ManagedAgentInfo,
    MessageType,
)
from aura.rbac import AgentConfig, PermissionEntry


class OrchestratorError(Exception):
    """Raised on orchestration or agent execution errors."""


class MultiAgentOrchestrator:
    """Central orchestrator managing multi-agent lifecycles and interactions."""

    def __init__(
        self,
        gateway: AuraGateway,
        broker: MessageBroker | None = None,
        default_llm_client: LLMClient | None = None,
    ) -> None:
        self.gateway = gateway
        self.broker = broker or MessageBroker(gateway)
        self.default_llm_client = default_llm_client or ScriptedLLMClient([])

        self._agent_llms: dict[str, LLMClient] = {}
        self._agent_statuses: dict[str, AgentStatus] = {}
        self._agent_metrics: dict[str, dict[str, int]] = {}
        self._event_listeners: list[Callable[[dict[str, Any]], None]] = []

        # Connect broker listener to orchestrator event bus
        self.broker.add_listener(self._on_broker_message)

        # Initialize agents from RBAC
        self._refresh_agents_from_rbac()

    def add_event_listener(self, listener: Callable[[dict[str, Any]], None]) -> None:
        """Subscribe to live orchestration events for UI monitoring."""
        self._event_listeners.append(listener)

    def _emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **data,
        }
        for listener in self._event_listeners:
            try:
                listener(payload)
            except Exception:
                pass

    def _on_broker_message(self, message: InterAgentMessage, result: AuraResult) -> None:
        self._emit_event(
            "INTER_AGENT_MESSAGE",
            {
                "sender_id": message.sender_id,
                "receiver_id": message.receiver_id,
                "task_id": message.task_id,
                "message_type": message.message_type.value,
                "message_digest": message.message_digest[:16] + "...",
                "decision": result.decision.value,
                "error": result.error,
            },
        )

    def _refresh_agents_from_rbac(self) -> None:
        rbac = self.gateway.rbac_manager
        if not rbac:
            return

        for agent_id in rbac.list_agents():
            if agent_id not in self._agent_statuses:
                self._agent_statuses[agent_id] = AgentStatus.IDLE
                self._agent_metrics[agent_id] = {
                    "processed": 0,
                    "succeeded": 0,
                    "failed": 0,
                }

    def list_agents(self) -> list[ManagedAgentInfo]:
        """List all managed agents, their roles, tool assignments, and statuses."""
        rbac = self.gateway.rbac_manager
        if not rbac:
            return []

        result: list[ManagedAgentInfo] = []
        for agent_id in rbac.list_agents():
            cfg = rbac.get_agent_config(agent_id)
            if not cfg:
                continue
            assigned_tools = self._resolve_tools_for_role(cfg.role, cfg.permissions)
            allowed_sens = self._resolve_sensitivities_for_role(cfg.permissions)
            metrics = self._agent_metrics.get(agent_id, {"processed": 0, "succeeded": 0, "failed": 0})

            info = ManagedAgentInfo(
                identity=AgentIdentity(agent_id=agent_id, role=cfg.role),
                status=self._agent_statuses.get(agent_id, AgentStatus.IDLE),
                description=cfg.description,
                assigned_tools=assigned_tools,
                allowed_sensitivities=allowed_sens,
                tasks_processed=metrics["processed"],
                tasks_succeeded=metrics["succeeded"],
                tasks_failed=metrics["failed"],
            )
            result.append(info)
        return result

    def get_agent_info(self, agent_id: str) -> ManagedAgentInfo | None:
        """Retrieve inspection info for a specific agent."""
        for agent in self.list_agents():
            if agent.identity.agent_id == agent_id:
                return agent
        return None

    def register_agent(
        self,
        agent_id: str,
        role: str,
        description: str = "",
        permissions: list[dict[str, Any]] | None = None,
        llm_client: LLMClient | None = None,
    ) -> ManagedAgentInfo:
        """Dynamically register a new agent into the system and RBAC."""
        rbac = self.gateway.rbac_manager
        if not rbac:
            raise OrchestratorError("RBAC Manager not available")

        # Convert raw permissions if provided
        perms: list[PermissionEntry] = []
        if permissions:
            for p in permissions:
                perms.append(PermissionEntry(**p))
        else:
            perms = self._get_default_permissions_for_role(role)

        agent_cfg = AgentConfig(
            agent_id=agent_id,
            role=role,
            description=description,
            permissions=perms,
        )
        rbac._agents[agent_id] = agent_cfg
        self._agent_statuses[agent_id] = AgentStatus.IDLE
        self._agent_metrics[agent_id] = {"processed": 0, "succeeded": 0, "failed": 0}

        if llm_client:
            self._agent_llms[agent_id] = llm_client

        self._emit_event(
            "AGENT_REGISTERED",
            {"agent_id": agent_id, "role": role, "description": description},
        )
        return self.get_agent_info(agent_id)  # type: ignore

    def set_agent_status(self, agent_id: str, status: AgentStatus) -> None:
        """Update an agent's lifecycle status."""
        if agent_id not in self._agent_statuses:
            raise OrchestratorError(f"Agent '{agent_id}' does not exist")
        old_status = self._agent_statuses[agent_id]
        self._agent_statuses[agent_id] = status
        self._emit_event(
            "AGENT_STATUS_CHANGED",
            {"agent_id": agent_id, "old_status": old_status.value, "new_status": status.value},
        )

    def set_agent_llm(self, agent_id: str, llm_client: LLMClient) -> None:
        """Assign a custom LLM client to an agent."""
        self._agent_llms[agent_id] = llm_client

    def delegate_task(
        self,
        sender_id: str,
        receiver_id: str,
        task: str,
        trace_id: str | None = None,
        taint_state: TaintState | None = None,
    ) -> tuple[AuraResult, InterAgentMessage]:
        """Delegate a task from one agent to another through the controlled broker."""
        active_trace = trace_id or f"trace-{uuid.uuid4().hex[:12]}"
        task_id = f"task-{uuid.uuid4().hex[:8]}"

        msg = InterAgentMessage(
            sender_id=sender_id,
            receiver_id=receiver_id,
            task_id=task_id,
            trace_id=active_trace,
            message_type=MessageType.TASK_DELEGATION,
            content=task,
            taint_state=taint_state or TaintState(),
        )

        delivery_result = self.broker.send_message(msg)
        return delivery_result, msg

    def execute_delegated_task(
        self,
        receiver_id: str,
        message: InterAgentMessage,
    ) -> AgentRunResult:
        """Execute a task received by an agent via delegation.

        Invariants:
          - The receiver agent treats the message as untrusted input.
          - The receiver agent's actions are validated strictly against ITS OWN permissions.
          - Sender permissions are NEVER inherited.
          - Taint state from the message is applied to the receiver's run context.
        """
        if self._agent_statuses.get(receiver_id) == AgentStatus.STOPPED:
            return AgentRunResult(
                run_id=message.task_id,
                agent_id=receiver_id,
                completed=False,
                error="AGENT_IS_STOPPED",
            )

        self.set_agent_status(receiver_id, AgentStatus.BUSY)
        llm = self._agent_llms.get(receiver_id) or self.default_llm_client

        rbac = self.gateway.rbac_manager
        agent_ident = rbac.get_agent(receiver_id) if rbac else AgentIdentity(agent_id=receiver_id, role="unknown")

        self._emit_event(
            "AGENT_TASK_STARTED",
            {
                "agent_id": receiver_id,
                "task_id": message.task_id,
                "delegated_by": message.sender_id,
                "trace_id": message.trace_id,
                "tainted": message.taint_state.tainted,
            },
        )

        # Build custom AgentLoop
        loop = AgentLoop(
            gateway=self.gateway,
            llm_client=llm,
            max_steps=6,
            max_duration_seconds=30.0,
        )

        # Dispatch with the receiver's own identity and propagated taint state
        task_str = str(message.content)
        run_res = loop.run(task_str, agent=agent_ident, initial_taint=message.taint_state)

        metrics = self._agent_metrics[receiver_id]
        metrics["processed"] += 1
        if run_res.completed and run_res.blocked_tool_calls == 0:
            metrics["succeeded"] += 1
        else:
            metrics["failed"] += 1

        self.set_agent_status(receiver_id, AgentStatus.IDLE)
        self._emit_event(
            "AGENT_TASK_COMPLETED",
            {
                "agent_id": receiver_id,
                "task_id": message.task_id,
                "completed": run_res.completed,
                "tool_calls": run_res.total_tool_calls,
                "blocked": run_res.blocked_tool_calls,
                "error": run_res.error,
            },
        )

        # Send response message back to delegator
        reply_msg = InterAgentMessage(
            sender_id=receiver_id,
            receiver_id=message.sender_id,
            task_id=message.task_id,
            trace_id=message.trace_id,
            message_type=MessageType.TASK_RESULT if run_res.completed else MessageType.ERROR,
            content=run_res.final_answer or run_res.error or "No output",
            taint_state=message.taint_state,  # Propagate taint back
        )
        self.broker.send_message(reply_msg)
        return run_res

    def run_collaborative_workflow(
        self,
        analyst_id: str = "analyst_agent",
        reader_id: str = "reader_agent",
        mailer_id: str = "mailer_agent",
        doc_id: str = "public/readme",
        recipient: str = "internal-team@corp.local",
    ) -> dict[str, Any]:
        """Execute a coordinated multi-agent workflow:

        1. Analyst delegates document inspection to Reader Agent.
        2. Reader Agent uses READ_FILE to retrieve document.
        3. Reader returns findings to Analyst.
        4. Analyst analyzes findings and delegates report email to Mailer Agent.
        5. Mailer Agent uses SEND_EMAIL to deliver report.
        """
        trace_id = f"trace-collab-{uuid.uuid4().hex[:8]}"
        self._emit_event("WORKFLOW_STARTED", {"workflow": "Collaborative Analysis", "trace_id": trace_id})

        # Step 1: Analyst delegates doc read to Reader
        del_res, msg1 = self.delegate_task(
            sender_id=analyst_id,
            receiver_id=reader_id,
            task=f"Please read the document '{doc_id}' and provide a summary.",
            trace_id=trace_id,
        )
        if del_res.decision != Decision.ALLOW:
            return {"status": "BLOCKED", "step": "Analyst -> Reader Delegation", "error": del_res.error}

        # Step 2: Reader executes read task
        # Provide scripted response for reader if using ScriptedLLMClient
        from aura.agent import LLMResponse, ToolCallProposal

        reader_step = LLMResponse(
            tool_calls=[ToolCallProposal(tool_name="read_file", arguments={"doc_id": doc_id})]
        )
        reader_finish = LLMResponse(content=f"Document '{doc_id}' successfully read.")
        self.set_agent_llm(reader_id, ScriptedLLMClient([reader_step, reader_finish]))

        reader_run = self.execute_delegated_task(reader_id, msg1)
        if not reader_run.completed or reader_run.blocked_tool_calls > 0:
            return {"status": "BLOCKED", "step": "Reader Execution", "error": reader_run.error}

        # Step 3: Analyst delegates email dispatch to Mailer
        del_res2, msg2 = self.delegate_task(
            sender_id=analyst_id,
            receiver_id=mailer_id,
            task=f"Please send an email to {recipient} with the summary of {doc_id}",
            trace_id=trace_id,
        )
        if del_res2.decision != Decision.ALLOW:
            return {"status": "BLOCKED", "step": "Analyst -> Mailer Delegation", "error": del_res2.error}

        # Step 4: Mailer executes email dispatch
        mailer_step = LLMResponse(
            tool_calls=[
                ToolCallProposal(
                    tool_name="send_email",
                    arguments={"to": recipient, "body": f"Summary of {doc_id}: Complete"},
                )
            ]
        )
        mailer_finish = LLMResponse(content="Email sent successfully.")
        self.set_agent_llm(mailer_id, ScriptedLLMClient([mailer_step, mailer_finish]))

        mailer_run = self.execute_delegated_task(mailer_id, msg2)

        workflow_status = "SUCCESS" if mailer_run.completed and mailer_run.blocked_tool_calls == 0 else "BLOCKED"
        self._emit_event(
            "WORKFLOW_FINISHED",
            {"workflow": "Collaborative Analysis", "status": workflow_status, "trace_id": trace_id},
        )

        return {
            "status": workflow_status,
            "trace_id": trace_id,
            "reader_run": reader_run.model_dump(),
            "mailer_run": mailer_run.model_dump(),
        }

    def _resolve_tools_for_role(
        self,
        role: str,
        permissions: list[PermissionEntry],
    ) -> list[ToolAction]:
        actions: set[ToolAction] = set()
        for p in permissions:
            if p.action == "*":
                return [ToolAction.READ_FILE, ToolAction.SEND_EMAIL, ToolAction.RUN_QUERY, ToolAction.CALL_API]
            try:
                actions.add(ToolAction(p.action))
            except ValueError:
                pass
        return sorted(list(actions), key=lambda x: x.value)

    def _resolve_sensitivities_for_role(
        self,
        permissions: list[PermissionEntry],
    ) -> list[str]:
        sens: set[str] = set()
        for p in permissions:
            for r in p.resources:
                if r == "*":
                    sens.update(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"])
                elif "public" in r:
                    sens.add("PUBLIC")
                elif "internal" in r or "reports" in r or "analytics" in r:
                    sens.add("INTERNAL")
                elif "confidential" in r:
                    sens.add("CONFIDENTIAL")
                elif "restricted" in r:
                    sens.add("RESTRICTED")
        return sorted(list(sens))

    def _get_default_permissions_for_role(self, role: str) -> list[PermissionEntry]:
        if role == "admin":
            return [PermissionEntry(action="*", resources=["*"])]
        if role == "analyst":
            return [
                PermissionEntry(action="read_file", resources=["public/*", "internal/*"]),
                PermissionEntry(action="run_query", resources=["reports/*", "analytics/*"]),
            ]
        if role == "reader":
            return [PermissionEntry(action="read_file", resources=["public/*"])]
        if role == "mailer":
            return [
                PermissionEntry(action="send_email", resources=["*"]),
                PermissionEntry(action="read_file", resources=["public/*"]),
            ]
        return [PermissionEntry(action="read_file", resources=["public/*"])]
