"""Workflow DAG Execution Engine for AURA."""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import logging
from typing import Any, Callable

from aura.gateway import AuraGateway
from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    RunContext,
    TaintState,
)
from aura.workflow.models import TaskState, WorkflowInstance, WorkflowStatus, WorkflowTask

logger = logging.getLogger("aura.workflow")


class WorkflowEngine:
    """Executes multi-agent DAG workflows with concurrent tasks and AURA enforcement."""

    def __init__(
        self,
        gateway: AuraGateway,
        on_task_event: Callable[[str, WorkflowTask, str], None] | None = None,
    ) -> None:
        self.gateway = gateway
        self.on_task_event = on_task_event
        self._workflows: dict[str, WorkflowInstance] = {}

    def register_workflow(self, workflow: WorkflowInstance) -> None:
        """Register a workflow instance."""
        self._workflows[workflow.workflow_id] = workflow

    def get_workflow(self, workflow_id: str) -> WorkflowInstance | None:
        """Get workflow by ID."""
        return self._workflows.get(workflow_id)

    def list_workflows(self) -> list[WorkflowInstance]:
        """List all active and completed workflows."""
        return list(self._workflows.values())

    def _notify(self, workflow_id: str, task: WorkflowTask, event: str) -> None:
        if self.on_task_event:
            try:
                self.on_task_event(workflow_id, task, event)
            except Exception as e:
                logger.warning(f"Error in on_task_event callback: {e}")

    def execute_workflow(self, workflow_id: str) -> WorkflowInstance:
        """Execute a workflow DAG until completion or until paused for human approval."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        wf.status = WorkflowStatus.RUNNING

        while True:
            completed_ids = set(wf.get_completed_tasks().keys())

            # Find all tasks that are CREATED or QUEUED and ready to run
            ready_tasks = [
                task
                for task in wf.tasks.values()
                if task.state in (TaskState.CREATED, TaskState.QUEUED)
                and task.is_ready(completed_ids)
            ]

            if not ready_tasks:
                # Check if paused for approval
                pending_approvals = wf.get_pending_approvals()
                if pending_approvals:
                    wf.status = WorkflowStatus.PAUSED_FOR_APPROVAL
                    return wf

                # Check if any tasks failed or blocked
                has_failures = any(
                    t.state in (TaskState.FAILED, TaskState.BLOCKED)
                    for t in wf.tasks.values()
                )
                if has_failures:
                    wf.status = WorkflowStatus.FAILED
                else:
                    wf.status = WorkflowStatus.COMPLETED
                    wf.completed_at = datetime.now(timezone.utc)
                return wf

            # Run independent tasks concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ready_tasks), 4)) as executor:
                futures = {
                    executor.submit(self._execute_single_task, wf, task): task
                    for task in ready_tasks
                }
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()

            # If any task entered WAITING_FOR_APPROVAL, pause workflow loop
            if wf.get_pending_approvals():
                wf.status = WorkflowStatus.PAUSED_FOR_APPROVAL
                return wf

            # If any task failed, mark failed
            if any(t.state in (TaskState.FAILED, TaskState.BLOCKED) for t in ready_tasks):
                wf.status = WorkflowStatus.FAILED
                return wf

        return wf

    def _execute_single_task(self, wf: WorkflowInstance, task: WorkflowTask) -> None:
        """Execute a single task through AURA.handle()."""
        task.state = TaskState.RUNNING
        task.started_at = datetime.now(timezone.utc)
        self._notify(wf.workflow_id, task, "STARTED")

        # 1. Resolve dynamic parameter bindings from parent tasks
        resolved_params = dict(task.tool_params)
        for param_name, binding_expr in task.param_bindings.items():
            if "." in binding_expr:
                parent_task_id, field_name = binding_expr.split(".", 1)
                parent_task = wf.tasks.get(parent_task_id)
                if parent_task and parent_task.result:
                    if isinstance(parent_task.result, dict):
                        resolved_params[param_name] = parent_task.result.get(field_name)
                    elif hasattr(parent_task.result, field_name):
                        resolved_params[param_name] = getattr(parent_task.result, field_name)

        # 2. Build AuraRequest
        agent_identity = AgentIdentity(
            agent_id=task.assigned_agent_id,
            role=task.assigned_agent_role,
        )
        request = AuraRequest(
            request_id=f"req-{task.task_id}",
            trace_id=wf.workflow_id,
            action=task.tool_action,
            params=resolved_params,
            agent=agent_identity,
            idempotency_key=task.idempotency_key or f"idem-{task.task_id}",
        )
        run_ctx = RunContext(
            request=request,
            max_steps=20,
            step_count=0,
            taint=TaintState(),
        )

        # 3. Submit to central AURA gateway
        res = self.gateway.handle(request, run_ctx)

        # 4. Process AURA result
        task.completed_at = datetime.now(timezone.utc)
        if res.decision == Decision.ALLOW and res.execution_status == "success":
            task.state = TaskState.COMPLETED
            task.result = res.execution_result
            self._notify(wf.workflow_id, task, "COMPLETED")
        elif res.decision == Decision.APPROVAL:
            task.state = TaskState.WAITING_FOR_APPROVAL
            # Extract approval_id from error message "APPROVAL_REQUIRED: approval_id=..."
            if res.error and "approval_id=" in res.error:
                task.approval_id = res.error.split("approval_id=")[-1].strip()
            task.error = res.error
            self._notify(wf.workflow_id, task, "APPROVAL_REQUIRED")
        elif res.decision == Decision.BLOCK:
            task.state = TaskState.BLOCKED
            task.error = res.error
            self._notify(wf.workflow_id, task, "BLOCKED")
        else:
            task.state = TaskState.FAILED
            task.error = res.error or "Unknown failure"
            self._notify(wf.workflow_id, task, "FAILED")

    def decline_approval(
        self,
        workflow_id: str,
        approval_id: str,
        decliner_id: str = "human-operator",
        reason: str = "Operation declined by operator",
    ) -> WorkflowInstance:
        """Decline a pending approval request and block dependent tasks without execution."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        # 1. Resolve approval as rejected
        self.gateway.approval_manager.resolve_approval(
            approval_id=approval_id,
            approved=False,
            approver_id=decliner_id,
        )

        # 2. Block the specific task and all downstream dependent tasks
        declined_task_id = None
        for task in wf.tasks.values():
            if task.approval_id == approval_id:
                declined_task_id = task.task_id
                task.state = TaskState.BLOCKED
                task.error = f"APPROVAL_DECLINED: {reason}"
                task.completed_at = datetime.now(timezone.utc)
                self._notify(wf.workflow_id, task, "APPROVAL_DECLINED")

        if declined_task_id:
            for task in wf.tasks.values():
                if declined_task_id in task.depends_on:
                    task.state = TaskState.BLOCKED
                    task.error = f"BLOCKED: Prerequisite task '{declined_task_id}' was declined"
                    self._notify(wf.workflow_id, task, "BLOCKED_DEPENDENCY")

        wf.status = WorkflowStatus.FAILED
        return wf

    def resume_after_approval(
        self,
        workflow_id: str,
        approver_id: str = "human-operator",
    ) -> WorkflowInstance:
        """Approve and execute pending approval tasks, then resume downstream tasks."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        pending_tasks = wf.get_pending_approvals()
        for task in pending_tasks:
            if not task.approval_id:
                continue

            # 1. Resolve approval in approval manager if still pending
            appr = self.gateway.approval_manager.store.get_approval(task.approval_id)
            if appr and appr.status.value == "PENDING":
                self.gateway.approval_manager.resolve_approval(
                    approval_id=task.approval_id,
                    approved=True,
                    approver_id=approver_id,
                )
            elif appr and appr.status.value == "REJECTED":
                task.state = TaskState.BLOCKED
                task.error = "APPROVAL_WAS_REJECTED"
                self._notify(wf.workflow_id, task, "APPROVAL_REJECTED")
                continue

            # 2. Execute approved action via gateway
            agent_identity = AgentIdentity(
                agent_id=task.assigned_agent_id,
                role=task.assigned_agent_role,
            )
            dummy_req = AuraRequest(
                request_id=f"appr-req-{task.task_id}",
                trace_id=wf.workflow_id,
                action=task.tool_action,
                params=task.tool_params,
                agent=agent_identity,
            )
            run_ctx = RunContext(
                request=dummy_req,
                max_steps=20,
            )

            res = self.gateway.execute_approved_action(
                approval_id=task.approval_id,
                claiming_agent=agent_identity,
                run_ctx=run_ctx,
            )

            if res.decision == Decision.ALLOW and res.execution_status == "success":
                task.state = TaskState.COMPLETED
                task.result = res.execution_result
                task.completed_at = datetime.now(timezone.utc)
                self._notify(wf.workflow_id, task, "APPROVED_AND_EXECUTED")
            else:
                task.state = TaskState.FAILED
                task.error = res.error
                task.completed_at = datetime.now(timezone.utc)
                self._notify(wf.workflow_id, task, "APPROVAL_EXECUTION_FAILED")

        # 3. Resume remaining DAG tasks
        return self.execute_workflow(workflow_id)
