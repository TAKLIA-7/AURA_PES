"""Workflow DAG models for AURA multi-agent execution."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from aura.models import ToolAction


class TaskState(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class WorkflowStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED_FOR_APPROVAL = "PAUSED_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class WorkflowTask(BaseModel):
    """A single executable task in a workflow DAG."""

    task_id: str
    workflow_id: str
    name: str
    assigned_agent_id: str
    assigned_agent_role: str
    tool_action: ToolAction
    tool_params: dict[str, Any] = Field(default_factory=dict)
    param_bindings: dict[str, str] = Field(default_factory=dict)
    # param_bindings: e.g. {"order_id": "extract_invoice.order_id"}
    depends_on: list[str] = Field(default_factory=list)
    state: TaskState = TaskState.CREATED
    result: Any | None = None
    error: str | None = None
    approval_id: str | None = None
    idempotency_key: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def is_ready(self, completed_task_ids: set[str]) -> bool:
        """Check if all prerequisite tasks have successfully completed."""
        return set(self.depends_on).issubset(completed_task_ids)


class WorkflowInstance(BaseModel):
    """An execution instance of a multi-agent workflow DAG."""

    workflow_id: str
    name: str
    description: str
    status: WorkflowStatus = WorkflowStatus.PENDING
    tasks: dict[str, WorkflowTask] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_task(self, task: WorkflowTask) -> None:
        self.tasks[task.task_id] = task

    def get_completed_tasks(self) -> dict[str, WorkflowTask]:
        return {
            tid: t
            for tid, t in self.tasks.items()
            if t.state == TaskState.COMPLETED
        }

    def get_pending_approvals(self) -> list[WorkflowTask]:
        return [
            t
            for t in self.tasks.values()
            if t.state == TaskState.WAITING_FOR_APPROVAL
        ]

