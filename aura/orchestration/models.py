"""Multi-Agent Orchestration Domain Models.

Defines schemas for inter-agent messaging, delegation policies,
agent lifecycle states, and cryptographic message digests.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from aura.models import AgentIdentity, TaintState, ToolAction


class AgentStatus(str, Enum):
    """Lifecycle state of an orchestrated agent."""
    IDLE = "IDLE"
    BUSY = "BUSY"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class MessageType(str, Enum):
    """Type of message exchanged between orchestrated agents."""
    TASK_DELEGATION = "TASK_DELEGATION"
    TASK_RESULT = "TASK_RESULT"
    STATUS_UPDATE = "STATUS_UPDATE"
    ERROR = "ERROR"
    SYSTEM_NOTICE = "SYSTEM_NOTICE"


class InterAgentMessage(BaseModel):
    """Immutable envelope for inter-agent communication.

    Invariants:
      - Inter-agent messages are UNTRUSTED input to the receiver.
      - Message digest binds sender, receiver, task, timestamp, and content.
      - The audit log is NOT the operational message queue; the message broker
        delivers messages in-memory while durably logging the communication.
      - Taint state is explicitly propagated from sender to receiver.
    """
    message_id: str = Field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:12]}")
    sender_id: str
    receiver_id: str
    task_id: str
    trace_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_type: MessageType = MessageType.TASK_DELEGATION
    content: Any = Field(default="")
    taint_state: TaintState = Field(default_factory=TaintState)
    message_digest: str = Field(default="")

    def model_post_init(self, __context: Any) -> None:
        """Compute message digest if not already provided."""
        if not self.message_digest:
            self.message_digest = self.compute_digest()

    def compute_digest(self) -> str:
        """Compute SHA-256 digest over the message fields."""
        if isinstance(self.content, (dict, list)):
            content_str = json.dumps(self.content, sort_keys=True, separators=(",", ":"))
        else:
            content_str = str(self.content)

        ts_str = self.timestamp.isoformat()
        payload = f"{self.sender_id}:{self.receiver_id}:{self.task_id}:{self.trace_id}:{ts_str}:{content_str}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class DelegationRule(BaseModel):
    """Permission rule governing whether sender can delegate to receiver."""
    from_role: str
    to_role: str
    allowed_actions: list[str] = Field(default_factory=lambda: ["*"])
    description: str = ""


class DelegationPolicy(BaseModel):
    """Policy matrix controlling inter-agent delegation and preventing privilege escalation.

    Invariants:
      - Default DENY: delegation is forbidden unless an explicit rule permits it.
      - Receivers NEVER inherit the sender's role, permissions, or credentials.
    """
    rules: list[DelegationRule] = Field(default_factory=list)

    def is_delegation_allowed(
        self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
    ) -> tuple[bool, str]:
        """Check if sender is authorized to delegate tasks to receiver."""
        # Prevent self-delegation loops
        if sender.agent_id == receiver.agent_id:
            return False, "SELF_DELEGATION_PROHIBITED"

        # Check explicit rules
        for rule in self.rules:
            if (rule.from_role == "*" or rule.from_role == sender.role) and (
                rule.to_role == "*" or rule.to_role == receiver.role
            ):
                return True, "DELEGATION_AUTHORIZED"

        return False, f"DELEGATION_DENIED: Role '{sender.role}' cannot delegate to role '{receiver.role}'"

    @classmethod
    def create_default(cls) -> DelegationPolicy:
        """Default delegation policy aligned with AURA standard roles."""
        return cls(
            rules=[
                # Admin can delegate to anyone
                DelegationRule(
                    from_role="admin",
                    to_role="*",
                    description="Admin can delegate tasks to any agent",
                ),
                # Analyst can delegate to reader and mailer
                DelegationRule(
                    from_role="analyst",
                    to_role="reader",
                    description="Analyst can delegate document reading to reader",
                ),
                DelegationRule(
                    from_role="analyst",
                    to_role="mailer",
                    description="Analyst can delegate report sending to mailer",
                ),
                # Customer Case Coordinator can delegate to specialist agents
                DelegationRule(
                    from_role="coordinator",
                    to_role="image_inspector",
                    description="Coordinator can delegate photo inspection",
                ),
                DelegationRule(
                    from_role="coordinator",
                    to_role="invoice_processor",
                    description="Coordinator can delegate invoice parsing",
                ),
                DelegationRule(
                    from_role="coordinator",
                    to_role="audio_processor",
                    description="Coordinator can delegate voice transcription",
                ),
                DelegationRule(
                    from_role="coordinator",
                    to_role="order_verifier",
                    description="Coordinator can delegate order verification",
                ),
                DelegationRule(
                    from_role="coordinator",
                    to_role="resolution_specialist",
                    description="Coordinator can delegate case resolution",
                ),
                DelegationRule(
                    from_role="coordinator",
                    to_role="fulfillment_specialist",
                    description="Coordinator can delegate fulfillment execution",
                ),
                DelegationRule(
                    from_role="resolution_specialist",
                    to_role="fulfillment_specialist",
                    description="Resolution specialist can delegate actions to fulfillment",
                ),
                # Reader cannot delegate to anyone (read-only worker)
                # Mailer cannot delegate to anyone (egress-only worker)
            ]
        )


class ManagedAgentInfo(BaseModel):
    """Metadata describing an active managed agent within the orchestrator."""
    identity: AgentIdentity
    status: AgentStatus = AgentStatus.IDLE
    description: str = ""
    assigned_tools: list[ToolAction] = Field(default_factory=list)
    allowed_sensitivities: list[str] = Field(default_factory=list)
    tasks_processed: int = 0
    tasks_succeeded: int = 0
    tasks_failed: int = 0
    last_active: datetime | None = None

