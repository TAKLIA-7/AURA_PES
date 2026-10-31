"""AURA domain models — Pydantic v2.

Every type used across the AURA enforcement layer is defined here.
Security-critical invariants are encoded as Pydantic validators so that
invalid states are rejected at construction time.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ────────────────────────────────────────────────────────────────────
# Enums
# ────────────────────────────────────────────────────────────────────

class Decision(str, Enum):
    """Outcome of a policy evaluation or JEV assessment."""
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    APPROVAL = "APPROVAL"
    DEFER = "DEFER"


class RiskLevel(IntEnum):
    """Monotonically combinable risk levels.

    Risk can only increase: ``final = max(rule_risk, jev_risk)``.
    """
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ToolAction(str, Enum):
    """Protected tool actions exposed through AURA adapters."""
    READ_FILE = "read_file"
    SEND_EMAIL = "send_email"
    RUN_QUERY = "run_query"
    CALL_API = "call_api"


class ResourceSensitivity(str, Enum):
    """Sensitivity classification for registered resources."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# ────────────────────────────────────────────────────────────────────
# Identity & Context
# ────────────────────────────────────────────────────────────────────

class AgentIdentity(BaseModel):
    """Trusted agent identity — set by the gateway, never by the LLM.

    The ``agent_id`` is the stable identifier for the agent.
    The ``role`` determines RBAC permissions.
    """
    agent_id: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)

    @field_validator("agent_id", "role")
    @classmethod
    def _no_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank or whitespace-only")
        return v


class ResourceInfo(BaseModel):
    """Trusted resource metadata from the resource registry.

    ``exists`` defaults to ``True``; set to ``False`` when the registry
    confirms the resource is not known.
    """
    resource_id: str = Field(..., min_length=1)
    sensitivity: ResourceSensitivity
    resource_type: str = Field(..., min_length=1)
    exists: bool = True
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaintState(BaseModel):
    """Run-level taint tracking.

    After a confidential read, the run is *tainted* and deterministic
    egress rules block external sends.  Taint is monotonic within a run:
    once set, it cannot be cleared.
    """
    tainted: bool = False
    taint_source: str | None = None
    taint_reason: str | None = None
    taint_level: ResourceSensitivity | None = None

    def apply_taint(
        self,
        source: str,
        reason: str,
        level: ResourceSensitivity,
    ) -> TaintState:
        """Return a new TaintState with taint applied (monotonic)."""
        # If already tainted at a higher or equal level, keep it.
        if self.tainted and self.taint_level is not None:
            sensitivity_order = {
                ResourceSensitivity.PUBLIC: 0,
                ResourceSensitivity.INTERNAL: 1,
                ResourceSensitivity.CONFIDENTIAL: 2,
                ResourceSensitivity.RESTRICTED: 3,
            }
            if sensitivity_order.get(self.taint_level, 0) >= sensitivity_order.get(level, 0):
                return self
        return TaintState(
            tainted=True,
            taint_source=source,
            taint_reason=reason,
            taint_level=level,
        )


# ────────────────────────────────────────────────────────────────────
# Request & Context
# ────────────────────────────────────────────────────────────────────

class AuraRequest(BaseModel):
    """Incoming request to ``AURA.handle()``.

    ``params`` is a dict whose shape depends on the ``action``:
      - read_file:  {"doc_id": str}
      - send_email: {"to": str, "body": str}
      - run_query:  {"query_name": str, "params": dict}
      - call_api:   {"op": str}
    Validation of param shapes is deferred to the tool adapters (Phase 4).
    """
    request_id: str = Field(..., min_length=1)
    trace_id: str = Field(default="", min_length=0)
    action: ToolAction
    params: dict[str, Any] = Field(default_factory=dict)
    agent: AgentIdentity
    idempotency_key: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def _set_trace_id(self) -> AuraRequest:
        """Default trace_id to request_id if not supplied."""
        if not self.trace_id:
            self.trace_id = self.request_id
        return self

    def canonical_digest(self) -> str:
        """SHA-256 of the canonical (action, params, agent_id) triple.

        Used for approval binding and idempotency verification.
        """
        return compute_request_digest(
            self.action.value, self.params, self.agent.agent_id,
        )


class RunContext(BaseModel):
    """Mutable execution context for a single AURA request lifecycle."""
    request: AuraRequest
    taint: TaintState = Field(default_factory=TaintState)
    deadline: datetime | None = None
    step_count: int = 0
    max_steps: int = 8
    max_duration_seconds: float = 60.0
    resource_info: ResourceInfo | None = None


# ────────────────────────────────────────────────────────────────────
# Policy evaluation results
# ────────────────────────────────────────────────────────────────────

class RuleResult(BaseModel):
    """Outcome of a single deterministic rule evaluation."""
    rule_id: str = Field(..., min_length=1)
    decision: Decision
    risk_level: RiskLevel = RiskLevel.NONE
    reason_code: str = Field(..., min_length=1)
    reason_detail: str = ""


class PolicyDecision(BaseModel):
    """Aggregate outcome of the ordered policy evaluation.

    ``deciding_rule_id`` is the rule that produced the final decision
    (the BLOCK rule if blocked, or the last meaningful rule otherwise).
    """
    decision: Decision
    risk_level: RiskLevel
    rule_results: list[RuleResult] = Field(default_factory=list)
    policy_version: str = ""
    deciding_rule_id: str | None = None
    reason_code: str = ""


# ────────────────────────────────────────────────────────────────────
# JEV
# ────────────────────────────────────────────────────────────────────

class JEVResult(BaseModel):
    """Outcome of a JEV (LLM-backed) evaluation.

    JEV may raise risk but never lower it.  On any failure the gateway
    must fail closed with ``decision=BLOCK``.
    """
    provider: str = ""
    model: str = ""
    decision: Decision = Decision.DEFER
    risk_level: RiskLevel = RiskLevel.NONE
    findings: str = ""
    latency_ms: float = 0.0
    token_usage: int = 0
    attempt: int = 1
    error: str | None = None


# ────────────────────────────────────────────────────────────────────
# AURA Result (gateway output)
# ────────────────────────────────────────────────────────────────────

class AuraResult(BaseModel):
    """Final result returned by ``AURA.handle()``."""
    request_id: str
    decision: Decision
    risk_level: RiskLevel
    policy_decision: PolicyDecision | None = None
    jev_result: JEVResult | None = None
    execution_result: Any | None = None
    execution_status: str | None = None  # success | error | blocked | pending_approval | unknown
    error: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ────────────────────────────────────────────────────────────────────
# Audit
# ────────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    """Immutable audit log entry for the tamper-evident hash chain.

    ``compute_hash()`` produces a SHA-256 over the canonical JSON
    serialization chained with the previous hash.
    """
    sequence_number: int = Field(..., ge=0)
    request_id: str
    trace_id: str
    timestamp: datetime
    action: ToolAction
    agent_id: str
    agent_role: str
    decision: Decision
    risk_level: RiskLevel
    policy_version: str = ""
    rule_ids: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    # JEV fields
    jev_provider: str | None = None
    jev_model: str | None = None
    jev_decision: Decision | None = None
    jev_risk_level: RiskLevel | None = None
    jev_findings_summary: str | None = None
    jev_latency_ms: float | None = None
    jev_tokens: int | None = None
    jev_error: str | None = None
    # Execution fields
    execution_status: str | None = None
    execution_duration_ms: float | None = None
    safe_error_summary: str | None = None
    safe_result_summary: str | None = None
    # Hash chain
    previous_hash: str = ""
    current_hash: str = ""

    def compute_hash(self, previous_hash: str) -> str:
        """Compute SHA-256 for the tamper-evident chain.

        The hash covers the canonical JSON of all fields **except**
        ``previous_hash`` and ``current_hash``, prefixed by the
        previous entry's hash.
        """
        canonical = self.model_dump(
            mode="json",
            exclude={"current_hash", "previous_hash"},
        )
        payload = previous_hash + "|" + json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ────────────────────────────────────────────────────────────────────
# Approval (stub model — implemented in Phase 6)
# ────────────────────────────────────────────────────────────────────

class ApprovalStatus(str, Enum):
    """Lifecycle states for an approval request."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class ApprovalRecord(BaseModel):
    """Digest-bound persistent approval request.

    Invariants:
      - Bound to canonical action_digest of (action, params, agent_id).
      - Executes stored_params, NEVER re-submitted parameters.
      - Self-approval is forbidden (approver_id != requester_agent_id).
      - Single-use: consumed atomically with the execution claim.
    """
    approval_id: str = Field(..., min_length=1)
    request_id: str
    action: ToolAction = ToolAction.CALL_API
    stored_params: dict[str, Any] = Field(default_factory=dict)
    action_digest: str
    requester_agent_id: str
    approver_id: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    policy_version: str = ""
    resource_version: str = ""
    ttl_seconds: int = Field(default=3600, gt=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None
    consumed_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return (current - self.created_at).total_seconds() > self.ttl_seconds


# ────────────────────────────────────────────────────────────────────
# Utility functions
# ────────────────────────────────────────────────────────────────────

def compute_request_digest(
    action: str,
    params: dict[str, Any],
    agent_id: str,
) -> str:
    """Deterministic SHA-256 digest of (action, params, agent_id).

    Used for approval binding and idempotency key verification.
    """
    canonical = json.dumps(
        {"action": action, "agent_id": agent_id, "params": params},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

