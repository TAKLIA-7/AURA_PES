"""
AURA Core Models — Pydantic v2 type system for the entire platform.

Every data structure flowing through AURA is defined here:
ToolRequest, RunContext, RuleResult, PolicyResult, JEVResult,
GatewayResult, AuditEvent, ApprovalRecord, and supporting enums.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ──────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────

class Decision(str, Enum):
    """Policy decision outcomes."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    APPROVAL = "APPROVAL"
    DEFER = "DEFER"


class RiskLevel(str, Enum):
    """Risk levels, ordered LOW < MEDIUM < HIGH < CRITICAL."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __ge__(self, other: RiskLevel) -> bool:
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return order[self.value] >= order[other.value]

    def __gt__(self, other: RiskLevel) -> bool:
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return order[self.value] > order[other.value]

    def __le__(self, other: RiskLevel) -> bool:
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return order[self.value] <= order[other.value]

    def __lt__(self, other: RiskLevel) -> bool:
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return order[self.value] < order[other.value]


class ExecutionStatus(str, Enum):
    """Execution lifecycle states."""
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    NOT_EXECUTED = "NOT_EXECUTED"


class ResourceSensitivity(str, Enum):
    """Resource sensitivity levels."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    TOP_SECRET = "TOP_SECRET"


class ApprovalStatus(str, Enum):
    """Approval workflow states."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


# ──────────────────────────────────────────────
# Request / Context Models
# ──────────────────────────────────────────────

class ToolRequest(BaseModel):
    """A tool call proposed by an AI agent — not yet authorized or executed."""
    tool_name: str = Field(..., min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = Field(..., min_length=1, max_length=100)
    idempotency_key: Optional[str] = Field(default=None, max_length=200)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        allowed = {"read_file", "send_email", "run_query", "call_api"}
        if v not in allowed:
            raise ValueError(f"Unknown tool: {v}. Allowed: {allowed}")
        return v

    def canonical_digest(self) -> str:
        """Compute a deterministic digest of the canonical action."""
        canonical = json.dumps(
            {"tool_name": self.tool_name, "parameters": self.parameters},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


class RunContext(BaseModel):
    """Trusted execution context — set by the gateway, never by the agent."""
    agent_id: str
    agent_role: str
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tainted: bool = False
    taint_sources: list[str] = Field(default_factory=list)
    confidential_data_accessed: bool = False
    step_number: int = 0
    max_steps: int = 8
    deadline: Optional[datetime] = None
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ──────────────────────────────────────────────
# Policy / Rule Models
# ──────────────────────────────────────────────

class RuleResult(BaseModel):
    """Outcome of a single deterministic policy rule."""
    rule_id: str
    decision: Decision
    reason_code: str
    risk_level: RiskLevel = RiskLevel.LOW
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = ""


class PolicyResult(BaseModel):
    """Aggregated result of all deterministic policy rules."""
    rule_results: list[RuleResult] = Field(default_factory=list)
    final_decision: Decision = Decision.DEFER
    final_risk_level: RiskLevel = RiskLevel.LOW
    policy_version: str = ""
    requires_jev: bool = False
    requires_approval: bool = False


# ──────────────────────────────────────────────
# JEV Models
# ──────────────────────────────────────────────

class JEVAssessment(BaseModel):
    """Structured output from a JEV provider — validated locally."""
    risk_level: RiskLevel
    findings: list[str] = Field(default_factory=list)
    recommendation: Decision = Decision.DEFER
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    reasoning: str = ""

    @model_validator(mode="after")
    def cross_field_validation(self) -> JEVAssessment:
        """Conservative escalation for contradictory findings."""
        # If findings mention confidential/external but risk is LOW → escalate
        danger_keywords = {"confidential", "secret", "external", "unauthorized", "injection"}
        has_dangerous_finding = any(
            any(kw in f.lower() for kw in danger_keywords)
            for f in self.findings
        )
        if has_dangerous_finding and self.risk_level == RiskLevel.LOW:
            self.risk_level = RiskLevel.HIGH
            self.findings.append("ESCALATED: Contradictory low risk with dangerous findings")
        return self


class JEVResult(BaseModel):
    """Complete JEV invocation result including metadata."""
    invoked: bool = False
    assessment: Optional[JEVAssessment] = None
    provider: str = ""
    model: str = ""
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    attempts: int = 0
    failure_reason: Optional[str] = None
    schema_valid: bool = True


# ──────────────────────────────────────────────
# Gateway Result
# ──────────────────────────────────────────────

class GatewayResult(BaseModel):
    """The complete result returned to the agent after AURA processes a request."""
    request_id: str
    trace_id: str
    decision: Decision
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED
    risk_level: RiskLevel = RiskLevel.LOW
    reason_code: str = ""
    reason: str = ""
    tool_name: str = ""
    result_data: Optional[Any] = None
    result_digest: Optional[str] = None
    policy_result: Optional[PolicyResult] = None
    jev_result: Optional[JEVResult] = None
    approval_required: bool = False
    approval_id: Optional[str] = None
    gateway_latency_ms: float = 0.0
    execution_latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_agent_message(self) -> str:
        """Format result as a clear message for the agent."""
        if self.decision == Decision.BLOCK:
            return (
                f"[AURA BLOCKED] Tool '{self.tool_name}' was BLOCKED. "
                f"Reason: {self.reason_code} — {self.reason}. "
                f"Status: {self.execution_status.value}. "
                f"The operation was NOT executed. Do NOT claim it succeeded."
            )
        if self.decision == Decision.APPROVAL:
            return (
                f"[AURA APPROVAL REQUIRED] Tool '{self.tool_name}' requires human approval. "
                f"Approval ID: {self.approval_id}. Status: PENDING. "
                f"The operation has NOT been executed yet."
            )
        if self.execution_status == ExecutionStatus.COMPLETED:
            return (
                f"[AURA ALLOWED] Tool '{self.tool_name}' executed successfully. "
                f"Result: {self.result_data}"
            )
        if self.execution_status == ExecutionStatus.FAILED:
            return (
                f"[AURA EXECUTION FAILED] Tool '{self.tool_name}' was authorized but "
                f"execution failed. Reason: {self.reason}. "
                f"Do NOT claim the operation succeeded."
            )
        if self.execution_status == ExecutionStatus.UNKNOWN:
            return (
                f"[AURA UNKNOWN] Tool '{self.tool_name}' execution outcome is ambiguous. "
                f"Do NOT retry automatically. Do NOT claim success or failure."
            )
        return f"[AURA] Tool '{self.tool_name}': {self.decision.value} / {self.execution_status.value}"


# ──────────────────────────────────────────────
# Approval Models
# ──────────────────────────────────────────────

class ApprovalRecord(BaseModel):
    """Persistent approval record."""
    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    agent_id: str
    tool_name: str
    canonical_digest: str
    parameters_snapshot: dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_id: Optional[str] = None
    policy_version: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    consumed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None


# ──────────────────────────────────────────────
# Audit Models
# ──────────────────────────────────────────────

class AuditEvent(BaseModel):
    """Comprehensive audit event with hash chain integrity."""
    # A. Request info
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = ""
    trace_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    idempotency_key: Optional[str] = None
    action_type: str = ""
    tool_name: str = ""
    request_digest: str = ""

    # B. Agent identity and RBAC
    agent_id: str = ""
    agent_role: str = ""
    requested_permission: str = ""
    authorization_result: str = ""
    resource_scope: str = ""

    # C. Request validation
    schema_valid: bool = True
    resource_lookup_result: str = ""
    validation_failure: Optional[str] = None
    safe_input_summary: str = ""
    canonical_digest: str = ""

    # D. Policy evaluation
    rule_ids_evaluated: list[str] = Field(default_factory=list)
    rule_outcomes: dict[str, str] = Field(default_factory=dict)
    policy_version: str = ""
    deterministic_decision: str = ""
    reason_codes: list[str] = Field(default_factory=list)

    # E. JEV information
    jev_invoked: bool = False
    jev_provider: str = ""
    jev_model: str = ""
    jev_risk_level: str = ""
    jev_findings: list[str] = Field(default_factory=list)
    jev_schema_valid: bool = True
    jev_input_tokens: int = 0
    jev_output_tokens: int = 0
    jev_latency_ms: float = 0.0
    jev_failure: Optional[str] = None

    # F. Final authorization
    final_decision: str = ""
    final_risk_level: str = ""
    approval_required: bool = False
    decision_reason: str = ""

    # G. Approval information
    approval_id: Optional[str] = None
    approval_requester: str = ""
    approval_approver: Optional[str] = None
    approval_status: str = ""
    approval_timestamp: Optional[datetime] = None
    approval_expiry: Optional[datetime] = None
    approval_digest_verified: bool = False
    approval_consumption_result: str = ""

    # H. Execution information
    adapter_name: str = ""
    execution_start: Optional[datetime] = None
    execution_end: Optional[datetime] = None
    execution_duration_ms: float = 0.0
    execution_status: str = ""
    error_code: Optional[str] = None
    result_digest: Optional[str] = None
    safe_result_summary: str = ""

    # I. Cost and efficiency
    cost_provider: str = ""
    cost_input_tokens: int = 0
    cost_output_tokens: int = 0
    cost_estimated_usd: float = 0.0
    jev_calls_count: int = 0
    gateway_latency_ms: float = 0.0
    tool_latency_ms: float = 0.0
    approval_wait_ms: float = 0.0

    # J. Audit integrity (hash chain)
    sequence_number: int = 0
    prev_hash: str = ""
    this_hash: str = ""
    hash_algorithm: str = "sha256"

    def compute_hash(self, prev_hash: str) -> str:
        """Compute hash over a canonical serialization of the event."""
        self.prev_hash = prev_hash
        canonical = self.model_dump(exclude={"this_hash"})
        # Serialize datetimes to ISO format for deterministic hashing
        canonical_str = json.dumps(canonical, sort_keys=True, default=str, separators=(",", ":"))
        self.this_hash = hashlib.sha256(canonical_str.encode()).hexdigest()
        return self.this_hash


# ──────────────────────────────────────────────
# Resource Models
# ──────────────────────────────────────────────

class ResourceEntry(BaseModel):
    """A registered resource with trusted sensitivity metadata."""
    id: str
    type: str
    name: str
    sensitivity: ResourceSensitivity
    owner: str
    allowed_roles: list[str] = Field(default_factory=list)
    content: Optional[str] = None


class AgentConfig(BaseModel):
    """Agent configuration from the trusted registry."""
    id: str
    role: str
    description: str = ""
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_operations: list[str] = Field(default_factory=list)
    rate_limits: dict[str, int] = Field(default_factory=dict)


class ApproverConfig(BaseModel):
    """Approver configuration from the trusted registry."""
    id: str
    role: str
    secret_hash: str
    can_approve_for: list[str] = Field(default_factory=list)


class SQLQueryDef(BaseModel):
    """Allowlisted named SQL query definition."""
    name: str
    description: str = ""
    sql: str
    allowed_params: dict[str, dict[str, Any]] = Field(default_factory=dict)
    allowed_tables: list[str] = Field(default_factory=list)
    operation: str = "read"

