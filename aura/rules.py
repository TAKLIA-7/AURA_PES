"""
AURA Deterministic Policy Rules — evaluated before any JEV invocation.

Each rule is a pure function:
    (request: ToolRequest, context: RunContext, config: dict) → RuleResult

Rules are stateless, side-effect-free, and ordered by priority. A BLOCK from
any rule is final and cannot be overridden by the JEV or by downstream rules.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from aura.models import (
    Decision,
    ResourceSensitivity,
    RiskLevel,
    RuleResult,
    RunContext,
    ToolRequest,
)

# Type alias for rule functions
RuleFunc = Callable[[ToolRequest, RunContext, dict[str, Any]], RuleResult]


# ──────────────────────────────────────────────
# Helper utilities
# ──────────────────────────────────────────────

def _policy_version(config: dict[str, Any]) -> str:
    """Extract policy_version from config, defaulting to 'unknown'."""
    return str(config.get("policy_version", "unknown"))


def _make_result(
    rule_id: str,
    decision: Decision,
    reason_code: str,
    config: dict[str, Any],
    risk_level: RiskLevel = RiskLevel.LOW,
    **extra_metadata: Any,
) -> RuleResult:
    """Construct a ``RuleResult`` with consistent metadata."""
    metadata: dict[str, Any] = {"policy_version": _policy_version(config)}
    metadata.update(extra_metadata)
    return RuleResult(
        rule_id=rule_id,
        decision=decision,
        reason_code=reason_code,
        risk_level=risk_level,
        metadata=metadata,
        policy_version=_policy_version(config),
    )


# ──────────────────────────────────────────────
# RULE 1 — Agent Authentication
# ──────────────────────────────────────────────

def rule_agent_auth(
    request: ToolRequest,
    context: RunContext,
    config: dict[str, Any],
) -> RuleResult:
    """Verify that ``request.agent_id`` exists in the agent registry.

    If the agent is not found in the ``agents`` section of the loaded config
    the request is immediately blocked with ``UNAUTHORIZED_AGENT``.
    """
    agents: dict[str, Any] = config.get("agents", {})
    if request.agent_id not in agents:
        return _make_result(
            rule_id="RULE_AGENT_AUTH",
            decision=Decision.BLOCK,
            reason_code="UNAUTHORIZED_AGENT",
            config=config,
            risk_level=RiskLevel.CRITICAL,
            agent_id=request.agent_id,
        )
    return _make_result(
        rule_id="RULE_AGENT_AUTH",
        decision=Decision.ALLOW,
        reason_code="AGENT_AUTHORIZED",
        config=config,
        risk_level=RiskLevel.LOW,
        agent_id=request.agent_id,
    )


# ──────────────────────────────────────────────
# RULE 2 — Resource Access Control
# ──────────────────────────────────────────────

def _resource_id_for_request(request: ToolRequest) -> str | None:
    """Derive the resource identifier from the request parameters.

    For ``read_file`` the resource id comes from ``doc_id`` or ``file_id``.
    For ``run_query`` it comes from ``query_name`` or ``database``.
    Returns ``None`` when the tool does not target a named resource.
    """
    if request.tool_name == "read_file":
        return request.parameters.get("doc_id") or request.parameters.get("file_id")
    if request.tool_name == "run_query":
        q_name = request.parameters.get("query_name")
        if q_name:
            return f"query:{q_name}"
        db = request.parameters.get("database")
        if db is not None:
            # Accept both "db:analytics" and bare "analytics"
            return db if db.startswith("db:") else f"db:{db}"
    return None


def _role_matches(agent_role: str, allowed_roles: list[str]) -> bool:
    """Return True when *agent_role* is contained in *allowed_roles*."""
    return agent_role in allowed_roles


def rule_resource_access(
    request: ToolRequest,
    context: RunContext,
    config: dict[str, Any],
) -> RuleResult:
    """For ``read_file``/``run_query`` verify that the resource exists in the
    registry and that the agent's role is permitted to access it.

    * Unknown resource → ``BLOCK / UNKNOWN_RESOURCE``
    * Unauthorized role → ``BLOCK / RESOURCE_ACCESS_DENIED``
    """
    # Only applies to resource-accessing tools
    if request.tool_name not in ("read_file", "run_query"):
        return _make_result(
            rule_id="RULE_RESOURCE_ACCESS",
            decision=Decision.ALLOW,
            reason_code="NOT_RESOURCE_TOOL",
            config=config,
        )

    if request.tool_name == "run_query":
        query_name = request.parameters.get("query_name")
        queries: dict[str, Any] = config.get("sql_queries", {})
        if not query_name or query_name not in queries:
            return _make_result(
                rule_id="RULE_RESOURCE_ACCESS",
                decision=Decision.BLOCK,
                reason_code="UNKNOWN_RESOURCE",
                config=config,
                risk_level=RiskLevel.HIGH,
                query_name=query_name,
            )
        if context.agent_role not in ("sql", "admin"):
            return _make_result(
                rule_id="RULE_RESOURCE_ACCESS",
                decision=Decision.BLOCK,
                reason_code="RESOURCE_ACCESS_DENIED",
                config=config,
                risk_level=RiskLevel.HIGH,
                agent_role=context.agent_role,
            )
        return _make_result(
            rule_id="RULE_RESOURCE_ACCESS",
            decision=Decision.ALLOW,
            reason_code="RESOURCE_ACCESS_GRANTED",
            config=config,
        )

    resource_id = _resource_id_for_request(request)
    if resource_id is None:
        return _make_result(
            rule_id="RULE_RESOURCE_ACCESS",
            decision=Decision.BLOCK,
            reason_code="UNKNOWN_RESOURCE",
            config=config,
            risk_level=RiskLevel.HIGH,
            detail="No resource identifier found in request parameters",
        )

    resources: dict[str, Any] = config.get("resources", {})
    if resource_id not in resources:
        return _make_result(
            rule_id="RULE_RESOURCE_ACCESS",
            decision=Decision.BLOCK,
            reason_code="UNKNOWN_RESOURCE",
            config=config,
            risk_level=RiskLevel.HIGH,
            resource_id=resource_id,
        )

    resource = resources[resource_id]
    allowed_roles: list[str] = resource.get("allowed_roles", [])
    if not _role_matches(context.agent_role, allowed_roles):
        return _make_result(
            rule_id="RULE_RESOURCE_ACCESS",
            decision=Decision.BLOCK,
            reason_code="RESOURCE_ACCESS_DENIED",
            config=config,
            risk_level=RiskLevel.HIGH,
            resource_id=resource_id,
            agent_role=context.agent_role,
            allowed_roles=allowed_roles,
        )

    return _make_result(
        rule_id="RULE_RESOURCE_ACCESS",
        decision=Decision.ALLOW,
        reason_code="RESOURCE_ACCESS_GRANTED",
        config=config,
        resource_id=resource_id,
    )


# ──────────────────────────────────────────────
# RULE 3 — Confidential Data Egress Prevention
# ──────────────────────────────────────────────

def rule_confidential_egress(
    request: ToolRequest,
    context: RunContext,
    config: dict[str, Any],
) -> RuleResult:
    """Block egress of confidential data via ``send_email`` or ``call_api``.

    This rule fires **before** the JEV so that no amount of LLM reasoning
    can override it.  If the context is tainted *or* confidential data has
    been accessed in this session, outbound communication is blocked.
    """
    egress_tools = {"send_email", "call_api"}
    if request.tool_name not in egress_tools:
        return _make_result(
            rule_id="RULE_CONFIDENTIAL_EGRESS",
            decision=Decision.ALLOW,
            reason_code="NOT_EGRESS_TOOL",
            config=config,
        )

    if context.tainted or context.confidential_data_accessed:
        return _make_result(
            rule_id="RULE_CONFIDENTIAL_EGRESS",
            decision=Decision.BLOCK,
            reason_code="CONFIDENTIAL_EGRESS_BLOCKED",
            config=config,
            risk_level=RiskLevel.CRITICAL,
            tainted=context.tainted,
            confidential_data_accessed=context.confidential_data_accessed,
            taint_sources=context.taint_sources,
            tool_name=request.tool_name,
        )

    return _make_result(
        rule_id="RULE_CONFIDENTIAL_EGRESS",
        decision=Decision.ALLOW,
        reason_code="NO_CONFIDENTIAL_TAINT",
        config=config,
    )


# ──────────────────────────────────────────────
# RULE 4 — Sensitive Operations Approval
# ──────────────────────────────────────────────

def rule_sensitive_ops(
    request: ToolRequest,
    context: RunContext,
    config: dict[str, Any],
) -> RuleResult:
    """If the requested tool is in the ``sensitive_operations`` list the
    request is escalated to ``APPROVAL`` with risk level ``MEDIUM``.
    """
    sensitive: list[str] = config.get("sensitive_operations", [])
    if request.tool_name in sensitive:
        return _make_result(
            rule_id="RULE_SENSITIVE_OPS",
            decision=Decision.APPROVAL,
            reason_code="SENSITIVE_OP_REQUIRES_APPROVAL",
            config=config,
            risk_level=RiskLevel.MEDIUM,
            tool_name=request.tool_name,
        )

    return _make_result(
        rule_id="RULE_SENSITIVE_OPS",
        decision=Decision.ALLOW,
        reason_code="NOT_SENSITIVE_OP",
        config=config,
    )


# ──────────────────────────────────────────────
# RULE 5 — Destination Restriction
# ──────────────────────────────────────────────

def _extract_domain(email_address: str) -> str | None:
    """Extract the domain part of an email address (after ``@``)."""
    if "@" not in email_address:
        return None
    return email_address.rsplit("@", 1)[1].strip().lower()


def rule_destination_restrict(
    request: ToolRequest,
    context: RunContext,
    config: dict[str, Any],
) -> RuleResult:
    """For ``send_email``, verify the destination domain.

    * Domain in ``blocked_destinations`` → ``BLOCK / BLOCKED_DESTINATION``
    * Domain not in ``internal_domains`` → ``HIGH`` risk, ``DEFER`` to JEV
    """
    if request.tool_name != "send_email":
        return _make_result(
            rule_id="RULE_DESTINATION_RESTRICT",
            decision=Decision.ALLOW,
            reason_code="NOT_EMAIL_TOOL",
            config=config,
        )

    to_addr: str | None = request.parameters.get("to")
    if to_addr is None:
        return _make_result(
            rule_id="RULE_DESTINATION_RESTRICT",
            decision=Decision.BLOCK,
            reason_code="MISSING_DESTINATION",
            config=config,
            risk_level=RiskLevel.HIGH,
        )

    domain = _extract_domain(to_addr)
    if domain is None:
        return _make_result(
            rule_id="RULE_DESTINATION_RESTRICT",
            decision=Decision.BLOCK,
            reason_code="INVALID_DESTINATION",
            config=config,
            risk_level=RiskLevel.HIGH,
            destination=to_addr,
        )

    blocked: list[str] = config.get("blocked_destinations", [])
    if domain in [d.lower() for d in blocked]:
        return _make_result(
            rule_id="RULE_DESTINATION_RESTRICT",
            decision=Decision.BLOCK,
            reason_code="BLOCKED_DESTINATION",
            config=config,
            risk_level=RiskLevel.CRITICAL,
            domain=domain,
            destination=to_addr,
        )

    internal: list[str] = config.get("internal_domains", [])
    if domain not in [d.lower() for d in internal]:
        return _make_result(
            rule_id="RULE_DESTINATION_RESTRICT",
            decision=Decision.DEFER,
            reason_code="EXTERNAL_DESTINATION",
            config=config,
            risk_level=RiskLevel.HIGH,
            domain=domain,
            destination=to_addr,
        )

    return _make_result(
        rule_id="RULE_DESTINATION_RESTRICT",
        decision=Decision.ALLOW,
        reason_code="INTERNAL_DESTINATION",
        config=config,
        domain=domain,
    )


# ──────────────────────────────────────────────
# RULE 6 — Execution Constraints
# ──────────────────────────────────────────────

def rule_execution_constraints(
    request: ToolRequest,
    context: RunContext,
    config: dict[str, Any],
) -> RuleResult:
    """Enforce request-size constraints.

    * Individual parameter values must not exceed ``max_param_value_length``.
    * The total serialised request must not exceed ``max_request_size_bytes``.

    Violations → ``BLOCK / REQUEST_TOO_LARGE``.
    """
    max_param_len: int = config.get("max_param_value_length", 10_000)
    max_request_bytes: int = config.get("max_request_size_bytes", 1_048_576)

    # Check individual parameter value sizes
    for key, value in request.parameters.items():
        str_value = str(value) if not isinstance(value, str) else value
        if len(str_value) > max_param_len:
            return _make_result(
                rule_id="RULE_EXECUTION_CONSTRAINTS",
                decision=Decision.BLOCK,
                reason_code="REQUEST_TOO_LARGE",
                config=config,
                risk_level=RiskLevel.MEDIUM,
                violation="param_value_too_long",
                parameter=key,
                length=len(str_value),
                max_allowed=max_param_len,
            )

    # Check total serialised request size
    try:
        total_size = len(
            json.dumps(
                request.model_dump(mode="json"),
                default=str,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    except (TypeError, ValueError):
        # Fallback: use sys.getsizeof for an approximation
        total_size = sys.getsizeof(request.parameters)

    if total_size > max_request_bytes:
        return _make_result(
            rule_id="RULE_EXECUTION_CONSTRAINTS",
            decision=Decision.BLOCK,
            reason_code="REQUEST_TOO_LARGE",
            config=config,
            risk_level=RiskLevel.MEDIUM,
            violation="total_request_too_large",
            size_bytes=total_size,
            max_allowed=max_request_bytes,
        )

    return _make_result(
        rule_id="RULE_EXECUTION_CONSTRAINTS",
        decision=Decision.ALLOW,
        reason_code="WITHIN_CONSTRAINTS",
        config=config,
        total_size_bytes=total_size,
    )


# ──────────────────────────────────────────────
# Rule registry
# ──────────────────────────────────────────────

def get_all_rules() -> list[RuleFunc]:
    """Return deterministic rule functions in priority order.

    The order matches the ``priority`` field in ``policy.yaml``:
      1. RULE_AGENT_AUTH           (priority 10)
      2. RULE_RESOURCE_ACCESS      (priority 20)
      3. RULE_CONFIDENTIAL_EGRESS  (priority 30)
      4. RULE_SENSITIVE_OPS        (priority 40)
      5. RULE_DESTINATION_RESTRICT (priority 50)
      6. RULE_EXECUTION_CONSTRAINTS(priority 60)
    """
    return [
        rule_agent_auth,
        rule_resource_access,
        rule_confidential_egress,
        rule_sensitive_ops,
        rule_destination_restrict,
        rule_execution_constraints,
    ]
