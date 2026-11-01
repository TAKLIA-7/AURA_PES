"""AURA deterministic rules.

Each rule has exactly one responsibility and returns a ``RuleResult``
or ``None`` (not applicable).  Rules are stateless evaluators; side
effects (like taint application) are returned as signals for the
gateway to apply.

A ``BLOCK`` from any rule is final and cannot be overridden by JEV.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from aura.models import (
    Decision,
    ResourceSensitivity,
    RiskLevel,
    RuleResult,
    ToolAction,
)

if TYPE_CHECKING:
    from aura.models import AuraRequest, RunContext
    from aura.rbac import RBACManager
    from aura.resources import ResourceRegistry


class Rule(ABC):
    """Base class for all deterministic policy rules."""

    def __init__(self, rule_id: str, *, enabled: bool = True) -> None:
        self.rule_id = rule_id
        self.enabled = enabled

    @abstractmethod
    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        """Evaluate the rule against the request and context.

        Returns a ``RuleResult`` if the rule applies, or ``None`` if
        the rule is not applicable to this request.
        """
        ...


# ────────────────────────────────────────────────────────────────────
# Concrete rules
# ────────────────────────────────────────────────────────────────────


class PermissionCheckRule(Rule):
    """Verify that the agent has RBAC permission for the action + resource.

    Delegates to ``RBACManager.check_permission()``.
    Deny-by-default: no permission entry → BLOCK.
    """

    def __init__(
        self,
        rule_id: str = "rbac_check",
        *,
        rbac_manager: RBACManager | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)
        self._rbac: RBACManager | None = rbac_manager

    @property
    def rbac(self) -> RBACManager:
        if self._rbac is None:
            raise RuntimeError("RBACManager not set on PermissionCheckRule")
        return self._rbac

    @rbac.setter
    def rbac(self, manager: RBACManager) -> None:
        self._rbac = manager

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        # Determine the resource_id from params for the permission check.
        resource_id = _extract_resource_id(request)

        if self._rbac is None:
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                reason_code="RBAC_NOT_CONFIGURED",
                reason_detail="RBAC manager is not available",
            )

        allowed = self._rbac.check_permission(
            request.agent, request.action, resource_id,
        )

        if not allowed:
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                reason_code="PERMISSION_DENIED",
                reason_detail=(
                    f"Agent '{request.agent.agent_id}' (role={request.agent.role}) "
                    f"lacks permission for {request.action.value} "
                    f"on resource '{resource_id}'"
                ),
            )

        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.ALLOW,
            risk_level=RiskLevel.NONE,
            reason_code="PERMISSION_GRANTED",
            reason_detail=(
                f"Agent '{request.agent.agent_id}' has permission for "
                f"{request.action.value} on '{resource_id}'"
            ),
        )


class ResourceExistenceRule(Rule):
    """Verify that the target resource exists in the trusted registry.

    If the resource is not registered, BLOCK with an explanation.
    """

    def __init__(
        self,
        rule_id: str = "resource_exists",
        *,
        resource_registry: ResourceRegistry | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)
        self._registry: ResourceRegistry | None = resource_registry

    @property
    def registry(self) -> ResourceRegistry:
        if self._registry is None:
            raise RuntimeError("ResourceRegistry not set on ResourceExistenceRule")
        return self._registry

    @registry.setter
    def registry(self, reg: ResourceRegistry) -> None:
        self._registry = reg

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        # Communication endpoints and search queries are not cataloged storage resources
        if request.action in (
            ToolAction.SEND_EMAIL,
            ToolAction.SEND_CUSTOMER_UPDATE,
            ToolAction.SEND_MEETING_INVITE,
            ToolAction.SEARCH_MEETING_ROOMS,
        ):
            return None

        resource_id = _extract_resource_id(request)
        if not resource_id:
            # No resource to check (e.g., some call_api operations).
            return None

        if self._registry is None:
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                reason_code="REGISTRY_NOT_CONFIGURED",
                reason_detail="Resource registry is not available",
            )

        info = self._registry.lookup(resource_id)
        if info is None or not info.exists:
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.MEDIUM,
                reason_code="RESOURCE_NOT_FOUND",
                reason_detail=f"Resource '{resource_id}' is not registered",
            )

        # Stash resolved resource info on the context for later rules.
        context.resource_info = info

        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.ALLOW,
            risk_level=RiskLevel.NONE,
            reason_code="RESOURCE_FOUND",
            reason_detail=f"Resource '{resource_id}' exists (sensitivity={info.sensitivity.value})",
        )


class TaintPropagationRule(Rule):
    """Apply run-level taint after reading confidential or restricted resources.

    This rule does NOT block; it signals that the context should be
    tainted.  The gateway applies the taint after this rule returns.
    """

    def __init__(
        self,
        rule_id: str = "taint_propagation",
        *,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        # Only applies to read actions.
        if request.action != ToolAction.READ_FILE:
            return None

        resource_info = context.resource_info
        if resource_info is None:
            return None

        if resource_info.sensitivity in (
            ResourceSensitivity.CONFIDENTIAL,
            ResourceSensitivity.RESTRICTED,
        ):
            # Signal taint.  The gateway is responsible for actually
            # applying ``context.taint = context.taint.apply_taint(...)``.
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.ALLOW,
                risk_level=RiskLevel.MEDIUM,
                reason_code="TAINT_REQUIRED",
                reason_detail=(
                    f"Reading {resource_info.sensitivity.value} resource "
                    f"'{resource_info.resource_id}' — run will be tainted"
                ),
            )

        return None


class ConfidentialEgressRule(Rule):
    """Block external egress when the run is tainted.

    Sending email or calling external APIs after a confidential read
    is deterministically blocked.
    """

    EGRESS_ACTIONS: frozenset[ToolAction] = frozenset({
        ToolAction.SEND_EMAIL,
        ToolAction.CALL_API,
        ToolAction.SEND_CUSTOMER_UPDATE,
        ToolAction.SEND_MEETING_INVITE,
    })

    def __init__(
        self,
        rule_id: str = "confidential_egress",
        *,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        if request.action not in self.EGRESS_ACTIONS:
            return None

        if not context.taint.tainted:
            return None

        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            reason_code="CONFIDENTIAL_EGRESS_BLOCKED",
            reason_detail=(
                f"Egress action '{request.action.value}' blocked — "
                f"run is tainted from '{context.taint.taint_source}' "
                f"(level={context.taint.taint_level.value if context.taint.taint_level else 'unknown'})"
            ),
        )


class RateLimitRule(Rule):
    """Enforce per-agent and per-role rate limits.

    Delegates to ``RateLimiter.check_and_consume()``.
    If no RateLimiter is configured, returns None (pass-through).
    """

    def __init__(
        self,
        rule_id: str = "rate_limit",
        *,
        rate_limiter: Any | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)
        self._rate_limiter = rate_limiter

    @property
    def rate_limiter(self) -> Any | None:
        return self._rate_limiter

    @rate_limiter.setter
    def rate_limiter(self, limiter: Any) -> None:
        self._rate_limiter = limiter

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        if self._rate_limiter is None:
            return None

        allowed, reason = self._rate_limiter.check_and_consume(
            request.agent.agent_id, request.agent.role
        )
        if not allowed:
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.MEDIUM,
                reason_code="RATE_LIMIT_EXCEEDED",
                reason_detail=reason,
            )

        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.ALLOW,
            risk_level=RiskLevel.NONE,
            reason_code="RATE_LIMIT_OK",
            reason_detail="Within rate limits",
        )


class ApprovalRequiredRule(Rule):
    """Enforces mandatory human-in-the-loop approval for financial and order mutation actions."""

    def __init__(
        self,
        rule_id: str = "approval_required",
        *,
        approval_actions: set[ToolAction] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)
        self.approval_actions = approval_actions or {
            ToolAction.CREATE_REFUND,
            ToolAction.CREATE_REPLACEMENT,
            ToolAction.CREATE_RESERVATION,
        }

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        if request.action in self.approval_actions:
            return RuleResult(
                rule_id=self.rule_id,
                decision=Decision.APPROVAL,
                risk_level=RiskLevel.HIGH,
                reason_code="APPROVAL_REQUIRED",
                reason_detail=f"Operation '{request.action.value}' requires human-in-the-loop approval",
            )
        return None


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

def _extract_resource_id(request: AuraRequest) -> str:
    """Extract the target resource identifier from request params."""
    action = request.action
    params = request.params

    if action in (ToolAction.READ_FILE, ToolAction.READ_INVOICE_PDF, ToolAction.EXTRACT_INVOICE_DETAILS):
        return str(params.get("doc_id", ""))
    elif action in (ToolAction.READ_PRODUCT_IMAGE, ToolAction.ANALYZE_DAMAGE):
        return str(params.get("image_id", ""))
    elif action == ToolAction.TRANSCRIBE_CUSTOMER_AUDIO:
        return str(params.get("audio_id", ""))
    elif action in (
        ToolAction.LOOKUP_ORDER,
        ToolAction.CHECK_RETURN_ELIGIBILITY,
        ToolAction.CREATE_REFUND,
        ToolAction.CREATE_REPLACEMENT,
    ):
        return str(params.get("order_id", ""))
    elif action == ToolAction.SEND_EMAIL:
        return str(params.get("to", ""))
    elif action == ToolAction.SEND_CUSTOMER_UPDATE:
        return str(params.get("email", ""))
    elif action == ToolAction.RUN_QUERY:
        return str(params.get("query_name", ""))
    elif action == ToolAction.CALL_API:
        return str(params.get("op", ""))
    elif action == ToolAction.CREATE_RESERVATION:
        return str(params.get("room_id", ""))
    elif action == ToolAction.SEND_MEETING_INVITE:
        return str(params.get("to_emails", ""))
    elif action == ToolAction.SEARCH_MEETING_ROOMS:
        return str(params.get("location", ""))
    return ""

