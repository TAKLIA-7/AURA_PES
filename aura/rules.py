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
    """Enforce per-agent rate limits.

    Stub for Phase 1 — always passes.  Actual rate-limit state tracking
    will be added in Phase 3 (persistence) and wired in Phase 2 (gateway).
    """

    def __init__(
        self,
        rule_id: str = "rate_limit",
        *,
        enabled: bool = True,
    ) -> None:
        super().__init__(rule_id, enabled=enabled)

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> RuleResult | None:
        # Stub: rate limiting requires persistence (Phase 3).
        return None


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

def _extract_resource_id(request: AuraRequest) -> str:
    """Extract the target resource identifier from request params.

    The mapping depends on the action type:
      - read_file  → params["doc_id"]
      - send_email → params.get("to", "")  (recipient is the "resource")
      - run_query  → params["query_name"]
      - call_api   → params["op"]
    """
    action = request.action
    params = request.params

    if action == ToolAction.READ_FILE:
        return str(params.get("doc_id", ""))
    elif action == ToolAction.SEND_EMAIL:
        return str(params.get("to", ""))
    elif action == ToolAction.RUN_QUERY:
        return str(params.get("query_name", ""))
    elif action == ToolAction.CALL_API:
        return str(params.get("op", ""))
    return ""
