"""AURA Gateway — Central Enforcement Gateway.

Every protected tool call must pass through:
    `AURA.handle(request, run_ctx)`

Agents receive schemas, not adapter callables or credentials.
AURA makes authorization decisions, persists durable audit logs,
enforces caller-scoped idempotency, executes approval lifecycles,
and executes approved actions.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aura.approval import ApprovalManager
from aura.audit import AuditLogger
from aura.models import (
    ApprovalRecord,
    AuraRequest,
    AuraResult,
    Decision,
    JEVResult,
    PolicyDecision,
    ResourceSensitivity,
    RiskLevel,
    RunContext,
    ToolAction,
)
from aura.policy import PolicyEngine
from aura.rate_limit import RateLimiter
from aura.rbac import RBACManager
from aura.resources import ResourceRegistry
from aura.rules import (
    ApprovalRequiredRule,
    ConfidentialEgressRule,
    PermissionCheckRule,
    RateLimitRule,
    ResourceExistenceRule,
    TaintPropagationRule,
)
from aura.store import AuraStore, ExternalOutcomeUnknownError, IdempotencyConflictError
from aura.telemetry import OperationMetrics, TelemetryCollector
from aura.tools import ToolRegistry

if TYPE_CHECKING:
    from aura.jev.base import JEVProvider


class AuraGateway:
    """Central enforcement gateway implementation."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        tool_registry: ToolRegistry,
        jev_provider: JEVProvider | None = None,
        rate_limiter: RateLimiter | None = None,
        store: AuraStore | None = None,
        audit_logger: AuditLogger | None = None,
        approval_manager: ApprovalManager | None = None,
        telemetry: TelemetryCollector | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.tool_registry = tool_registry
        self.jev_provider = jev_provider
        self.rate_limiter = rate_limiter
        self.store = store or AuraStore()
        self.audit_logger = audit_logger or AuditLogger(self.store)
        self.approval_manager = approval_manager or ApprovalManager(self.store)
        self.telemetry = telemetry or TelemetryCollector()
        self._rbac_manager: RBACManager | None = None
        self._resource_registry: ResourceRegistry | None = None

    @property
    def rbac_manager(self) -> RBACManager | None:
        """Access the RBAC manager associated with the gateway."""
        if self._rbac_manager is not None:
            return self._rbac_manager
        for rule in self.policy_engine._rules:
            if hasattr(rule, "rbac_manager"):
                return rule.rbac_manager
        return None

    @classmethod
    def create_default(
        cls,
        config_dir: str = "config",
        jev_provider: JEVProvider | None = None,
        db_path: str | Path = ":memory:",
        use_gemini: bool = False,
    ) -> AuraGateway:
        """Create a fully configured gateway from YAML config files and SQLite store."""
        from pathlib import Path

        cfg_path = Path(config_dir)

        rbac_mgr = RBACManager.from_yaml(cfg_path / "agents.yaml")
        registry = ResourceRegistry.from_yaml(cfg_path / "resources.yaml")

        import yaml

        with open(cfg_path / "policy.yaml", "r", encoding="utf-8") as f:
            policy_yaml = yaml.safe_load(f)

        rate_limiter = RateLimiter.from_dict(policy_yaml.get("policy", {}))

        rules = [
            PermissionCheckRule(rbac_manager=rbac_mgr),
            ResourceExistenceRule(resource_registry=registry),
            TaintPropagationRule(),
            ConfidentialEgressRule(),
            RateLimitRule(rate_limiter=rate_limiter),
            ApprovalRequiredRule(),
        ]

        policy_engine = PolicyEngine(
            rules=rules,
            version=policy_yaml.get("version", "1.0"),
        )
        tools = ToolRegistry.create_default()

        if jev_provider is None:
            if use_gemini:
                from aura.jev.gemini import GeminiJEVProvider

                jev_provider = GeminiJEVProvider()
            else:
                from aura.jev.mock import MockJEVProvider

                jev_provider = MockJEVProvider()

        store = AuraStore(db_path=db_path)
        audit_logger = AuditLogger(store)
        approval_mgr = ApprovalManager(store)

        gw = cls(
            policy_engine=policy_engine,
            tool_registry=tools,
            jev_provider=jev_provider,
            rate_limiter=rate_limiter,
            store=store,
            audit_logger=audit_logger,
            approval_manager=approval_mgr,
        )
        gw._rbac_manager = rbac_mgr
        gw._resource_registry = registry
        return gw

    def handle(self, request: AuraRequest, run_ctx: RunContext) -> AuraResult:
        """Handle a single protected tool call."""
        start_time = time.monotonic()

        # ── 1. Idempotency Check ──────────────────────────────────────
        if request.idempotency_key:
            try:
                status, cached_result = self.store.check_or_claim_idempotency(
                    agent_id=request.agent.agent_id,
                    idempotency_key=request.idempotency_key,
                    canonical_digest=request.canonical_digest(),
                    request_id=request.request_id,
                )
                if status == "COMPLETED" and cached_result:
                    return AuraResult.model_validate(cached_result)
                elif status == "IN_PROGRESS":
                    result = AuraResult(
                        request_id=request.request_id,
                        decision=Decision.BLOCK,
                        risk_level=RiskLevel.MEDIUM,
                        execution_status="blocked",
                        error="CONCURRENT_IDEMPOTENT_REQUEST_IN_PROGRESS",
                    )
                    return self._finalize_and_audit(request, run_ctx, result, start_time)
                elif status == "UNKNOWN":
                    result = AuraResult(
                        request_id=request.request_id,
                        decision=Decision.BLOCK,
                        risk_level=RiskLevel.HIGH,
                        execution_status="unknown",
                        error="PREVIOUS_EXECUTION_STATE_UNKNOWN",
                    )
                    return self._finalize_and_audit(request, run_ctx, result, start_time)
            except IdempotencyConflictError as exc:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    execution_status="blocked",
                    error=f"IDEMPOTENCY_CONFLICT: {exc}",
                )
                return self._finalize_and_audit(request, run_ctx, result, start_time)

        # ── 2. Step bounds check ──────────────────────────────────────
        if run_ctx.step_count >= run_ctx.max_steps:
            result = AuraResult(
                request_id=request.request_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                execution_status="blocked",
                error="MAX_STEPS_EXCEEDED",
            )
            return self._finalize_and_audit(request, run_ctx, result, start_time)
        run_ctx.step_count += 1

        # ── 3. Global deadline check ──────────────────────────────────
        if run_ctx.deadline is not None:
            now = datetime.now(timezone.utc)
            if now > run_ctx.deadline:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    execution_status="blocked",
                    error="DEADLINE_EXCEEDED",
                )
                return self._finalize_and_audit(request, run_ctx, result, start_time)

        # ── 4. Deterministic policy evaluation ────────────────────────
        policy_decision = self.policy_engine.evaluate(request, run_ctx)

        # Deterministic BLOCK is final — tool adapter must NOT execute!
        if policy_decision.decision == Decision.BLOCK:
            result = AuraResult(
                request_id=request.request_id,
                decision=Decision.BLOCK,
                risk_level=policy_decision.risk_level,
                policy_decision=policy_decision,
                execution_status="blocked",
                error=policy_decision.reason_code,
            )
            return self._finalize_and_audit(request, run_ctx, result, start_time)

        # ── 5. Taint propagation side-effect ──────────────────────────
        if request.action == ToolAction.READ_FILE and run_ctx.resource_info is not None:
            sensitivity = run_ctx.resource_info.sensitivity
            if sensitivity in (ResourceSensitivity.CONFIDENTIAL, ResourceSensitivity.RESTRICTED):
                run_ctx.taint = run_ctx.taint.apply_taint(
                    source=run_ctx.resource_info.resource_id,
                    reason=f"Read {sensitivity.value} resource",
                    level=sensitivity,
                )

        # ── 6. Ambiguity & JEV evaluation ─────────────────────────────
        jev_result: JEVResult | None = None
        current_decision = policy_decision.decision
        current_risk = policy_decision.risk_level

        if current_decision == Decision.DEFER:
            if self.jev_provider is None:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    policy_decision=policy_decision,
                    execution_status="blocked",
                    error="JEV_REQUIRED_BUT_UNAVAILABLE",
                )
                return self._finalize_and_audit(request, run_ctx, result, start_time)

            jev_result = self.jev_provider.evaluate(request, run_ctx)

            # Fail closed on JEV error or block
            if jev_result.error or jev_result.decision == Decision.BLOCK:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel(max(current_risk, jev_result.risk_level)),
                    policy_decision=policy_decision,
                    jev_result=jev_result,
                    execution_status="blocked",
                    error=jev_result.error or "JEV_BLOCKED",
                )
                return self._finalize_and_audit(request, run_ctx, result, start_time)

            combined = self.policy_engine.combine_with_jev(
                policy_decision,
                jev_risk=jev_result.risk_level,
                jev_decision=jev_result.decision,
            )
            current_decision = combined.decision
            current_risk = combined.risk_level

        # ── 7. Approval handling ──────────────────────────────────────
        if current_decision == Decision.APPROVAL:
            # Persist an approval request
            approval_rec = self.approval_manager.create_approval_request(request, run_ctx)
            result = AuraResult(
                request_id=request.request_id,
                decision=Decision.APPROVAL,
                risk_level=current_risk,
                policy_decision=policy_decision,
                jev_result=jev_result,
                execution_status="pending_approval",
                error=f"APPROVAL_REQUIRED: approval_id={approval_rec.approval_id}",
            )
            return self._finalize_and_audit(request, run_ctx, result, start_time)

        # ── 8. Tool Execution (ONLY on ALLOW) ─────────────────────────
        if current_decision == Decision.ALLOW:
            adapter = self.tool_registry.get(request.action)
            if adapter is None:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    policy_decision=policy_decision,
                    jev_result=jev_result,
                    execution_status="error",
                    error=f"ADAPTER_NOT_FOUND: {request.action.value}",
                )
                return self._finalize_and_audit(request, run_ctx, result, start_time)

            try:
                output = adapter.execute(request.params)
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.ALLOW,
                    risk_level=current_risk,
                    policy_decision=policy_decision,
                    jev_result=jev_result,
                    execution_result=output,
                    execution_status="success",
                )
            except ExternalOutcomeUnknownError as exc:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.ALLOW,
                    risk_level=current_risk,
                    policy_decision=policy_decision,
                    jev_result=jev_result,
                    execution_status="unknown",
                    error=f"EXTERNAL_OUTCOME_UNKNOWN: {str(exc)}",
                )
            except Exception as exc:
                result = AuraResult(
                    request_id=request.request_id,
                    decision=Decision.ALLOW,
                    risk_level=current_risk,
                    policy_decision=policy_decision,
                    jev_result=jev_result,
                    execution_status="error",
                    error=f"ADAPTER_EXECUTION_ERROR: {str(exc)}",
                )
            return self._finalize_and_audit(request, run_ctx, result, start_time)

        # Catch-all fail closed
        result = AuraResult(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            risk_level=current_risk,
            policy_decision=policy_decision,
            jev_result=jev_result,
            execution_status="blocked",
            error="UNKNOWN_DECISION_FAIL_CLOSED",
        )
        return self._finalize_and_audit(request, run_ctx, result, start_time)

    # ── Approval Workflow Execution ───────────────────────────────────

    def execute_approved_action(
        self,
        approval_id: str,
        claiming_agent: AgentIdentity,
        run_ctx: RunContext,
    ) -> AuraResult:
        """Atomically consume an approved request and execute the STORED action."""
        start_time = time.monotonic()
        record = self.approval_manager.store.get_approval(approval_id)
        if record is None:
            return AuraResult(
                request_id=f"appr-{approval_id}",
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                execution_status="blocked",
                error="APPROVAL_NOT_FOUND",
            )

        # Atomically consume approval
        try:
            consumed_rec = self.approval_manager.consume_for_execution(
                approval_id=approval_id,
                claiming_digest=record.action_digest,
            )
        except Exception as exc:
            return AuraResult(
                request_id=record.request_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                execution_status="blocked",
                error=f"APPROVAL_CONSUMPTION_REJECTED: {exc}",
            )

        # Critical security invariant: Execute the STORED parameters, NOT user resubmissions!
        adapter = self.tool_registry.get(consumed_rec.action)
        if adapter is None:
            return AuraResult(
                request_id=record.request_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                execution_status="error",
                error=f"ADAPTER_NOT_FOUND: {consumed_rec.action.value}",
            )

        try:
            output = adapter.execute(consumed_rec.stored_params)
            res = AuraResult(
                request_id=record.request_id,
                decision=Decision.ALLOW,
                risk_level=RiskLevel.NONE,
                execution_result=output,
                execution_status="success",
            )
        except ExternalOutcomeUnknownError as exc:
            res = AuraResult(
                request_id=record.request_id,
                decision=Decision.ALLOW,
                risk_level=RiskLevel.HIGH,
                execution_status="unknown",
                error=f"EXTERNAL_OUTCOME_UNKNOWN: {exc}",
            )
        except Exception as exc:
            res = AuraResult(
                request_id=record.request_id,
                decision=Decision.ALLOW,
                risk_level=RiskLevel.HIGH,
                execution_status="error",
                error=f"ADAPTER_EXECUTION_ERROR: {exc}",
            )

        # Create AuraRequest representation for durable audit log
        exec_request = AuraRequest(
            request_id=record.request_id,
            trace_id=run_ctx.request.trace_id if (run_ctx and run_ctx.request) else None,
            action=consumed_rec.action,
            params=consumed_rec.stored_params,
            agent=claiming_agent,
        )
        return self._finalize_and_audit(exec_request, run_ctx, res, start_time)

    def _finalize_and_audit(
        self,
        request: AuraRequest,
        run_ctx: RunContext,
        result: AuraResult,
        start_time: float,
    ) -> AuraResult:
        """Durable audit recording and idempotency completion."""
        duration_ms = (time.monotonic() - start_time) * 1000

        try:
            self.audit_logger.log_operation(
                request=request,
                context=run_ctx,
                result=result,
                execution_duration_ms=duration_ms,
            )
        except Exception as exc:
            return AuraResult(
                request_id=request.request_id,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                execution_status="error",
                error=f"DURABLE_AUDIT_WRITE_FAILED: {exc}",
            )

        if request.idempotency_key:
            if result.decision == Decision.ALLOW and result.execution_status == "success":
                self.store.complete_idempotency(
                    agent_id=request.agent.agent_id,
                    idempotency_key=request.idempotency_key,
                    status="COMPLETED",
                    result=result.model_dump(mode="json"),
                )
            elif result.execution_status == "unknown":
                self.store.complete_idempotency(
                    agent_id=request.agent.agent_id,
                    idempotency_key=request.idempotency_key,
                    status="UNKNOWN",
                    result=None,
                )
            else:
                self.store.complete_idempotency(
                    agent_id=request.agent.agent_id,
                    idempotency_key=request.idempotency_key,
                    status="FAILED",
                    result=result.model_dump(mode="json"),
                )

        if hasattr(self, "telemetry") and self.telemetry:
            self.telemetry.record(
                OperationMetrics(
                    trace_id=request.trace_id or request.request_id,
                    action=request.action.value,
                    agent_id=request.agent.agent_id if request.agent else "unknown",
                    decision=result.decision.value,
                    fast_path=True,
                    total_duration_ms=duration_ms,
                )
            )

        return result
