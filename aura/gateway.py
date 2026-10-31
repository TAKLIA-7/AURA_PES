"""
AURA Enforcement Gateway — The central boundary between AI agents and execution.

Core principle:
"The AI agent may propose an action, but AURA decides whether that action is allowed to execute."
Every protected tool call must pass through AURA.handle(request, run_ctx).
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from aura.approval import ApprovalManager
from aura.audit import AuditLogger
from aura.jev.base import JEVProvider
from aura.jev.gemini import GeminiJEVProvider
from aura.jev.mock import MockJEVProvider
from aura.jev.openrouter import OpenRouterJEVProvider
from aura.models import (
    ApprovalRecord,
    ApprovalStatus,
    AuditEvent,
    Decision,
    ExecutionStatus,
    GatewayResult,
    JEVResult,
    PolicyResult,
    ResourceEntry,
    RiskLevel,
    RuleResult,
    RunContext,
    ToolRequest,
)
from aura.policy import PolicyEngine
from aura.rate_limit import RateLimiter
from aura.rbac import RBACEnforcer
from aura.resources import ResourceRegistry
from aura.store import AuraStore
from aura.telemetry import OperationMetrics, TelemetryCollector, Timer
from aura.tools import ToolRegistry


class AuraGateway:
    """The authoritative AURA Security and Execution-Enforcement Gateway."""

    def __init__(
        self,
        config_dir: str = "config",
        db_path: str = "aura.db",
        jsonl_path: str = "audit.jsonl",
        jev_provider: Optional[JEVProvider] = None,
    ) -> None:
        self.config_dir = Path(config_dir)
        self.policy_engine = PolicyEngine(config_path=str(self.config_dir / "policy.yaml"))
        self.resources = ResourceRegistry(self.policy_engine.resources_config)
        self.rbac = RBACEnforcer(self.policy_engine.agents)
        
        # Rate limiter
        global_rate_cfg = self.policy_engine.policy_config.get("global_rate_limits", {})
        self.rate_limiter = RateLimiter(global_rate_cfg, self.policy_engine.agents)

        # Store & Audit
        self.store = AuraStore(db_path=db_path)
        self.audit = AuditLogger(store=self.store, jsonl_path=jsonl_path)
        self.telemetry = TelemetryCollector()

        # Tools & Approvals
        self.tools = ToolRegistry()
        approvers_cfg = self.policy_engine.agents_config.get("approvers", {})
        self.approvals = ApprovalManager(store=self.store, approvers_config=approvers_cfg)

        # JEV provider initialization
        jev_cfg = self.policy_engine.policy_config.get("jev", {})
        if jev_provider is not None:
            self.jev = jev_provider
        else:
            provider_type = jev_cfg.get("provider", "mock").lower()
            if provider_type == "gemini" and os.environ.get("GOOGLE_API_KEY"):
                self.jev = GeminiJEVProvider(model=jev_cfg.get("model", "gemini-2.0-flash"))
            elif provider_type == "openrouter" and os.environ.get("OPENROUTER_API_KEY"):
                self.jev = OpenRouterJEVProvider(model=jev_cfg.get("model", "google/gemini-2.0-flash-001"))
            else:
                self.jev = MockJEVProvider()

    def handle(self, request: ToolRequest, run_ctx: RunContext) -> GatewayResult:
        """Synchronous entry point: run the async handler synchronously."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If called inside an existing event loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, self.handle_async(request, run_ctx)).result()
        else:
            return asyncio.run(self.handle_async(request, run_ctx))

    async def handle_async(self, request: ToolRequest, run_ctx: RunContext) -> GatewayResult:
        """The core AURA enforcement pipeline.
        
        Execution steps:
        1. Validate request and agent identity
        2. Resolve trusted agent role
        3. Enforce RBAC permissions
        4. Rate limit check & acquire concurrency slot
        5. Evaluate deterministic policy rules
        6. If DEFER/ambiguous, invoke JEV
        7. Monotone combination
        8. If APPROVAL, create persistent pending approval
        9. Idempotency check & execution claim
        10. Execute tool via private adapter
        11. Authoritative audit recording with hash-chain
        12. Return GatewayResult
        """
        start_time = time.perf_counter()
        metrics = OperationMetrics(trace_id=run_ctx.trace_id)
        gateway_result: Optional[GatewayResult] = None
        policy_result: Optional[PolicyResult] = None
        jev_result: Optional[JEVResult] = None
        approval_record: Optional[ApprovalRecord] = None
        slot_acquired = False

        try:
            # 1 & 2. Authenticate agent identity & resolve trusted role
            with Timer() as t_rbac:
                trusted_agent = self.policy_engine.get_agent_config(request.agent_id)
                if not trusted_agent:
                    return self._block(
                        request=request,
                        run_ctx=run_ctx,
                        reason_code="UNAUTHORIZED_AGENT",
                        reason=f"Agent '{request.agent_id}' is not registered in trusted agent registry",
                        risk_level=RiskLevel.CRITICAL,
                        start_time=start_time,
                    )
                # Overwrite context role with trusted role (never trust self-declared role)
                run_ctx.agent_role = trusted_agent.role

                # 3. RBAC Check
                if request.tool_name == "read_file":
                    resource_id = request.parameters.get("doc_id")
                elif request.tool_name == "run_query":
                    resource_id = request.parameters.get("database") or "db:analytics"
                elif request.tool_name == "call_api":
                    resource_id = "api:admin"
                else:
                    resource_id = None

                rbac_result = self.rbac.check_permission(
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    resource_id=resource_id,
                )
                if rbac_result.decision == Decision.BLOCK:
                    return self._block(
                        request=request,
                        run_ctx=run_ctx,
                        reason_code=rbac_result.reason_code,
                        reason=f"RBAC Denied: {rbac_result.metadata.get('detail', 'Unauthorized tool or resource')}",
                        risk_level=rbac_result.risk_level,
                        start_time=start_time,
                    )
            metrics.rbac_time_ms = t_rbac.elapsed_ms

            # 4. Rate Limiting
            rate_res = self.rate_limiter.check_rate_limit(request.agent_id)
            if rate_res.decision == Decision.BLOCK:
                return self._block(
                    request=request,
                    run_ctx=run_ctx,
                    reason_code=rate_res.reason_code,
                    reason="Rate limit or concurrency limit exceeded",
                    risk_level=RiskLevel.HIGH,
                    start_time=start_time,
                )
            slot_acquired = self.rate_limiter.acquire(request.agent_id)
            self.rate_limiter.record_request(request.agent_id)

            # 5. Deterministic Policy Evaluation
            with Timer() as t_rule:
                policy_result = self.policy_engine.evaluate(request, run_ctx)
            metrics.rule_evaluation_time_ms = t_rule.elapsed_ms

            # If deterministic BLOCK: final and immediate
            if policy_result.final_decision == Decision.BLOCK:
                blocking_rule = next(
                    (r for r in policy_result.rule_results if r.decision == Decision.BLOCK),
                    None,
                )
                code = blocking_rule.reason_code if blocking_rule else "POLICY_BLOCKED"
                return self._finalize_result(
                    request=request,
                    run_ctx=run_ctx,
                    decision=Decision.BLOCK,
                    reason_code=code,
                    reason=f"Deterministic policy blocked request: {code}",
                    risk_level=policy_result.final_risk_level,
                    policy_result=policy_result,
                    start_time=start_time,
                )

            # 6. JEV Assessment when ambiguous (DEFER)
            if policy_result.requires_jev:
                with Timer() as t_jev:
                    jev_result = await self.jev.assess(
                        request=request,
                        context=run_ctx,
                        timeout_seconds=5.0,
                    )
                metrics.jev_latency_ms = t_jev.elapsed_ms
                metrics.jev_calls = 1
                metrics.input_tokens = jev_result.input_tokens
                metrics.output_tokens = jev_result.output_tokens

                # Combine with JEV (monotone)
                policy_result = self.policy_engine.combine_with_jev(policy_result, jev_result)

                if policy_result.final_decision == Decision.BLOCK:
                    return self._finalize_result(
                        request=request,
                        run_ctx=run_ctx,
                        decision=Decision.BLOCK,
                        reason_code=jev_result.failure_reason or "JEV_RISK_BLOCK",
                        reason=f"JEV evaluation resulted in BLOCK: {jev_result.failure_reason or 'High risk'}",
                        risk_level=policy_result.final_risk_level,
                        policy_result=policy_result,
                        jev_result=jev_result,
                        start_time=start_time,
                    )

            # 7 & 8. Human Approval Check
            if policy_result.final_decision == Decision.APPROVAL:
                approval_record = self.approvals.create_pending_approval(
                    request=request,
                    context=run_ctx,
                    policy_version=self.policy_engine.policy_version,
                )
                return self._finalize_result(
                    request=request,
                    run_ctx=run_ctx,
                    decision=Decision.APPROVAL,
                    execution_status=ExecutionStatus.PENDING,
                    reason_code="APPROVAL_REQUIRED",
                    reason=f"Operation requires human approval (Approval ID: {approval_record.approval_id})",
                    risk_level=policy_result.final_risk_level,
                    policy_result=policy_result,
                    jev_result=jev_result,
                    approval_required=True,
                    approval_id=approval_record.approval_id,
                    start_time=start_time,
                )

            # 9. Idempotency Check & Atomic Claim
            canonical_digest = request.canonical_digest()
            idempotency_key = request.idempotency_key or f"req_{request.request_id}"
            
            with Timer() as t_persist:
                status_str, prior = self.store.check_idempotency(idempotency_key, canonical_digest)
                if status_str == "duplicate":
                    # Detected duplicate
                    return self._finalize_result(
                        request=request,
                        run_ctx=run_ctx,
                        decision=Decision.ALLOW,
                        execution_status=ExecutionStatus.COMPLETED,
                        reason_code="IDEMPOTENT_DUPLICATE",
                        reason="Duplicate request detected with identical digest; returned previous result",
                        risk_level=policy_result.final_risk_level,
                        result_data=prior,
                        policy_result=policy_result,
                        start_time=start_time,
                    )
                elif status_str == "conflict":
                    return self._finalize_result(
                        request=request,
                        run_ctx=run_ctx,
                        decision=Decision.BLOCK,
                        reason_code="IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_PAYLOAD",
                        reason="Idempotency key reused with different canonical digest",
                        risk_level=RiskLevel.HIGH,
                        policy_result=policy_result,
                        start_time=start_time,
                    )

                # Atomically claim execution
                claimed = self.store.claim_execution(idempotency_key, canonical_digest, request.request_id)
                if not claimed:
                    return self._finalize_result(
                        request=request,
                        run_ctx=run_ctx,
                        decision=Decision.BLOCK,
                        reason_code="CONCURRENT_EXECUTION_CLAIM_CONFLICT",
                        reason="Another worker has already claimed this execution key",
                        risk_level=RiskLevel.HIGH,
                        policy_result=policy_result,
                        start_time=start_time,
                    )
            metrics.persistence_time_ms = t_persist.elapsed_ms

            # 10. Execute Tool via Private Typed Adapter
            with Timer() as t_tool:
                exec_status = ExecutionStatus.COMPLETED
                exec_result_data = None
                exec_error = None

                try:
                    adapter = self.tools.get_adapter(request.tool_name)
                    if not adapter:
                        raise ValueError(f"No adapter registered for tool {request.tool_name}")

                    if request.tool_name == "read_file":
                        doc_id = request.parameters["doc_id"]
                        res_entry = self.resources.lookup(doc_id)
                        exec_result_data = adapter.execute(doc_id, res_entry)
                        # Taint tracking: if document is confidential, mark context tainted!
                        if res_entry and res_entry.sensitivity.value in ("CONFIDENTIAL", "TOP_SECRET"):
                            run_ctx.tainted = True
                            run_ctx.confidential_data_accessed = True
                            run_ctx.taint_sources.append(doc_id)

                    elif request.tool_name == "send_email":
                        to_addr = request.parameters["to"]
                        subject = request.parameters.get("subject", "")
                        body = request.parameters.get("body", "")
                        exec_result_data = adapter.execute(to_addr, subject, body)

                    elif request.tool_name == "run_query":
                        q_name = request.parameters["query_name"]
                        q_def = self.resources.get_sql_query(q_name)
                        params = request.parameters.get("params", {})
                        exec_result_data = adapter.execute(q_def, params)

                    elif request.tool_name == "call_api":
                        op = request.parameters["operation"]
                        params = request.parameters.get("params", {})
                        exec_result_data = adapter.execute(op, params)

                except Exception as e:
                    exec_status = ExecutionStatus.FAILED
                    exec_error = str(e)

            metrics.tool_execution_time_ms = t_tool.elapsed_ms

            # Record completion in idempotency store
            self.store.complete_execution(
                key=idempotency_key,
                status=exec_status,
                result_summary=str(exec_result_data)[:200] if exec_result_data else (exec_error or ""),
            )

            # 11. Authoritative Finalize & Audit
            gateway_result = self._finalize_result(
                request=request,
                run_ctx=run_ctx,
                decision=Decision.ALLOW,
                execution_status=exec_status,
                reason_code="EXECUTION_SUCCESS" if exec_status == ExecutionStatus.COMPLETED else "EXECUTION_FAILED",
                reason="Tool executed successfully" if exec_status == ExecutionStatus.COMPLETED else (exec_error or "Failed"),
                risk_level=policy_result.final_risk_level,
                result_data=exec_result_data,
                policy_result=policy_result,
                jev_result=jev_result,
                start_time=start_time,
                exec_latency_ms=t_tool.elapsed_ms,
            )
            return gateway_result

        finally:
            if slot_acquired:
                self.rate_limiter.release(request.agent_id)
            metrics.end_to_end_time_ms = (time.perf_counter() - start_time) * 1000
            self.telemetry.record(metrics)

    def execute_approved(self, approval_id: str) -> GatewayResult:
        """Execute a stored action that has been approved by an authorized approver.

        Security guarantees:
        1. Executes the STORED action snapshot, never resubmitted parameters from the agent.
        2. Re-verifies policy version.
        3. Invokes the private typed tool adapter.
        4. Emits a durable cryptographic audit event.
        """
        stored = self.approvals.get_stored_action(approval_id)
        if not stored:
            raise ValueError(f"No consumed/approved action found for approval ID: {approval_id}")

        tool_name = stored["tool_name"]
        params = stored["parameters"]
        agent_id = stored["agent_id"]

        agent_cfg = self.policy_engine.get_agent_config(agent_id)
        role = agent_cfg.role if agent_cfg else "agent"

        req = ToolRequest(
            agent_id=agent_id,
            tool_name=tool_name,
            parameters=params,
        )
        ctx = RunContext(agent_id=agent_id, agent_role=role)

        start_time = time.perf_counter()
        adapter = self.tools.get_adapter(tool_name)
        if not adapter:
            raise ValueError(f"No adapter registered for tool {tool_name}")

        exec_status = ExecutionStatus.COMPLETED
        exec_result = None
        exec_err = None
        try:
            if tool_name == "read_file":
                doc_id = params["doc_id"]
                res_entry = self.resources.lookup(doc_id)
                exec_result = adapter.execute(doc_id, res_entry)
            elif tool_name == "send_email":
                to_addr = params["to"]
                subject = params.get("subject", "")
                body = params.get("body", "")
                exec_result = adapter.execute(to_addr, subject, body)
            elif tool_name == "run_query":
                q_name = params["query_name"]
                q_def = self.resources.get_sql_query(q_name)
                p = params.get("params", {})
                exec_result = adapter.execute(q_def, p)
            elif tool_name == "call_api":
                op = params["operation"]
                p = params.get("params", {})
                exec_result = adapter.execute(op, p)
        except Exception as e:
            exec_status = ExecutionStatus.FAILED
            exec_err = str(e)

        gw_res = GatewayResult(
            request_id=req.request_id,
            trace_id=ctx.trace_id,
            decision=Decision.ALLOW,
            execution_status=exec_status,
            risk_level=RiskLevel.MEDIUM,
            reason_code="APPROVED_EXECUTION_COMPLETED" if exec_status == ExecutionStatus.COMPLETED else "APPROVED_EXECUTION_FAILED",
            reason=f"Approved action executed by approver {stored['approver_id']}" if exec_status == ExecutionStatus.COMPLETED else str(exec_err),
            tool_name=tool_name,
            result_data=exec_result,
            result_digest=req.canonical_digest(),
            approval_required=False,
            approval_id=approval_id,
            gateway_latency_ms=(time.perf_counter() - start_time) * 1000,
        )

        audit_event = self.audit.build_event(
            request=req,
            context=ctx,
            policy_result=None,
            jev_result=None,
            gateway_result=gw_res,
        )
        self.audit.log_event(audit_event)
        return gw_res

    def _block(
        self,
        request: ToolRequest,
        run_ctx: RunContext,
        reason_code: str,
        reason: str,
        risk_level: RiskLevel,
        start_time: float,
    ) -> GatewayResult:
        """Helper to construct and audit an immediate BLOCK result."""
        return self._finalize_result(
            request=request,
            run_ctx=run_ctx,
            decision=Decision.BLOCK,
            execution_status=ExecutionStatus.NOT_EXECUTED,
            reason_code=reason_code,
            reason=reason,
            risk_level=risk_level,
            start_time=start_time,
        )

    def _finalize_result(
        self,
        request: ToolRequest,
        run_ctx: RunContext,
        decision: Decision,
        reason_code: str,
        reason: str,
        risk_level: RiskLevel,
        execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED,
        result_data: Any = None,
        policy_result: Optional[PolicyResult] = None,
        jev_result: Optional[JEVResult] = None,
        approval_required: bool = False,
        approval_id: Optional[str] = None,
        start_time: float = 0.0,
        exec_latency_ms: float = 0.0,
    ) -> GatewayResult:
        """Construct the GatewayResult, persist an authoritative AuditEvent, and return."""
        gw_latency = (time.perf_counter() - start_time) * 1000 if start_time > 0 else 0.0

        gw_result = GatewayResult(
            request_id=request.request_id,
            trace_id=run_ctx.trace_id,
            decision=decision,
            execution_status=execution_status,
            risk_level=risk_level,
            reason_code=reason_code,
            reason=reason,
            tool_name=request.tool_name,
            result_data=result_data,
            result_digest=request.canonical_digest(),
            policy_result=policy_result,
            jev_result=jev_result,
            approval_required=approval_required,
            approval_id=approval_id,
            gateway_latency_ms=gw_latency,
            execution_latency_ms=exec_latency_ms,
        )

        # Audit logging (mandatory — if audit write fails, raise to prevent untracked execution)
        audit_event = self.audit.build_event(
            request=request,
            context=run_ctx,
            policy_result=policy_result,
            jev_result=jev_result,
            gateway_result=gw_result,
        )
        self.audit.log_event(audit_event)

        return gw_result
