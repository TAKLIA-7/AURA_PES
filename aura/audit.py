"""
AURA Audit Logger — Tamper-evident hash-chain audit trail.

Responsibilities:
- Assign monotonic sequence numbers to audit events
- Compute SHA-256 hash chain (each event links to its predecessor)
- Dual-write: SQLite (primary) + JSONL (secondary / export)
- Build ``AuditEvent`` from pipeline components
- Verify chain integrity on demand

The audit logger is a *critical-path* component.  If persistence
fails the caller **must** refuse execution — there is no silent
fallback.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

from aura.models import (
    ApprovalRecord,
    AuditEvent,
    GatewayResult,
    JEVResult,
    PolicyResult,
    RunContext,
    ToolRequest,
)
from aura.store import AuraStore


class AuditLogger:
    """Hash-chain audit logger with SQLite + JSONL dual-write.

    Thread-safe: all mutations go through ``self._lock``.

    Args:
        store: The ``AuraStore`` backing the persistent audit trail.
        jsonl_path: Path to the append-only JSONL sidecar file.
    """

    def __init__(
        self,
        store: AuraStore,
        jsonl_path: str = "audit.jsonl",
    ) -> None:
        self._store: AuraStore = store
        self._jsonl_path: str = jsonl_path
        self._lock: threading.Lock = threading.Lock()

    # ── Core Logging ────────────────────────────────────────────

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Assign a sequence number, compute the hash chain, and persist.

        The method performs the following steps atomically under a lock:

        1. Fetch the last ``(sequence_number, this_hash)`` from the store.
        2. Assign ``event.sequence_number = last_seq + 1``.
        3. Compute ``event.this_hash`` linking to the previous hash.
        4. Insert into SQLite.
        5. Append to JSONL.

        If *any* step fails the exception propagates — the caller
        **must** refuse execution.

        Args:
            event: A partially populated ``AuditEvent``.  The fields
                   ``sequence_number``, ``prev_hash``, and ``this_hash``
                   will be set by this method.

        Returns:
            The same ``AuditEvent`` instance, now fully populated.

        Raises:
            sqlite3.Error: On database write failure.
            OSError: On JSONL write failure.
        """
        with self._lock:
            last_seq, prev_hash = self._store.get_last_hash()
            event.sequence_number = last_seq + 1
            event.compute_hash(prev_hash)
            self._store.insert_audit_event(event)
            self._append_jsonl(event)
        return event

    # ── Event Building ──────────────────────────────────────────

    def build_event(
        self,
        request: ToolRequest,
        context: RunContext,
        policy_result: Optional[PolicyResult],
        jev_result: Optional[JEVResult],
        gateway_result: GatewayResult,
        approval_record: Optional[ApprovalRecord] = None,
    ) -> AuditEvent:
        """Build a comprehensive ``AuditEvent`` from all pipeline components.

        This is a *pure* builder — it does **not** persist or hash
        the event.  Call :meth:`log_event` afterwards.

        Args:
            request: The original tool call request.
            context: Trusted execution context.
            policy_result: Deterministic policy evaluation (may be ``None``).
            jev_result: JEV assessment result (may be ``None``).
            gateway_result: The final gateway decision.
            approval_record: Associated approval, if any.

        Returns:
            A fully populated but *un-hashed* ``AuditEvent``.
        """
        event = AuditEvent(
            # A. Request info
            request_id=request.request_id,
            trace_id=context.trace_id,
            timestamp=gateway_result.timestamp,
            idempotency_key=request.idempotency_key,
            action_type="tool_call",
            tool_name=request.tool_name,
            request_digest=request.canonical_digest(),
            # B. Agent identity and RBAC
            agent_id=context.agent_id,
            agent_role=context.agent_role,
            # C. Request validation
            canonical_digest=request.canonical_digest(),
            # F. Final authorization
            final_decision=gateway_result.decision.value,
            final_risk_level=gateway_result.risk_level.value,
            approval_required=gateway_result.approval_required,
            decision_reason=gateway_result.reason,
            # H. Execution information
            execution_status=gateway_result.execution_status.value,
            result_digest=gateway_result.result_digest,
            # I. Cost and efficiency
            gateway_latency_ms=gateway_result.gateway_latency_ms,
            tool_latency_ms=gateway_result.execution_latency_ms,
        )

        # D. Policy evaluation
        if policy_result is not None:
            event.rule_ids_evaluated = [r.rule_id for r in policy_result.rule_results]
            event.rule_outcomes = {
                r.rule_id: r.decision.value for r in policy_result.rule_results
            }
            event.policy_version = policy_result.policy_version
            event.deterministic_decision = policy_result.final_decision.value
            event.reason_codes = [r.reason_code for r in policy_result.rule_results]

        # E. JEV information
        if jev_result is not None and jev_result.invoked:
            event.jev_invoked = True
            event.jev_provider = jev_result.provider
            event.jev_model = jev_result.model
            event.jev_schema_valid = jev_result.schema_valid
            event.jev_input_tokens = jev_result.input_tokens
            event.jev_output_tokens = jev_result.output_tokens
            event.jev_latency_ms = jev_result.latency_ms
            event.jev_failure = jev_result.failure_reason
            event.jev_calls_count = jev_result.attempts
            if jev_result.assessment is not None:
                event.jev_risk_level = jev_result.assessment.risk_level.value
                event.jev_findings = list(jev_result.assessment.findings)
            # I. Cost info from JEV
            event.cost_provider = jev_result.provider
            event.cost_input_tokens = jev_result.input_tokens
            event.cost_output_tokens = jev_result.output_tokens
            event.cost_estimated_usd = jev_result.estimated_cost_usd

        # G. Approval information
        if approval_record is not None:
            event.approval_id = approval_record.approval_id
            event.approval_requester = approval_record.agent_id
            event.approval_approver = approval_record.approver_id
            event.approval_status = approval_record.status.value
            event.approval_timestamp = approval_record.approved_at
            event.approval_expiry = approval_record.expires_at
            event.approval_digest_verified = (
                approval_record.canonical_digest == request.canonical_digest()
            )

        return event

    # ── Query Helpers ───────────────────────────────────────────

    def get_operation_trace(self, trace_id: str) -> list[AuditEvent]:
        """Get all audit events for a trace, showing the full lifecycle.

        Args:
            trace_id: The trace identifier to filter on.

        Returns:
            Ordered list of ``AuditEvent`` objects for the trace.
        """
        raw_events = self._store.get_audit_events(trace_id=trace_id)
        return [AuditEvent.model_validate(e) for e in raw_events]

    # ── Integrity ───────────────────────────────────────────────

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        """Verify the entire audit hash chain.

        Delegates to :meth:`AuraStore.verify_chain`.

        Returns:
            ``(True, None)`` if intact, ``(False, detail)`` otherwise.
        """
        return self._store.verify_chain()

    # ── JSONL Export ────────────────────────────────────────────

    def export_jsonl(self, output_path: Optional[str] = None) -> int:
        """Export all stored audit events to a JSONL file.

        Args:
            output_path: Destination file path.  Defaults to
                         ``self._jsonl_path``.

        Returns:
            The number of events written.
        """
        target = output_path or self._jsonl_path
        events = self._store.get_audit_events(limit=1_000_000)
        with open(target, "w", encoding="utf-8") as fh:
            for ev_dict in events:
                fh.write(json.dumps(ev_dict, default=str, sort_keys=True) + "\n")
        return len(events)

    def _append_jsonl(self, event: AuditEvent) -> None:
        """Append a single event to the JSONL sidecar file.

        Uses ``model_dump`` for deterministic serialisation and
        opens in append mode so concurrent writers do not clobber
        each other (assuming OS-level atomic appends for short lines).

        Args:
            event: The fully hashed ``AuditEvent`` to append.
        """
        line = json.dumps(
            event.model_dump(),
            default=str,
            sort_keys=True,
        )
        with open(self._jsonl_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
