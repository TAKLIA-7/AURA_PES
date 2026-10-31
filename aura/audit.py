"""AURA Audit Logger.

High-level audit logging service wrapping `AuraStore`.
Enforces tamper-evident hash chaining and safe payload sanitization.

Security Invariants:
  - Durable recording: If SQLite durable write fails, protected operations must refuse.
  - Safe summaries: Never log raw credentials, access tokens, or full confidential payloads.
  - Verification: Exposes full audit chain verification for detecting tampering.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aura.models import (
    AuditEntry,
    AuraRequest,
    AuraResult,
    Decision,
    RiskLevel,
    RunContext,
)

if TYPE_CHECKING:
    from aura.store import AuraStore


# Regex patterns to detect and mask sensitive credentials in audit summaries
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"),
    re.compile(r"(?i)(bearer)\s+([a-zA-Z0-9_\-\.]{8,})"),
]


def sanitize_summary(text: str | None, max_len: int = 250) -> str | None:
    """Sanitize strings for audit logging: mask secrets and truncate safely."""
    if text is None:
        return None
    cleaned = text
    for pattern in SECRET_PATTERNS:
        cleaned = pattern.sub(r"\1=***REDACTED***", cleaned)
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "...[TRUNCATED]"
    return cleaned


class AuditLogger:
    """Manages durable tamper-evident audit logging for AURA."""

    def __init__(self, store: AuraStore) -> None:
        self.store = store

    def log_operation(
        self,
        request: AuraRequest,
        context: RunContext,
        result: AuraResult,
        execution_duration_ms: float | None = None,
    ) -> AuditEntry:
        """Construct and durably append an AuditEntry.

        Raises RuntimeError if durable recording fails.
        """
        policy_dec = result.policy_decision
        jev_res = result.jev_result

        # Build safe summaries
        safe_error = sanitize_summary(result.error)
        safe_result = None
        if result.execution_result is not None:
            # Create safe summary instead of logging full payload
            if isinstance(result.execution_result, dict):
                keys = list(result.execution_result.keys())
                safe_result = f"Dict with keys: {keys}"
            else:
                safe_result = sanitize_summary(str(result.execution_result))

        rule_ids = [r.rule_id for r in policy_dec.rule_results] if policy_dec else []
        reason_codes = [r.reason_code for r in policy_dec.rule_results] if policy_dec else []
        policy_version = policy_dec.policy_version if policy_dec else ""

        entry = AuditEntry(
            sequence_number=0,  # store atomically assigns next sequence
            request_id=request.request_id,
            trace_id=request.trace_id,
            timestamp=datetime.now(timezone.utc),
            action=request.action,
            agent_id=request.agent.agent_id,
            agent_role=request.agent.role,
            decision=result.decision,
            risk_level=result.risk_level,
            policy_version=policy_version,
            rule_ids=rule_ids,
            reason_codes=reason_codes,
            jev_provider=jev_res.provider if jev_res else None,
            jev_model=jev_res.model if jev_res else None,
            jev_decision=jev_res.decision if jev_res else None,
            jev_risk_level=jev_res.risk_level if jev_res else None,
            jev_findings_summary=sanitize_summary(jev_res.findings) if jev_res else None,
            jev_latency_ms=jev_res.latency_ms if jev_res else None,
            jev_tokens=jev_res.token_usage if jev_res else None,
            jev_error=sanitize_summary(jev_res.error) if jev_res else None,
            execution_status=result.execution_status,
            execution_duration_ms=execution_duration_ms,
            safe_error_summary=safe_error,
            safe_result_summary=safe_result,
            previous_hash="",
            current_hash="",
        )

        try:
            return self.store.append_audit_entry(entry)
        except Exception as exc:
            # Security invariant: durable recording must not fail silently!
            raise RuntimeError(f"DURABLE_AUDIT_WRITE_FAILED: {exc}") from exc

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Verify the integrity of the audit log hash chain."""
        return self.store.verify_hash_chain()

    def get_trace(self, trace_id: str) -> list[AuditEntry]:
        """Fetch audit trail for a trace."""
        return self.store.get_trace(trace_id)

    def export_jsonl(self, path: str | Path) -> int:
        """Export audit trail to JSONL format."""
        return self.store.export_jsonl(path)
