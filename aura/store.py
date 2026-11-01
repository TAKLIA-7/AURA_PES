"""AURA SQLite Persistent Store.

Authoritative storage for:
  - Tamper-evident audit log with SHA-256 hash chaining
  - Caller-scoped idempotency records
  - Approval state records

Configuration:
  - WAL journal mode (PRAGMA journal_mode = WAL)
  - Synchronous FULL (PRAGMA synchronous = FULL)
  - Short, bounded transactions (never held across network or human waits)
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aura.models import (
    AuditEntry,
    Decision,
    RiskLevel,
    ToolAction,
)

GENESIS_HASH = "0" * 64


class IdempotencyConflictError(Exception):
    """Raised when an idempotency key is reused with a different request digest."""


class ConcurrentExecutionError(Exception):
    """Raised when a request with the same idempotency key is already running."""


class ExternalOutcomeUnknownError(Exception):
    """Raised when an external tool execution result is ambiguous/unknown and requires reconciliation."""


class AuraStore:
    """Authoritative SQLite store for AURA enforcement layer."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create connection with WAL and FULL synchrony."""
        if self._conn is None:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            conn.row_factory = sqlite3.Row
            with conn:
                # SQLite WAL and durability pragmas
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = FULL;")
                conn.execute("PRAGMA foreign_keys = ON;")
            self._conn = conn
        return self._conn

    def _init_db(self) -> None:
        """Create required tables and indexes."""
        conn = self._get_connection()
        with self._lock, conn:
            # 1. Audit log table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_role TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    risk_level INTEGER NOT NULL,
                    policy_version TEXT,
                    rule_ids TEXT,
                    reason_codes TEXT,
                    jev_provider TEXT,
                    jev_model TEXT,
                    jev_decision TEXT,
                    jev_risk_level INTEGER,
                    jev_findings_summary TEXT,
                    jev_latency_ms REAL,
                    jev_tokens INTEGER,
                    jev_error TEXT,
                    execution_status TEXT,
                    execution_duration_ms REAL,
                    safe_error_summary TEXT,
                    safe_result_summary TEXT,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_log(trace_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);"
            )

            # 2. Idempotency table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    agent_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    canonical_digest TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (agent_id, idempotency_key)
                );
                """
            )

            # 3. Approvals table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    stored_params TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    requester_agent_id TEXT NOT NULL,
                    approver_id TEXT,
                    status TEXT NOT NULL,
                    policy_version TEXT,
                    resource_version TEXT,
                    ttl_seconds INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    consumed_at TEXT
                );
                """
            )

    # ── Audit Operations ──────────────────────────────────────────────

    def get_latest_hash(self) -> tuple[int, str]:
        """Return (latest_sequence_number, latest_current_hash) or (-1, GENESIS_HASH)."""
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT sequence_number, current_hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1;"
            )
            row = cur.fetchone()
            if row:
                return row["sequence_number"], row["current_hash"]
            return -1, GENESIS_HASH

    def append_audit_entry(self, entry: AuditEntry) -> AuditEntry:
        """Durably write an audit entry into SQLite, linking the hash chain atomically.

        Refuses and raises if durable write fails.
        """
        conn = self._get_connection()
        with self._lock, conn:
            # Determine previous hash atomically inside the transaction
            cur = conn.cursor()
            cur.execute(
                "SELECT sequence_number, current_hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1;"
            )
            row = cur.fetchone()
            if row:
                seq = row["sequence_number"] + 1
                prev_hash = row["current_hash"]
            else:
                seq = 0
                prev_hash = GENESIS_HASH

            # Re-bind sequence number and compute tamper-evident hash
            entry.sequence_number = seq
            entry.previous_hash = prev_hash
            entry.current_hash = entry.compute_hash(prev_hash)

            cur.execute(
                """
                INSERT INTO audit_log (
                    sequence_number, request_id, trace_id, timestamp, action,
                    agent_id, agent_role, decision, risk_level, policy_version,
                    rule_ids, reason_codes, jev_provider, jev_model, jev_decision,
                    jev_risk_level, jev_findings_summary, jev_latency_ms, jev_tokens,
                    jev_error, execution_status, execution_duration_ms,
                    safe_error_summary, safe_result_summary, previous_hash, current_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    entry.sequence_number,
                    entry.request_id,
                    entry.trace_id,
                    entry.timestamp.isoformat(),
                    entry.action.value,
                    entry.agent_id,
                    entry.agent_role,
                    entry.decision.value,
                    int(entry.risk_level),
                    entry.policy_version,
                    json.dumps(entry.rule_ids),
                    json.dumps(entry.reason_codes),
                    entry.jev_provider,
                    entry.jev_model,
                    entry.jev_decision.value if entry.jev_decision else None,
                    int(entry.jev_risk_level) if entry.jev_risk_level is not None else None,
                    entry.jev_findings_summary,
                    entry.jev_latency_ms,
                    entry.jev_tokens,
                    entry.jev_error,
                    entry.execution_status,
                    entry.execution_duration_ms,
                    entry.safe_error_summary,
                    entry.safe_result_summary,
                    entry.previous_hash,
                    entry.current_hash,
                ),
            )
            return entry

    def verify_hash_chain(self) -> tuple[bool, str | None]:
        """Verify the entire audit hash chain for tampering.

        Detects:
          - Modified entries (recomputed hash != current_hash)
          - Broken hash linkages (previous_hash != prior row current_hash)
          - Sequence number gaps / reordering / deletion
        """
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute("SELECT * FROM audit_log ORDER BY sequence_number ASC;")
            rows = cur.fetchall()

            if not rows:
                return True, None

            expected_prev_hash = GENESIS_HASH
            for idx, row in enumerate(rows):
                seq = row["sequence_number"]
                if seq != idx:
                    return False, f"Sequence gap or reorder at index {idx}: expected seq {idx}, got {seq}"

                if row["previous_hash"] != expected_prev_hash:
                    return False, (
                        f"Hash linkage broken at sequence {seq}: "
                        f"expected previous_hash '{expected_prev_hash}', got '{row['previous_hash']}'"
                    )

                # Reconstruct entry to recompute canonical hash
                try:
                    entry = self._row_to_audit_entry(row)
                except Exception as exc:
                    return False, f"Corrupted or invalid data at sequence {seq}: {exc}"

                recomputed = entry.compute_hash(row["previous_hash"])
                if recomputed != row["current_hash"]:
                    return False, (
                        f"Tampered content at sequence {seq}: "
                        f"recorded hash '{row['current_hash']}' != recomputed '{recomputed}'"
                    )

                expected_prev_hash = row["current_hash"]

            return True, None

    def get_trace(self, trace_id: str) -> list[AuditEntry]:
        """Retrieve all audit entries associated with a trace_id."""
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM audit_log WHERE trace_id = ? ORDER BY sequence_number ASC;",
                (trace_id,),
            )
            return [self._row_to_audit_entry(r) for r in cur.fetchall()]

    def get_all_audit_entries(self, limit: int = 50) -> list[AuditEntry]:
        """Retrieve the most recent audit entries up to limit."""
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM audit_log ORDER BY sequence_number DESC LIMIT ?;",
                (limit,),
            )
            rows = cur.fetchall()
            return [self._row_to_audit_entry(r) for r in reversed(rows)]

    def export_jsonl(self, output_path: str | Path) -> int:
        """Export the audit log to an ordered JSONL file."""
        conn = self._get_connection()
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            cur = conn.cursor()
            cur.execute("SELECT * FROM audit_log ORDER BY sequence_number ASC;")
            count = 0
            with open(output_file, "w", encoding="utf-8") as f:
                for row in cur:
                    entry = self._row_to_audit_entry(row)
                    f.write(entry.model_dump_json() + "\n")
                    count += 1
            return count

    # ── Idempotency Operations ────────────────────────────────────────

    def check_or_claim_idempotency(
        self,
        agent_id: str,
        idempotency_key: str,
        canonical_digest: str,
        request_id: str,
    ) -> tuple[str, dict[str, Any] | None]:
        """Check or claim an idempotency key atomically.

        Returns (status, cached_result_dict).
        Status values: 'NEW', 'IN_PROGRESS', 'COMPLETED', 'UNKNOWN'.
        Raises IdempotencyConflictError if key was used with different digest.
        """
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()

        with self._lock, conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM idempotency_records WHERE agent_id = ? AND idempotency_key = ?;",
                (agent_id, idempotency_key),
            )
            row = cur.fetchone()

            if row is not None:
                if row["canonical_digest"] != canonical_digest:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' already used with different request digest"
                    )
                status = row["status"]
                cached_res = json.loads(row["result_json"]) if row["result_json"] else None
                return status, cached_res

            # Claim new key
            cur.execute(
                """
                INSERT INTO idempotency_records (
                    agent_id, idempotency_key, canonical_digest, request_id, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?, ?);
                """,
                (agent_id, idempotency_key, canonical_digest, request_id, now, now),
            )
            return "NEW", None

    def complete_idempotency(
        self,
        agent_id: str,
        idempotency_key: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Mark idempotency record completed or unknown."""
        now = datetime.now(timezone.utc).isoformat()
        res_json = json.dumps(result, default=str) if result is not None else None
        conn = self._get_connection()

        with self._lock, conn:
            conn.execute(
                """
                UPDATE idempotency_records
                SET status = ?, result_json = ?, updated_at = ?
                WHERE agent_id = ? AND idempotency_key = ?;
                """,
                (status, res_json, now, agent_id, idempotency_key),
            )

    def get_idempotency_record(
        self, agent_id: str, idempotency_key: str
    ) -> dict[str, Any] | None:
        """Retrieve an idempotency record by agent_id and key."""
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM idempotency_records WHERE agent_id = ? AND idempotency_key = ?;",
                (agent_id, idempotency_key),
            )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if res.get("result_json"):
                try:
                    res["result"] = json.loads(res["result_json"])
                except Exception:
                    res["result"] = None
            return res

    def list_idempotency_records(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent idempotency records."""
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM idempotency_records ORDER BY updated_at DESC LIMIT ?;",
                (limit,),
            )
            records = []
            for row in cur.fetchall():
                r = dict(row)
                if r.get("result_json"):
                    try:
                        r["result"] = json.loads(r["result_json"])
                    except Exception:
                        r["result"] = None
                records.append(r)
            return records

    def reconcile_idempotency(
        self,
        agent_id: str,
        idempotency_key: str,
        final_status: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Safely reconcile an unknown or in-progress idempotency record to final status."""
        self.complete_idempotency(agent_id, idempotency_key, final_status, result)

    # ── Approval Operations ───────────────────────────────────────────

    def save_approval(self, record: Any) -> None:
        """Save a new approval record into SQLite."""
        conn = self._get_connection()
        with self._lock, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO approvals (
                    approval_id, request_id, action, stored_params, action_digest,
                    requester_agent_id, approver_id, status, policy_version,
                    resource_version, ttl_seconds, created_at, resolved_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    record.approval_id,
                    record.request_id,
                    record.action.value if hasattr(record.action, "value") else str(record.action),
                    json.dumps(record.stored_params, default=str),
                    record.action_digest,
                    record.requester_agent_id,
                    record.approver_id,
                    record.status.value if hasattr(record.status, "value") else str(record.status),
                    record.policy_version,
                    record.resource_version,
                    record.ttl_seconds,
                    record.created_at.isoformat(),
                    record.resolved_at.isoformat() if record.resolved_at else None,
                    record.consumed_at.isoformat() if record.consumed_at else None,
                ),
            )

    def get_approval(self, approval_id: str) -> Any | None:
        """Retrieve an approval record by approval_id."""
        from aura.models import ApprovalRecord, ApprovalStatus
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
            row = cur.fetchone()
            if not row:
                return None
            return ApprovalRecord(
                approval_id=row["approval_id"],
                request_id=row["request_id"],
                action=ToolAction(row["action"]),
                stored_params=json.loads(row["stored_params"]) if row["stored_params"] else {},
                action_digest=row["action_digest"],
                requester_agent_id=row["requester_agent_id"],
                approver_id=row["approver_id"],
                status=ApprovalStatus(row["status"]),
                policy_version=row["policy_version"] or "",
                resource_version=row["resource_version"] or "",
                ttl_seconds=row["ttl_seconds"],
                created_at=datetime.fromisoformat(row["created_at"]),
                resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
                consumed_at=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None,
            )

    def list_pending_approvals(self) -> list[Any]:
        """List all pending approval records."""
        from aura.models import ApprovalRecord, ApprovalStatus
        conn = self._get_connection()
        with self._lock:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM approvals WHERE status = 'PENDING' ORDER BY created_at DESC;"
            )
            records = []
            for row in cur.fetchall():
                records.append(
                    ApprovalRecord(
                        approval_id=row["approval_id"],
                        request_id=row["request_id"],
                        action=ToolAction(row["action"]),
                        stored_params=json.loads(row["stored_params"]) if row["stored_params"] else {},
                        action_digest=row["action_digest"],
                        requester_agent_id=row["requester_agent_id"],
                        approver_id=row["approver_id"],
                        status=ApprovalStatus(row["status"]),
                        policy_version=row["policy_version"] or "",
                        resource_version=row["resource_version"] or "",
                        ttl_seconds=row["ttl_seconds"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
                        consumed_at=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None,
                    )
                )
            return records

    def update_approval_status(
        self,
        approval_id: str,
        status: str,
        approver_id: str | None = None,
        resolved_at: str | None = None,
    ) -> None:
        """Update status and approver for an approval record."""
        conn = self._get_connection()
        with self._lock, conn:
            conn.execute(
                """
                UPDATE approvals
                SET status = ?, approver_id = ?, resolved_at = ?
                WHERE approval_id = ?;
                """,
                (status, approver_id, resolved_at, approval_id),
            )

    def atomic_consume_approval(
        self,
        approval_id: str,
        expected_digest: str,
    ) -> tuple[bool, str, Any | None]:
        """Atomically consume an approval record with digest matching and replay prevention.

        Returns (success, reason, record_or_none).
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        with self._lock, conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
            row = cur.fetchone()
            if not row:
                return False, "APPROVAL_NOT_FOUND", None

            current_status = row["status"]
            if current_status == "CONSUMED":
                return False, "APPROVAL_ALREADY_CONSUMED_REPLAY_REJECTED", None
            if current_status != "APPROVED":
                return False, f"APPROVAL_NOT_APPROVED: status={current_status}", None
            if row["action_digest"] != expected_digest:
                return False, "APPROVAL_DIGEST_MISMATCH", None

            # Atomically update to CONSUMED
            cur.execute(
                """
                UPDATE approvals
                SET status = 'CONSUMED', consumed_at = ?
                WHERE approval_id = ? AND status = 'APPROVED';
                """,
                (now_iso, approval_id),
            )
            if cur.rowcount != 1:
                return False, "CONCURRENT_CONSUMPTION_CONFLICT", None

        # Return updated record
        updated_record = self.get_approval(approval_id)
        return True, "CONSUMED", updated_record

    # ── Helpers ───────────────────────────────────────────────────────

    def _row_to_audit_entry(self, row: sqlite3.Row) -> AuditEntry:
        """Convert a SQLite row to an AuditEntry model."""
        return AuditEntry(
            sequence_number=row["sequence_number"],
            request_id=row["request_id"],
            trace_id=row["trace_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            action=ToolAction(row["action"]),
            agent_id=row["agent_id"],
            agent_role=row["agent_role"],
            decision=Decision(row["decision"]),
            risk_level=RiskLevel(row["risk_level"]),
            policy_version=row["policy_version"] or "",
            rule_ids=json.loads(row["rule_ids"]) if row["rule_ids"] else [],
            reason_codes=json.loads(row["reason_codes"]) if row["reason_codes"] else [],
            jev_provider=row["jev_provider"],
            jev_model=row["jev_model"],
            jev_decision=Decision(row["jev_decision"]) if row["jev_decision"] else None,
            jev_risk_level=RiskLevel(row["jev_risk_level"]) if row["jev_risk_level"] is not None else None,
            jev_findings_summary=row["jev_findings_summary"],
            jev_latency_ms=row["jev_latency_ms"],
            jev_tokens=row["jev_tokens"],
            jev_error=row["jev_error"],
            execution_status=row["execution_status"],
            execution_duration_ms=row["execution_duration_ms"],
            safe_error_summary=row["safe_error_summary"],
            safe_result_summary=row["safe_result_summary"],
            previous_hash=row["previous_hash"],
            current_hash=row["current_hash"],
        )

    def close(self) -> None:
        """Close connection cleanly."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
