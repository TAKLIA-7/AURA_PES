"""
AURA Persistence Layer — SQLite with WAL mode.

Provides atomic, thread-safe storage for:
- Audit events (tamper-evident hash chain)
- Idempotency keys (exactly-once execution)
- Approval records (human-in-the-loop workflow)
- Execution claims (atomic claim-or-reject)

All operations use explicit transactions and threading locks
to guarantee consistency under concurrent access.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from aura.models import (
    ApprovalRecord,
    ApprovalStatus,
    AuditEvent,
    ExecutionStatus,
)


class AuraStore:
    """Thread-safe SQLite persistence layer for AURA with WAL journaling.

    Every write acquires ``self._lock`` so callers may safely share one
    ``AuraStore`` across threads.  Reads are lock-free (WAL allows
    concurrent readers) but still go through ``_get_conn`` so every
    connection gets the correct pragmas.

    Args:
        db_path: Filesystem path for the SQLite database file.
    """

    # ── Schema DDL ──────────────────────────────────────────────

    _SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id            TEXT PRIMARY KEY,
        request_id          TEXT NOT NULL DEFAULT '',
        trace_id            TEXT NOT NULL DEFAULT '',
        timestamp           TEXT NOT NULL,
        sequence_number     INTEGER NOT NULL UNIQUE,
        prev_hash           TEXT NOT NULL DEFAULT '',
        this_hash           TEXT NOT NULL DEFAULT '',
        hash_algorithm      TEXT NOT NULL DEFAULT 'sha256',
        event_json          TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_events(trace_id);
    CREATE INDEX IF NOT EXISTS idx_audit_seq   ON audit_events(sequence_number);

    CREATE TABLE IF NOT EXISTS approvals (
        approval_id         TEXT PRIMARY KEY,
        request_id          TEXT NOT NULL,
        agent_id            TEXT NOT NULL,
        tool_name           TEXT NOT NULL,
        canonical_digest    TEXT NOT NULL,
        parameters_snapshot TEXT NOT NULL DEFAULT '{}',
        status              TEXT NOT NULL DEFAULT 'PENDING',
        approver_id         TEXT,
        policy_version      TEXT NOT NULL DEFAULT '',
        created_at          TEXT NOT NULL,
        expires_at          TEXT,
        approved_at         TEXT,
        consumed_at         TEXT,
        rejection_reason    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_approval_status ON approvals(status);

    CREATE TABLE IF NOT EXISTS idempotency (
        idem_key            TEXT PRIMARY KEY,
        digest              TEXT NOT NULL,
        request_id          TEXT NOT NULL DEFAULT '',
        status              TEXT NOT NULL DEFAULT 'PENDING',
        result_summary      TEXT NOT NULL DEFAULT '',
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS execution_claims (
        idem_key            TEXT PRIMARY KEY,
        request_id          TEXT NOT NULL,
        claimed_at          TEXT NOT NULL,
        FOREIGN KEY (idem_key) REFERENCES idempotency(idem_key)
    );
    """

    # ── Lifecycle ───────────────────────────────────────────────

    def __init__(self, db_path: str = "aura.db") -> None:
        self._db_path: str = db_path
        self._lock: threading.Lock = threading.Lock()
        self._mem_conn: Optional[sqlite3.Connection] = None

        if db_path == ":memory:":
            self._uri = True
            self._conn_str = f"file:memdb_{id(self)}?mode=memory&cache=shared"
            self._mem_conn = sqlite3.connect(self._conn_str, uri=True)
        else:
            self._uri = False
            self._conn_str = db_path

        self._init_db()

    def _init_db(self) -> None:
        """Create tables with WAL mode and synchronous=FULL."""
        conn = self._get_conn()
        try:
            conn.executescript(self._SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a new connection with WAL mode and synchronous=FULL.

        Every connection is configured independently because SQLite
        pragmas are per-connection, not per-database.
        """
        if self._uri:
            conn = sqlite3.connect(self._conn_str, uri=True)
        else:
            conn = sqlite3.connect(self._conn_str)
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.row_factory = sqlite3.Row
        return conn

    # ── Audit Events ────────────────────────────────────────────

    def insert_audit_event(self, event: AuditEvent) -> None:
        """Insert an audit event atomically.

        If persistence fails the exception propagates — the caller
        **must** refuse execution when audit recording is impossible.

        Args:
            event: A fully populated ``AuditEvent`` with ``this_hash``
                   already computed.

        Raises:
            sqlite3.IntegrityError: Duplicate event_id or sequence_number.
            sqlite3.Error: Any other database-level error.
        """
        event_json = event.model_dump_json()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (event_id, request_id, trace_id, timestamp,
                         sequence_number, prev_hash, this_hash,
                         hash_algorithm, event_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.request_id,
                        event.trace_id,
                        event.timestamp.isoformat(),
                        event.sequence_number,
                        event.prev_hash,
                        event.this_hash,
                        event.hash_algorithm,
                        event_json,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def get_last_hash(self) -> tuple[int, str]:
        """Return ``(sequence_number, this_hash)`` for the most recent event.

        If the table is empty the genesis sentinel ``(0, "GENESIS")`` is
        returned so the first real event gets ``sequence_number=1``.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT sequence_number, this_hash FROM audit_events "
                "ORDER BY sequence_number DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return (0, "GENESIS")
            return (row["sequence_number"], row["this_hash"])
        finally:
            conn.close()

    def get_audit_events(
        self,
        trace_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve audit events, optionally filtered by *trace_id*.

        Args:
            trace_id: If given, only events sharing this trace are returned.
            limit: Maximum number of rows (default 100).

        Returns:
            A list of dicts, each the full deserialised ``AuditEvent``.
        """
        conn = self._get_conn()
        try:
            if trace_id is not None:
                rows = conn.execute(
                    "SELECT event_json FROM audit_events "
                    "WHERE trace_id = ? "
                    "ORDER BY sequence_number ASC LIMIT ?",
                    (trace_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT event_json FROM audit_events "
                    "ORDER BY sequence_number ASC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [json.loads(row["event_json"]) for row in rows]
        finally:
            conn.close()

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Walk the entire hash chain and verify every link.

        Returns:
            ``(True, None)`` when the chain is intact, or
            ``(False, error_message)`` describing the first broken link.
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT event_json FROM audit_events ORDER BY sequence_number ASC"
            ).fetchall()
            if not rows:
                return (True, None)

            prev_hash = "GENESIS"
            for row in rows:
                event_data: dict[str, Any] = json.loads(row["event_json"])
                event = AuditEvent.model_validate(event_data)

                if event.prev_hash != prev_hash:
                    return (
                        False,
                        f"Chain broken at sequence {event.sequence_number}: "
                        f"expected prev_hash={prev_hash!r}, "
                        f"got {event.prev_hash!r}",
                    )

                # Recompute hash to verify it matches the stored one
                stored_hash = event.this_hash
                event.compute_hash(prev_hash)
                if event.this_hash != stored_hash:
                    return (
                        False,
                        f"Hash mismatch at sequence {event.sequence_number}: "
                        f"stored={stored_hash!r}, "
                        f"recomputed={event.this_hash!r}",
                    )

                prev_hash = stored_hash
            return (True, None)
        finally:
            conn.close()

    # ── Idempotency ─────────────────────────────────────────────

    def check_idempotency(
        self,
        key: str,
        digest: str,
    ) -> tuple[str, Optional[dict[str, Any]]]:
        """Check the idempotency state for *key*.

        Returns:
            * ``("new", None)`` — key has never been seen.
            * ``("duplicate", {previous_result})`` — same key **and** same
              digest; safe to return the cached result.
            * ``("conflict", None)`` — same key but **different** digest;
              the caller must reject the request.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT digest, status, result_summary FROM idempotency WHERE idem_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return ("new", None)
            if row["digest"] == digest:
                result: dict[str, Any] = {
                    "status": row["status"],
                    "result_summary": row["result_summary"],
                }
                return ("duplicate", result)
            return ("conflict", None)
        finally:
            conn.close()

    def claim_execution(
        self,
        key: str,
        digest: str,
        request_id: str,
    ) -> bool:
        """Atomically claim execution for an idempotency key.

        Inserts both an idempotency row and an execution_claims row
        within a single transaction.

        Args:
            key: The idempotency key.
            digest: Canonical digest of the action.
            request_id: Unique request identifier.

        Returns:
            ``True`` if the claim was successful, ``False`` if the key
            was already claimed (``IntegrityError``).
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO idempotency
                        (idem_key, digest, request_id, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'CLAIMED', ?, ?)
                    """,
                    (key, digest, request_id, now, now),
                )
                conn.execute(
                    """
                    INSERT INTO execution_claims (idem_key, request_id, claimed_at)
                    VALUES (?, ?, ?)
                    """,
                    (key, request_id, now),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def complete_execution(
        self,
        key: str,
        status: ExecutionStatus,
        result_summary: str = "",
    ) -> None:
        """Record the completion (or failure) of a previously claimed execution.

        Args:
            key: The idempotency key originally claimed.
            status: Final execution status (``COMPLETED``, ``FAILED``, etc.).
            result_summary: Optional human-readable summary of the result.

        Raises:
            ValueError: If the key does not exist.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """
                    UPDATE idempotency
                       SET status = ?, result_summary = ?, updated_at = ?
                     WHERE idem_key = ?
                    """,
                    (status.value, result_summary, now, key),
                )
                if cur.rowcount == 0:
                    raise ValueError(
                        f"Idempotency key not found: {key!r}"
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    # ── Approvals ───────────────────────────────────────────────

    def save_approval(self, record: ApprovalRecord) -> None:
        """Persist a pending approval record.

        Args:
            record: The ``ApprovalRecord`` to store.

        Raises:
            sqlite3.IntegrityError: If an approval with the same ID exists.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO approvals
                        (approval_id, request_id, agent_id, tool_name,
                         canonical_digest, parameters_snapshot, status,
                         approver_id, policy_version, created_at,
                         expires_at, approved_at, consumed_at,
                         rejection_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.approval_id,
                        record.request_id,
                        record.agent_id,
                        record.tool_name,
                        record.canonical_digest,
                        json.dumps(record.parameters_snapshot),
                        record.status.value,
                        record.approver_id,
                        record.policy_version,
                        record.created_at.isoformat(),
                        record.expires_at.isoformat() if record.expires_at else None,
                        record.approved_at.isoformat() if record.approved_at else None,
                        record.consumed_at.isoformat() if record.consumed_at else None,
                        record.rejection_reason,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _row_to_approval(self, row: sqlite3.Row) -> ApprovalRecord:
        """Deserialise a database row into an ``ApprovalRecord``."""
        return ApprovalRecord(
            approval_id=row["approval_id"],
            request_id=row["request_id"],
            agent_id=row["agent_id"],
            tool_name=row["tool_name"],
            canonical_digest=row["canonical_digest"],
            parameters_snapshot=json.loads(row["parameters_snapshot"]),
            status=ApprovalStatus(row["status"]),
            approver_id=row["approver_id"],
            policy_version=row["policy_version"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=(
                datetime.fromisoformat(row["expires_at"])
                if row["expires_at"]
                else None
            ),
            approved_at=(
                datetime.fromisoformat(row["approved_at"])
                if row["approved_at"]
                else None
            ),
            consumed_at=(
                datetime.fromisoformat(row["consumed_at"])
                if row["consumed_at"]
                else None
            ),
            rejection_reason=row["rejection_reason"],
        )

    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Retrieve an approval record by ID regardless of status.

        Returns:
            The ``ApprovalRecord`` if found, otherwise ``None``.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_approval(row)
        finally:
            conn.close()

    def get_pending_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Retrieve a single pending approval by its ID.

        Returns:
            The ``ApprovalRecord`` if found and still ``PENDING``,
            otherwise ``None``.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ? AND status = 'PENDING'",
                (approval_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_approval(row)
        finally:
            conn.close()

    def get_pending_approvals(self) -> list[ApprovalRecord]:
        """Return all approvals currently in ``PENDING`` status."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = 'PENDING' ORDER BY created_at ASC"
            ).fetchall()
            return [self._row_to_approval(row) for row in rows]
        finally:
            conn.close()

    def consume_approval(self, approval_id: str, approver_id: str) -> bool:
        """Atomically transition an approval from PENDING → CONSUMED.

        This is a one-shot consumption: if the row is not ``PENDING``
        (already consumed, rejected, or expired) the method returns
        ``False`` without modifying data.

        Args:
            approval_id: The approval to consume.
            approver_id: Identity of the human approver.

        Returns:
            ``True`` if the transition succeeded.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """
                    UPDATE approvals
                       SET status = 'CONSUMED',
                           approver_id = ?,
                           approved_at = ?,
                           consumed_at = ?
                     WHERE approval_id = ?
                       AND status = 'PENDING'
                    """,
                    (approver_id, now, now, approval_id),
                )
                conn.commit()
                return cur.rowcount > 0
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def reject_approval(
        self,
        approval_id: str,
        approver_id: str,
        reason: str,
    ) -> bool:
        """Reject a pending approval.

        Args:
            approval_id: The approval to reject.
            approver_id: Identity of the human rejecting.
            reason: Free-text reason for rejection.

        Returns:
            ``True`` if the transition succeeded (was still ``PENDING``).
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """
                    UPDATE approvals
                       SET status = 'REJECTED',
                           approver_id = ?,
                           rejection_reason = ?
                     WHERE approval_id = ?
                       AND status = 'PENDING'
                    """,
                    (approver_id, reason, approval_id),
                )
                conn.commit()
                return cur.rowcount > 0
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def expire_stale_approvals(self) -> int:
        """Expire all approvals whose ``expires_at`` is in the past.

        Returns:
            The number of approvals that were transitioned to ``EXPIRED``.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """
                    UPDATE approvals
                       SET status = 'EXPIRED'
                     WHERE status = 'PENDING'
                       AND expires_at IS NOT NULL
                       AND expires_at <= ?
                    """,
                    (now,),
                )
                conn.commit()
                return cur.rowcount
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
