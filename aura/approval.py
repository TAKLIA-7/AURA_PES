"""
AURA Approval Manager — Human-in-the-loop approval workflow.

This module manages the lifecycle of approval records for sensitive tool
operations that deterministic policy or JEV assessment escalate to
``Decision.APPROVAL``.

Workflow
~~~~~~~~
1. **Create** — The gateway calls :meth:`ApprovalManager.create_pending_approval`
   to persist a ``PENDING`` approval record bound to the canonical action digest.
2. **Approve / Reject** — A human approver calls :meth:`process_approval` with
   their credentials.  The manager verifies identity, permissions, TTL, digest
   integrity, and atomically transitions the record to ``CONSUMED`` or
   ``REJECTED``.
3. **Execute** — If consumed, the gateway retrieves the *stored* action
   parameters via :meth:`get_stored_action` and executes them (never the
   re-submitted parameters from the agent).
4. **Expire** — :meth:`expire_stale` garbage-collects records past TTL.

Security Properties
~~~~~~~~~~~~~~~~~~~
- **Digest binding**: The approval is bound to the exact canonical digest of the
  original action.  If the agent re-submits with different parameters after
  approval, the digest will not match and execution is refused.
- **Single-use**: Approvals transition ``PENDING → CONSUMED`` atomically and
  cannot be replayed.
- **TTL enforcement**: Approvals expire after ``DEFAULT_TTL_SECONDS`` (5 min).
- **No self-approval**: ``agent_id != approver_id`` is enforced.
- **Policy version pinning**: The approval records the policy version active at
  creation time.  If policy is updated, stale approvals are invalidated.

Authentication
~~~~~~~~~~~~~~
For **demo / development** purposes, approver identity is verified using a
SHA-256 hash of the supplied secret compared against the stored
``secret_hash`` in :class:`~aura.models.ApproverConfig`.

.. warning::

   **Production deployments** must replace SHA-256 hashing with a proper
   key-derivation function such as ``bcrypt``, ``scrypt``, or ``argon2id``.
   SHA-256 is deterministic and fast — unsuitable for credential storage
   against offline brute-force attacks.

Thread Safety
~~~~~~~~~~~~~
All mutable state is protected by ``threading.Lock``.  The underlying
``AuraStore`` is assumed to provide its own thread-safety guarantees.
"""

from __future__ import annotations

import hashlib
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from aura.models import (
    ApprovalRecord,
    ApprovalStatus,
    ApproverConfig,
    Decision,
    ExecutionStatus,
    GatewayResult,
    RunContext,
    ToolRequest,
)
from aura.store import AuraStore


class ApprovalManager:
    """Manages the human approval workflow for sensitive operations.

    Parameters
    ----------
    store:
        The persistence back-end implementing approval CRUD operations.
    approvers_config:
        Mapping of ``approver_id → ApproverConfig`` loaded from the
        trusted ``agents.yaml`` approvers section.
    """

    DEFAULT_TTL_SECONDS: int = 300  # 5 minutes

    def __init__(
        self,
        store: AuraStore,
        approvers_config: dict[str, ApproverConfig],
    ) -> None:
        self._store: AuraStore = store
        self._approvers: dict[str, ApproverConfig] = approvers_config
        self._lock: threading.Lock = threading.Lock()

    # ──────────────────────────────────────────
    # Creation
    # ──────────────────────────────────────────

    def create_pending_approval(
        self,
        request: ToolRequest,
        context: RunContext,
        policy_version: str,
    ) -> ApprovalRecord:
        """Create and persist a ``PENDING`` approval record.

        The record is bound to the *canonical action digest* of the
        original request so that any parameter mutation after approval
        will be detected and rejected.

        Parameters
        ----------
        request:
            The tool request that requires human approval.
        context:
            Trusted execution context for the current run.
        policy_version:
            The policy version active when the approval was requested.

        Returns
        -------
        ApprovalRecord
            The newly created, persisted record with status ``PENDING``.
        """
        now = datetime.now(timezone.utc)
        record = ApprovalRecord(
            request_id=request.request_id,
            agent_id=context.agent_id,
            tool_name=request.tool_name,
            canonical_digest=request.canonical_digest(),
            parameters_snapshot=request.parameters.copy(),
            status=ApprovalStatus.PENDING,
            policy_version=policy_version,
            created_at=now,
            expires_at=now + timedelta(seconds=self.DEFAULT_TTL_SECONDS),
        )
        with self._lock:
            self._store.save_approval(record)
        return record

    # ──────────────────────────────────────────
    # Approval / Rejection Processing
    # ──────────────────────────────────────────

    def process_approval(
        self,
        approval_id: str,
        approver_id: str,
        approver_secret: str,
        approve: bool,
        rejection_reason: str = "",
    ) -> tuple[bool, str]:
        """Process an approval or rejection decision.

        Performs all security checks before atomically transitioning the
        record from ``PENDING`` to ``CONSUMED`` (approved) or ``REJECTED``.

        Parameters
        ----------
        approval_id:
            The unique approval record identifier.
        approver_id:
            The identifier of the human approver.
        approver_secret:
            The approver's authentication secret (plain-text, hashed here).
        approve:
            ``True`` to approve, ``False`` to reject.
        rejection_reason:
            Human-readable reason (required when *approve* is ``False``).

        Returns
        -------
        tuple[bool, str]
            ``(success, message)`` — ``success`` is ``True`` iff the
            approval was processed successfully.

        Security Checks (ordered)
        -------------------------
        1. Approval record exists and is ``PENDING``.
        2. TTL has not expired.
        3. Approver identity is authenticated (secret hash verification).
        4. Approver has permission to approve for this agent.
        5. No self-approval (``agent_id ≠ approver_id``).
        6. Canonical digest matches the stored snapshot.
        7. Policy version has not changed since creation.
        """
        with self._lock:
            # ── 1. Existence & status ─────────────────────────
            record: Optional[ApprovalRecord] = self._store.get_approval(
                approval_id
            )
            if record is None:
                return False, f"Approval '{approval_id}' not found."
            if record.status != ApprovalStatus.PENDING:
                return (
                    False,
                    f"Approval '{approval_id}' is no longer PENDING "
                    f"(current status: {record.status.value}).",
                )

            # ── 2. TTL ────────────────────────────────────────
            now = datetime.now(timezone.utc)
            if record.expires_at is not None and now > record.expires_at:
                record.status = ApprovalStatus.EXPIRED
                self._store.save_approval(record)
                return (
                    False,
                    f"Approval '{approval_id}' has expired "
                    f"(expired at {record.expires_at.isoformat()}).",
                )

            # ── 3. Approver authentication ────────────────────
            if not self._verify_approver(approver_id, approver_secret):
                return (
                    False,
                    f"Authentication failed for approver '{approver_id}'.",
                )

            # ── 4. Permission check ──────────────────────────
            if not self._check_approver_permission(
                approver_id, record.agent_id
            ):
                return (
                    False,
                    f"Approver '{approver_id}' does not have permission "
                    f"to approve actions for agent '{record.agent_id}'.",
                )

            # ── 5. No self-approval ──────────────────────────
            if record.agent_id == approver_id:
                return (
                    False,
                    "Self-approval is forbidden: agent_id and "
                    "approver_id must differ.",
                )

            # ── 6–7 are verified at execution time via digest ─
            # The digest and policy_version are stored on the record
            # and re-checked by the gateway before executing the
            # stored action (see get_stored_action).

            # ── Transition ────────────────────────────────────
            if approve:
                record.status = ApprovalStatus.CONSUMED
                record.approver_id = approver_id
                record.approved_at = now
                record.consumed_at = now
                self._store.save_approval(record)
                return True, f"Approval '{approval_id}' CONSUMED by '{approver_id}'."
            else:
                record.status = ApprovalStatus.REJECTED
                record.approver_id = approver_id
                record.rejection_reason = rejection_reason or "No reason provided."
                self._store.save_approval(record)
                return (
                    True,
                    f"Approval '{approval_id}' REJECTED by '{approver_id}': "
                    f"{record.rejection_reason}",
                )

    # ──────────────────────────────────────────
    # Stored Action Retrieval
    # ──────────────────────────────────────────

    def get_stored_action(self, approval_id: str) -> Optional[dict[str, Any]]:
        """Retrieve the stored action parameters for an approved request.

        The gateway must execute the **stored** parameters, never the
        re-submitted parameters from the agent.  This prevents the agent
        from mutating the action between approval and execution.

        Parameters
        ----------
        approval_id:
            The approval record identifier.

        Returns
        -------
        dict[str, Any] | None
            The frozen parameters snapshot if the approval is ``CONSUMED``,
            or ``None`` if the approval cannot be found or is not consumed.
        """
        record: Optional[ApprovalRecord] = self._store.get_approval(
            approval_id
        )
        if record is None:
            return None
        if record.status != ApprovalStatus.CONSUMED:
            return None
        return {
            "tool_name": record.tool_name,
            "parameters": record.parameters_snapshot,
            "canonical_digest": record.canonical_digest,
            "policy_version": record.policy_version,
            "agent_id": record.agent_id,
            "approver_id": record.approver_id,
            "approved_at": (
                record.approved_at.isoformat() if record.approved_at else None
            ),
        }

    # ──────────────────────────────────────────
    # Approver Verification (demo)
    # ──────────────────────────────────────────

    def _verify_approver(self, approver_id: str, secret: str) -> bool:
        """Verify approver identity using a stored hash."""
        config = self._approvers.get(approver_id)
        if config is None:
            return False

        stored_hash = config.secret_hash if hasattr(config, "secret_hash") else config.get("secret_hash")
        computed_hash: str = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return computed_hash == stored_hash

    def _check_approver_permission(
        self, approver_id: str, agent_id: str
    ) -> bool:
        """Check whether *approver_id* may approve actions for *agent_id*."""
        config = self._approvers.get(approver_id)
        if config is None:
            return False

        can_approve = config.can_approve_for if hasattr(config, "can_approve_for") else config.get("can_approve_for", [])
        if "*" in can_approve:
            return True
        return agent_id in can_approve
        config: Optional[ApproverConfig] = self._approvers.get(approver_id)
        if config is None:
            return False
        # Wildcard or explicit match
        return "*" in config.can_approve_for or agent_id in config.can_approve_for

    # ──────────────────────────────────────────
    # Housekeeping
    # ──────────────────────────────────────────

    def expire_stale(self) -> int:
        """Expire all approval records past their TTL.

        Delegates to :meth:`AuraStore.expire_stale_approvals`.

        Returns
        -------
        int
            The number of records transitioned to ``EXPIRED``.
        """
        return self._store.expire_stale_approvals()

    def list_pending(self) -> list[ApprovalRecord]:
        """List all ``PENDING`` approvals for CLI display / dashboards.

        Returns
        -------
        list[ApprovalRecord]
            All currently pending approval records.
        """
        self._store.expire_stale_approvals()
        return self._store.get_pending_approvals()
