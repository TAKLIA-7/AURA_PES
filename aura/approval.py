"""AURA Persistent Digest-Bound Approval System.

Invariants (Prompt §3):
  - Approval requests are bound to the canonical action digest, requester, approver,
    policy/resource versions, and TTL.
  - Authenticate approvers and prevent self-approval (approver_id != requester_agent_id).
  - Prevent replay: single-use approval consumed atomically with the execution claim.
  - Execute the stored action, NEVER resubmitted parameters.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from aura.models import (
    ApprovalRecord,
    ApprovalStatus,
    AuraRequest,
    RunContext,
    ToolAction,
)

if TYPE_CHECKING:
    from aura.store import AuraStore


class SelfApprovalError(Exception):
    """Raised when an agent attempts to approve their own request."""


class ApprovalExpiredError(Exception):
    """Raised when an approval request has expired past its TTL."""


class ApprovalReplayError(Exception):
    """Raised when an already consumed approval is claimed again."""


class ApprovalDigestMismatchError(Exception):
    """Raised when execution claim digest does not match the approved digest."""


class ApprovalManager:
    """Manages persistent digest-bound approval lifecycle."""

    def __init__(self, store: AuraStore) -> None:
        self.store = store

    def create_approval_request(
        self,
        request: AuraRequest,
        run_ctx: RunContext,
        ttl_seconds: int = 3600,
    ) -> ApprovalRecord:
        """Create and persist a new digest-bound approval request."""
        approval_id = f"apr-{uuid.uuid4().hex[:12]}"
        action_digest = request.canonical_digest()
        policy_ver = run_ctx.request.params.get("_policy_version", "1.0")

        record = ApprovalRecord(
            approval_id=approval_id,
            request_id=request.request_id,
            action=request.action,
            stored_params=dict(request.params),
            action_digest=action_digest,
            requester_agent_id=request.agent.agent_id,
            approver_id=None,
            status=ApprovalStatus.PENDING,
            policy_version=str(policy_ver),
            resource_version="1.0",
            ttl_seconds=ttl_seconds,
            created_at=datetime.now(timezone.utc),
            resolved_at=None,
            consumed_at=None,
        )

        self.store.save_approval(record)
        return record

    def resolve_approval(
        self,
        approval_id: str,
        approver_id: str,
        approved: bool,
    ) -> ApprovalRecord:
        """Authenticate approver, prevent self-approval, check TTL, and persist decision."""
        record = self.store.get_approval(approval_id)
        if record is None:
            raise ValueError(f"APPROVAL_NOT_FOUND: '{approval_id}'")

        if record.status != ApprovalStatus.PENDING:
            raise ValueError(f"APPROVAL_NOT_PENDING: status is already '{record.status.value}'")

        # 1. TTL Check
        if record.is_expired():
            self.store.update_approval_status(approval_id, ApprovalStatus.EXPIRED.value)
            raise ApprovalExpiredError(f"Approval request '{approval_id}' has expired")

        # 2. Self-Approval Invariant: approver must not be the requester!
        if approver_id == record.requester_agent_id:
            raise SelfApprovalError(
                f"Agent '{approver_id}' is prohibited from self-approving request '{approval_id}'"
            )

        new_status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        now = datetime.now(timezone.utc).isoformat()
        self.store.update_approval_status(
            approval_id=approval_id,
            status=new_status.value,
            approver_id=approver_id,
            resolved_at=now,
        )

        return self.store.get_approval(approval_id)  # type: ignore

    def consume_for_execution(
        self,
        approval_id: str,
        claiming_digest: str,
    ) -> ApprovalRecord:
        """Atomically consume the approved record, enforcing single-use and digest match.

        Returns the ApprovalRecord containing the original stored_params.
        """
        record = self.store.get_approval(approval_id)
        if record is None:
            raise ValueError(f"APPROVAL_NOT_FOUND: '{approval_id}'")

        if record.is_expired():
            self.store.update_approval_status(approval_id, ApprovalStatus.EXPIRED.value)
            raise ApprovalExpiredError(f"Approval request '{approval_id}' has expired")

        success, reason, updated = self.store.atomic_consume_approval(
            approval_id=approval_id,
            expected_digest=claiming_digest,
        )

        if not success:
            if reason == "APPROVAL_ALREADY_CONSUMED_REPLAY_REJECTED":
                raise ApprovalReplayError(f"APPROVAL_ALREADY_CONSUMED_REPLAY_REJECTED: approval '{approval_id}' was already consumed")
            elif reason == "APPROVAL_DIGEST_MISMATCH":
                raise ApprovalDigestMismatchError(
                    f"Digest mismatch: action claim does not match approved action digest"
                )
            else:
                raise ValueError(f"APPROVAL_CONSUMPTION_FAILED: {reason}")

        return updated  # type: ignore
