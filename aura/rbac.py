"""
AURA RBAC Enforcer — Role-Based Access Control for agent tool/resource authorization.

Enforces that only trusted, registry-declared agents can invoke specific tools and
access specific resources. All lookups use the server-side trusted registry — never
agent-self-declared claims.

Key invariants
--------------
* Agent identity comes from the trusted config, not from the request.
* Wildcard resource patterns (e.g. ``"doc:*"``) are matched with :pyfunc:`fnmatch.fnmatch`.
* Self-approval is explicitly forbidden: an agent cannot approve its own actions.
"""

from __future__ import annotations

import fnmatch
from typing import Optional

from aura.models import AgentConfig, Decision, RiskLevel, RuleResult


class RBACEnforcer:
    """Deterministic RBAC check against a trusted agent registry.

    Parameters
    ----------
    agents_config:
        Mapping of ``agent_id → AgentConfig`` loaded from ``agents.yaml``.
        This is the *only* source of truth for identity and permissions.
    """

    # ── Reason codes ────────────────────────────
    _AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    _TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"
    _RESOURCE_NOT_PERMITTED = "RESOURCE_NOT_PERMITTED"
    _RBAC_AUTHORIZED = "RBAC_AUTHORIZED"
    _SELF_APPROVAL_DENIED = "SELF_APPROVAL_DENIED"

    _RULE_ID = "rbac_check"

    def __init__(self, agents_config: dict[str, AgentConfig]) -> None:
        if not isinstance(agents_config, dict):
            raise TypeError(
                f"agents_config must be a dict[str, AgentConfig], got {type(agents_config).__name__}"
            )
        self._agents: dict[str, AgentConfig] = dict(agents_config)

    # ── Public API ──────────────────────────────

    def check_permission(
        self,
        agent_id: str,
        tool_name: str,
        resource_id: Optional[str] = None,
    ) -> RuleResult:
        """Check if *agent_id* is allowed to invoke *tool_name* on *resource_id*.

        Evaluation order
        ~~~~~~~~~~~~~~~~
        1. Look up agent in the trusted registry.
        2. Verify *tool_name* is in the agent's ``allowed_tools``.
        3. If *resource_id* is provided, verify it matches at least one entry
           in the agent's ``allowed_resources`` (supports shell-style wildcards
           like ``"doc:*"``).

        Returns
        -------
        RuleResult
            ``Decision.ALLOW`` with reason ``RBAC_AUTHORIZED`` when all checks
            pass; ``Decision.BLOCK`` with the first failing reason code otherwise.
        """
        # 1. Agent existence ---------------------------------------------------
        agent = self._agents.get(agent_id)
        if agent is None:
            return RuleResult(
                rule_id=self._RULE_ID,
                decision=Decision.BLOCK,
                reason_code=self._AGENT_NOT_FOUND,
                risk_level=RiskLevel.HIGH,
                metadata={"agent_id": agent_id},
            )

        # 2. Tool permission ---------------------------------------------------
        if tool_name not in agent.allowed_tools:
            return RuleResult(
                rule_id=self._RULE_ID,
                decision=Decision.BLOCK,
                reason_code=self._TOOL_NOT_PERMITTED,
                risk_level=RiskLevel.MEDIUM,
                metadata={
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "allowed_tools": agent.allowed_tools,
                },
            )

        # 3. Resource permission (optional) ------------------------------------
        if resource_id is not None:
            if not self._resource_matches(resource_id, agent.allowed_resources):
                return RuleResult(
                    rule_id=self._RULE_ID,
                    decision=Decision.BLOCK,
                    reason_code=self._RESOURCE_NOT_PERMITTED,
                    risk_level=RiskLevel.HIGH,
                    metadata={
                        "agent_id": agent_id,
                        "resource_id": resource_id,
                        "allowed_resources": agent.allowed_resources,
                    },
                )

        # 4. All checks passed -------------------------------------------------
        return RuleResult(
            rule_id=self._RULE_ID,
            decision=Decision.ALLOW,
            reason_code=self._RBAC_AUTHORIZED,
            risk_level=RiskLevel.LOW,
            metadata={
                "agent_id": agent_id,
                "tool_name": tool_name,
                "resource_id": resource_id,
            },
        )

    def get_agent(self, agent_id: str) -> Optional[AgentConfig]:
        """Return the trusted ``AgentConfig`` for *agent_id*, or ``None``."""
        return self._agents.get(agent_id)

    def validate_no_self_approval(self, agent_id: str, approver_id: str) -> bool:
        """Ensure an agent cannot approve its own actions.

        Returns
        -------
        bool
            ``True`` if the identities differ (valid — no self-approval).
            ``False`` if *agent_id* == *approver_id* (self-approval attempt).
        """
        return agent_id != approver_id

    # ── Private helpers ─────────────────────────

    @staticmethod
    def _resource_matches(resource_id: str, allowed_patterns: list[str]) -> bool:
        """Return ``True`` if *resource_id* matches any pattern in *allowed_patterns*.

        Patterns support shell-style wildcards via :pyfunc:`fnmatch.fnmatch`:
        ``"doc:*"`` matches ``"doc:readme"``, ``"doc:spec/v2"``, etc.
        An exact string match is always accepted.
        """
        for pattern in allowed_patterns:
            if fnmatch.fnmatch(resource_id, pattern):
                return True
        return False
