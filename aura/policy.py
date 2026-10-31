"""
AURA Policy Engine — deterministic policy evaluation with monotone enforcement.

The ``PolicyEngine`` loads the three YAML configs (policy, agents, resources),
runs every enabled rule in priority order, and combines their results using a
monotone lattice:

    ALLOW < DEFER < APPROVAL < BLOCK

A BLOCK from any rule is final and cannot be overridden by the JEV or by
downstream rules.  JEV can only *raise* risk — never lower it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from aura.models import (
    AgentConfig,
    Decision,
    JEVResult,
    PolicyResult,
    ResourceEntry,
    RiskLevel,
    RuleResult,
    RunContext,
    SQLQueryDef,
    ToolRequest,
)
from aura.rules import get_all_rules


# ──────────────────────────────────────────────
# Decision lattice helpers
# ──────────────────────────────────────────────

_DECISION_ORDER: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.DEFER: 1,
    Decision.APPROVAL: 2,
    Decision.BLOCK: 3,
}

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def _max_decision(a: Decision, b: Decision) -> Decision:
    """Return the more restrictive of two decisions."""
    return a if _DECISION_ORDER[a] >= _DECISION_ORDER[b] else b


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    """Return the higher of two risk levels."""
    return a if _RISK_ORDER[a] >= _RISK_ORDER[b] else b


# ──────────────────────────────────────────────
# YAML loader helper
# ──────────────────────────────────────────────

def _load_yaml(path: str | Path) -> dict[str, Any]:
    """Load a YAML file, raising on missing file or parse error."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping at top level in {path}")
    return data


# ──────────────────────────────────────────────
# PolicyEngine
# ──────────────────────────────────────────────

class PolicyEngine:
    """Deterministic policy engine for AURA.

    Loads the three YAML configuration files, exposes helper accessors for
    agent / resource / query lookups, evaluates every enabled rule in
    priority order, and combines the results using monotone enforcement.

    Parameters
    ----------
    config_path:
        Path to ``policy.yaml``, relative to the project root or absolute.
        The *agents.yaml* and *resources.yaml* are expected to reside in
        the same directory.
    """

    def __init__(self, config_path: str = "config/policy.yaml") -> None:
        # Resolve the config directory relative to the project root.
        # The project root is assumed to be two levels above the aura package.
        project_root = Path(__file__).resolve().parent.parent
        config_dir = (project_root / config_path).parent

        policy_path = project_root / config_path
        agents_path = config_dir / "agents.yaml"
        resources_path = config_dir / "resources.yaml"

        self._policy_cfg: dict[str, Any] = _load_yaml(policy_path)
        self._agents_cfg: dict[str, Any] = _load_yaml(agents_path)
        self._resources_cfg: dict[str, Any] = _load_yaml(resources_path)

        # Build a unified config dict that rules receive
        self._merged_config: dict[str, Any] = {
            **self._policy_cfg,
            "agents": self._agents_cfg.get("agents", {}),
            "resources": self._resources_cfg.get("resources", {}),
            "sql_queries": self._resources_cfg.get("sql_queries", {}),
            "approvers": self._agents_cfg.get("approvers", {}),
        }

        # Index enabled rules from policy.yaml by id for fast lookup
        self._enabled_rule_ids: set[str] = set()
        for rule_entry in self._policy_cfg.get("rules", []):
            if rule_entry.get("enabled", True):
                self._enabled_rule_ids.add(rule_entry["id"])

    # ── Public properties ────────────────────

    @property
    def policy_version(self) -> str:
        """Return the policy version string from ``policy.yaml``."""
        return str(self._policy_cfg.get("policy_version", "unknown"))

    @property
    def resources_config(self) -> dict[str, Any]:
        """Return the raw resources configuration mapping."""
        return self._resources_cfg

    @property
    def agents_config(self) -> dict[str, Any]:
        """Return the raw agents configuration mapping."""
        return self._agents_cfg

    @property
    def policy_config(self) -> dict[str, Any]:
        """Return the raw policy configuration mapping."""
        return self._policy_cfg

    @property
    def agents(self) -> dict[str, AgentConfig]:
        """Return trusted agent configurations indexed by agent_id."""
        return {
            k: AgentConfig(**v) if isinstance(v, dict) else v
            for k, v in self._agents_cfg.get("agents", {}).items()
        }

    # ── Config accessors ─────────────────────

    def get_agent_config(self, agent_id: str) -> Optional[AgentConfig]:
        """Look up an agent by id in the agent registry.

        Returns ``None`` if the agent is not registered.
        """
        agents: dict[str, Any] = self._agents_cfg.get("agents", {})
        raw = agents.get(agent_id)
        if raw is None:
            return None
        return AgentConfig(**raw)

    def get_resource(self, resource_id: str) -> Optional[ResourceEntry]:
        """Look up a resource by id in the resource registry.

        Returns ``None`` if the resource is not registered.
        """
        resources: dict[str, Any] = self._resources_cfg.get("resources", {})
        raw = resources.get(resource_id)
        if raw is None:
            return None
        return ResourceEntry(**raw)

    def get_sql_query(self, query_name: str) -> Optional[SQLQueryDef]:
        """Look up a named SQL query by name in the allowlist.

        Returns ``None`` if the query is not registered.
        """
        queries: dict[str, Any] = self._resources_cfg.get("sql_queries", {})
        raw = queries.get(query_name)
        if raw is None:
            return None
        return SQLQueryDef(**raw)

    # ── Core evaluation ──────────────────────

    def evaluate(
        self,
        request: ToolRequest,
        context: RunContext,
    ) -> PolicyResult:
        """Run all enabled deterministic rules and combine their results.

        Combination uses **monotone enforcement**:

        * Any ``BLOCK`` → final ``BLOCK`` (immediate, cannot be overridden).
        * Any ``APPROVAL`` → final ``APPROVAL`` (unless blocked).
        * All ``ALLOW`` / ``DEFER`` → ``ALLOW`` if at least one ``ALLOW``,
          else ``DEFER``.
        * ``final_risk_level`` = max of all individual rule risk levels.
        * ``requires_jev`` = True when the final decision is ``DEFER``.
        * ``requires_approval`` = True when any rule returned ``APPROVAL``.
        """
        all_rules = get_all_rules()
        rule_results: list[RuleResult] = []

        final_decision = Decision.ALLOW
        final_risk = RiskLevel.LOW
        has_allow = False
        has_defer = False
        has_approval = False

        for rule_fn in all_rules:
            # Derive rule_id from function name → uppercase
            rule_id = rule_fn.__name__.replace("rule_", "RULE_").upper()
            if rule_id not in self._enabled_rule_ids:
                continue

            result = rule_fn(request, context, self._merged_config)
            rule_results.append(result)

            # Track individual decision types
            if result.decision == Decision.ALLOW:
                has_allow = True
            elif result.decision == Decision.DEFER:
                has_defer = True
            elif result.decision == Decision.APPROVAL:
                has_approval = True

            # Monotone: take the most restrictive decision
            final_decision = _max_decision(final_decision, result.decision)
            final_risk = _max_risk(final_risk, result.risk_level)

            # Short-circuit: if we already have a BLOCK, remaining rules
            # still run for audit completeness but cannot change the outcome.

        # Refine final decision for the ALLOW/DEFER case
        if final_decision not in (Decision.BLOCK, Decision.APPROVAL):
            if has_defer and not has_allow:
                final_decision = Decision.DEFER
            elif has_allow:
                final_decision = Decision.ALLOW if not has_defer else Decision.DEFER

        # When no rules ran at all, default to DEFER (fail-safe)
        if not rule_results:
            final_decision = Decision.DEFER

        requires_jev = (has_defer or final_decision == Decision.DEFER) and final_decision != Decision.BLOCK
        requires_approval = has_approval and final_decision != Decision.BLOCK

        # Permissive / Monitor Mode: if configured, allow all actions while preserving audit findings
        if self._policy_cfg.get("enforcement_mode") == "permissive":
            final_decision = Decision.ALLOW
            requires_jev = False
            requires_approval = False

        return PolicyResult(
            rule_results=rule_results,
            final_decision=final_decision,
            final_risk_level=final_risk,
            policy_version=self.policy_version,
            requires_jev=requires_jev,
            requires_approval=requires_approval,
        )

    # ── JEV combination ─────────────────────

    def combine_with_jev(
        self,
        policy_result: PolicyResult,
        jev_result: JEVResult,
    ) -> PolicyResult:
        """Combine the deterministic policy result with a JEV assessment.

        Monotone enforcement guarantees:

        * JEV can **raise** the risk level but **NEVER** lower it.
        * JEV **CANNOT** override a deterministic ``BLOCK``.
        * If JEV recommends ``BLOCK`` and policy was not ``BLOCK``, the
          combined result becomes ``BLOCK``.
        * If JEV failed or timed out, fail closed to ``BLOCK``.
        """
        # If policy already blocked, JEV cannot change anything
        if policy_result.final_decision == Decision.BLOCK:
            return policy_result

        # If JEV was not invoked, return as-is
        if not jev_result.invoked:
            return policy_result

        # Fail closed on JEV timeout, error, or missing assessment
        if jev_result.assessment is None or jev_result.failure_reason:
            return PolicyResult(
                rule_results=policy_result.rule_results,
                final_decision=Decision.BLOCK,
                final_risk_level=RiskLevel.CRITICAL,
                policy_version=self.policy_version,
                requires_jev=False,
                requires_approval=False,
            )

        assessment = jev_result.assessment

        # Risk level: monotone max (JEV can only raise)
        combined_risk = _max_risk(
            policy_result.final_risk_level,
            assessment.risk_level,
        )

        # Decision: monotone max (JEV can raise to BLOCK or APPROVAL, but never lower)
        combined_decision = _max_decision(
            policy_result.final_decision,
            assessment.recommendation,
        )

        # Escalation based on JEV risk level:
        # HIGH risk -> escalate to APPROVAL (requires human user approval)
        # CRITICAL risk -> escalate to BLOCK
        if assessment.risk_level == RiskLevel.HIGH and combined_decision not in (Decision.BLOCK, Decision.APPROVAL):
            combined_decision = Decision.APPROVAL
        elif assessment.risk_level == RiskLevel.CRITICAL:
            combined_decision = Decision.BLOCK

        # Update requires flags
        requires_jev = combined_decision == Decision.DEFER
        requires_approval = (
            policy_result.requires_approval
            or combined_decision == Decision.APPROVAL
        ) and combined_decision != Decision.BLOCK

        return PolicyResult(
            rule_results=policy_result.rule_results,
            final_decision=combined_decision,
            final_risk_level=combined_risk,
            policy_version=policy_result.policy_version,
            requires_jev=requires_jev,
            requires_approval=requires_approval,
        )
