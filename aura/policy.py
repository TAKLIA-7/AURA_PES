"""AURA Policy Engine.

Evaluates an ordered list of deterministic rules against a request.

Invariants:
  - A ``BLOCK`` from any rule is final — short-circuits evaluation.
  - Risk levels combine monotonically: ``final = max(all rule risks)``.
  - JEV may raise risk, never lower it.
  - Policy version is recorded for audit binding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aura.models import Decision, PolicyDecision, RiskLevel

if TYPE_CHECKING:
    from aura.models import AuraRequest, RunContext
    from aura.rules import Rule


class PolicyEngine:
    """Ordered deterministic rule evaluator.

    Usage::

        engine = PolicyEngine(rules=[rbac_rule, resource_rule, ...], version="1.0")
        decision = engine.evaluate(request, context)
    """

    def __init__(self, rules: list[Rule], version: str = "1.0") -> None:
        self._rules = rules
        self._version = version

    @property
    def version(self) -> str:
        return self._version

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
    ) -> PolicyDecision:
        """Run all enabled rules in order against *request* / *context*.

        Returns a ``PolicyDecision`` with:
          - ``decision``: the aggregate outcome.
          - ``risk_level``: ``max()`` across all rule risk levels.
          - ``rule_results``: individual results from each rule.
          - ``deciding_rule_id``: the rule that produced the final decision.
        """
        from aura.models import RuleResult

        rule_results: list[RuleResult] = []
        max_risk = RiskLevel.NONE
        final_decision = Decision.ALLOW
        deciding_rule_id: str | None = None
        final_reason_code = "DEFAULT_ALLOW"

        for rule in self._rules:
            if not rule.enabled:
                continue

            result = rule.evaluate(request, context)
            if result is None:
                # Rule is not applicable to this request.
                continue

            rule_results.append(result)

            # Monotone risk combination.
            if result.risk_level > max_risk:
                max_risk = RiskLevel(result.risk_level)

            # A BLOCK is final — short-circuit immediately.
            if result.decision == Decision.BLOCK:
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel(max(max_risk, result.risk_level)),
                    rule_results=rule_results,
                    policy_version=self._version,
                    deciding_rule_id=result.rule_id,
                    reason_code=result.reason_code,
                )

            # Track the most restrictive non-BLOCK decision.
            # Priority: APPROVAL > DEFER > ALLOW
            decision_priority = {
                Decision.ALLOW: 0,
                Decision.DEFER: 1,
                Decision.APPROVAL: 2,
            }

            if decision_priority.get(result.decision, 0) > decision_priority.get(
                final_decision, 0
            ):
                final_decision = result.decision
                deciding_rule_id = result.rule_id
                final_reason_code = result.reason_code

            # If this is the first rule to produce a result, set it as deciding.
            if deciding_rule_id is None:
                deciding_rule_id = result.rule_id
                final_reason_code = result.reason_code

        return PolicyDecision(
            decision=final_decision,
            risk_level=max_risk,
            rule_results=rule_results,
            policy_version=self._version,
            deciding_rule_id=deciding_rule_id,
            reason_code=final_reason_code,
        )

    def combine_with_jev(
        self,
        policy_decision: PolicyDecision,
        jev_risk: RiskLevel,
        jev_decision: Decision,
    ) -> PolicyDecision:
        """Combine the deterministic policy result with a JEV assessment.

        JEV may raise risk but never lower it.  A deterministic BLOCK
        is final regardless of JEV.
        """
        # Deterministic BLOCK is final.
        if policy_decision.decision == Decision.BLOCK:
            return policy_decision

        # Monotone risk: final = max(policy, jev).
        combined_risk = RiskLevel(max(policy_decision.risk_level, jev_risk))

        # JEV can escalate decision but not downgrade.
        decision_priority = {
            Decision.ALLOW: 0,
            Decision.DEFER: 1,
            Decision.APPROVAL: 2,
            Decision.BLOCK: 3,
        }

        if decision_priority.get(jev_decision, 0) > decision_priority.get(
            policy_decision.decision, 0
        ):
            combined_decision = jev_decision
        else:
            combined_decision = policy_decision.decision

        return PolicyDecision(
            decision=combined_decision,
            risk_level=combined_risk,
            rule_results=policy_decision.rule_results,
            policy_version=policy_decision.policy_version,
            deciding_rule_id=policy_decision.deciding_rule_id,
            reason_code=policy_decision.reason_code,
        )
