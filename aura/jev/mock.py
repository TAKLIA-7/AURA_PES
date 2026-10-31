"""
AURA JEV — Deterministic mock provider for development and testing.

:class:`MockJEVProvider` returns predictable, configurable results so
that the rest of the AURA pipeline can be exercised without any
external API calls.  Constructor flags control the simulated behaviour:

* ``should_timeout`` — simulates a JEV timeout.
* ``should_return_malformed`` — simulates un-parseable model output.
* ``should_return_contradictory`` — returns LOW risk with dangerous
  findings, which :class:`~aura.models.JEVAssessment` cross-field
  validation will escalate to HIGH.
"""

from __future__ import annotations

import asyncio
import time

from aura.jev.base import JEVProvider
from aura.models import (
    Decision,
    JEVAssessment,
    JEVResult,
    RiskLevel,
    RunContext,
    ToolRequest,
)


class MockJEVProvider(JEVProvider):
    """Deterministic mock JEV provider for development and testing.

    Examples
    --------
    >>> provider = MockJEVProvider(default_risk=RiskLevel.LOW)
    >>> result = await provider.assess(request, context)
    >>> assert result.assessment.risk_level == RiskLevel.LOW

    >>> timeout_provider = MockJEVProvider(should_timeout=True)
    >>> result = await timeout_provider.assess(request, context)
    >>> assert result.failure_reason == "JEV_TIMEOUT"
    """

    def __init__(
        self,
        default_risk: RiskLevel = RiskLevel.LOW,
        *,
        should_timeout: bool = False,
        should_return_malformed: bool = False,
        should_return_contradictory: bool = False,
    ) -> None:
        """Initialise the mock provider.

        Parameters
        ----------
        default_risk:
            Risk level to return under normal operation.
        should_timeout:
            If ``True``, :meth:`assess` simulates a timeout failure.
        should_return_malformed:
            If ``True``, :meth:`assess` returns a ``JEV_MALFORMED_OUTPUT``
            failure result.
        should_return_contradictory:
            If ``True``, :meth:`assess` returns a LOW-risk assessment
            with findings that mention *"confidential external"*, which
            triggers the cross-field validator to escalate to HIGH.
        """
        self._default_risk = default_risk
        self._should_timeout = should_timeout
        self._should_return_malformed = should_return_malformed
        self._should_return_contradictory = should_return_contradictory
        self.call_count: int = 0

    # ── properties ───────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        """Provider identifier: ``"mock"``."""
        return "mock"

    @property
    def model_name(self) -> str:  # noqa: D401
        """Model identifier: ``"mock-v1"``."""
        return "mock-v1"

    # ── assess ───────────────────────────────────────────────────────

    async def assess(
        self,
        request: ToolRequest,
        context: RunContext,
        timeout_seconds: float = 5.0,
        max_context_tokens: int = 4096,
    ) -> JEVResult:
        """Return a deterministic JEV result based on constructor flags.

        The method increments :attr:`call_count` on every invocation,
        making it easy to assert that the provider was called the
        expected number of times in tests.

        Parameters
        ----------
        request:
            The tool request to evaluate.
        context:
            Trusted execution context.
        timeout_seconds:
            Ignored by the mock, but accepted for interface conformance.
        max_context_tokens:
            Ignored by the mock, but accepted for interface conformance.

        Returns
        -------
        JEVResult
            A result whose content depends on the constructor flags.
        """
        self.call_count += 1
        start = time.perf_counter()

        # ── Timeout simulation ───────────────────────────────────────
        if self._should_timeout:
            # Simulate a brief delay so latency is non-zero.
            await asyncio.sleep(0.01)
            latency_ms = (time.perf_counter() - start) * 1000
            return self._failure_result("JEV_TIMEOUT", latency_ms, attempts=1)

        # ── Malformed-output simulation ──────────────────────────────
        if self._should_return_malformed:
            latency_ms = (time.perf_counter() - start) * 1000
            return self._failure_result(
                "JEV_MALFORMED_OUTPUT: mock malformed response",
                latency_ms,
                attempts=1,
            )

        # ── Contradictory-assessment simulation ──────────────────────
        if self._should_return_contradictory:
            # LOW risk + dangerous keywords → cross-field validator
            # in JEVAssessment will escalate to HIGH automatically.
            assessment = JEVAssessment(
                risk_level=RiskLevel.LOW,
                findings=[
                    "Data marked confidential external detected in parameters",
                ],
                recommendation=Decision.ALLOW,
                confidence=0.6,
                reasoning="Mock contradictory assessment for testing",
            )
            latency_ms = (time.perf_counter() - start) * 1000
            return JEVResult(
                invoked=True,
                assessment=assessment,
                provider=self.provider_name,
                model=self.model_name,
                latency_ms=latency_ms,
                input_tokens=0,
                output_tokens=0,
                estimated_cost_usd=0.0,
                attempts=1,
                schema_valid=True,
            )

        # ── Normal (happy-path) result ───────────────────────────────
        # Derive a decision from the default risk level.
        decision_map: dict[RiskLevel, Decision] = {
            RiskLevel.LOW: Decision.ALLOW,
            RiskLevel.MEDIUM: Decision.ALLOW,
            RiskLevel.HIGH: Decision.APPROVAL,
            RiskLevel.CRITICAL: Decision.BLOCK,
        }
        assessment = JEVAssessment(
            risk_level=self._default_risk,
            findings=["Mock assessment: nominal"],
            recommendation=decision_map.get(self._default_risk, Decision.DEFER),
            confidence=0.8,
            reasoning="Deterministic mock assessment — no real model invocation",
        )
        latency_ms = (time.perf_counter() - start) * 1000
        return JEVResult(
            invoked=True,
            assessment=assessment,
            provider=self.provider_name,
            model=self.model_name,
            latency_ms=latency_ms,
            input_tokens=0,
            output_tokens=0,
            estimated_cost_usd=0.0,
            attempts=1,
            schema_valid=True,
        )
