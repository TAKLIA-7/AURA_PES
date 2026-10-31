"""Mock JEV provider for testing and development.

Returns configurable results without any network calls.
Defaults to ALLOW with LOW risk.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from aura.jev.base import JEVProvider
from aura.models import Decision, JEVResult, RiskLevel

if TYPE_CHECKING:
    from aura.models import AuraRequest, RunContext


class MockJEVProvider(JEVProvider):
    """Deterministic mock JEV for testing.

    Configure the mock's response at construction::

        jev = MockJEVProvider(decision=Decision.ALLOW, risk_level=RiskLevel.LOW)
        jev = MockJEVProvider(should_timeout=True)
        jev = MockJEVProvider(should_return_malformed=True)
    """

    def __init__(
        self,
        *,
        decision: Decision = Decision.ALLOW,
        risk_level: RiskLevel = RiskLevel.LOW,
        findings: str = "Mock JEV evaluation — no real analysis performed.",
        should_timeout: bool = False,
        should_return_malformed: bool = False,
        simulated_latency_ms: float = 10.0,
        simulated_tokens: int = 50,
    ) -> None:
        self._decision = decision
        self._risk_level = risk_level
        self._findings = findings
        self._should_timeout = should_timeout
        self._should_return_malformed = should_return_malformed
        self._latency_ms = simulated_latency_ms
        self._tokens = simulated_tokens
        self.call_count = 0

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return "mock-v1"

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
        *,
        timeout_seconds: float = 5.0,
        max_attempts: int = 2,
    ) -> JEVResult:
        self.call_count += 1
        start = time.monotonic()

        # Simulate timeout.
        if self._should_timeout:
            elapsed = (time.monotonic() - start) * 1000
            return JEVResult(
                provider=self.provider_name,
                model=self.model_name,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                findings="",
                latency_ms=elapsed,
                token_usage=0,
                attempt=max_attempts,
                error="JEV_TIMEOUT",
            )

        # Simulate malformed output.
        if self._should_return_malformed:
            elapsed = (time.monotonic() - start) * 1000
            return JEVResult(
                provider=self.provider_name,
                model=self.model_name,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                findings="",
                latency_ms=elapsed,
                token_usage=0,
                attempt=1,
                error="JEV_MALFORMED_OUTPUT",
            )

        elapsed = (time.monotonic() - start) * 1000 + self._latency_ms
        return JEVResult(
            provider=self.provider_name,
            model=self.model_name,
            decision=self._decision,
            risk_level=self._risk_level,
            findings=self._findings,
            latency_ms=elapsed,
            token_usage=self._tokens,
            attempt=1,
            error=None,
        )
