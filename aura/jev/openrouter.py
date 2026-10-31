"""OpenRouter JEV Provider.

Uses OpenRouter API to evaluate ambiguous actions with:
  - Local Pydantic cross-field consistency checks
  - Minimal context with hard context cap (1500 chars)
  - 5-second deadline and max 2 attempts
  - Strict fail-closed semantics (timeout, network error, malformed output -> BLOCK)
"""

from __future__ import annotations

import json
import os
import time
from typing import TYPE_CHECKING, Any

from aura.jev.base import JEVProvider
from aura.jev.schema import JEVStructuredResponse
from aura.models import Decision, JEVResult, RiskLevel

if TYPE_CHECKING:
    from aura.models import AuraRequest, RunContext

HARD_CONTEXT_CAP_CHARS = 1500
MAX_ATTEMPTS = 2
PER_ATTEMPT_TIMEOUT_SECONDS = 5.0
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"


class OpenRouterJEVProvider(JEVProvider):
    """OpenRouter JEV provider."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "anthropic/claude-3.5-sonnet",
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._model_name = model_name

    @property
    def provider_name(self) -> str:
        return "openrouter"

    @property
    def model_name(self) -> str:
        return self._model_name

    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
        *,
        timeout_seconds: float = PER_ATTEMPT_TIMEOUT_SECONDS,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> JEVResult:
        start_time = time.monotonic()

        # 1. API key check (no silent fallback)
        if not self._api_key:
            return JEVResult(
                provider=self.provider_name,
                model=self.model_name,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                findings="",
                latency_ms=(time.monotonic() - start_time) * 1000,
                token_usage=0,
                attempt=1,
                error="JEV_UNAVAILABLE: OPENROUTER_API_KEY not configured",
            )

        # 2. Context cap check
        minimal_context = {
            "action": request.action.value,
            "agent_id": request.agent.agent_id,
            "agent_role": request.agent.role,
            "params": {k: str(v)[:100] for k, v in request.params.items()},
            "tainted": context.taint.tainted,
        }
        context_str = json.dumps(minimal_context, separators=(",", ":"))

        if len(context_str) > HARD_CONTEXT_CAP_CHARS:
            return JEVResult(
                provider=self.provider_name,
                model=self.model_name,
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                findings="",
                latency_ms=(time.monotonic() - start_time) * 1000,
                token_usage=0,
                attempt=1,
                error=f"CONTEXT_CAP_EXCEEDED: payload {len(context_str)} > cap {HARD_CONTEXT_CAP_CHARS}",
            )

        # 3. Execution attempts
        last_error = "UNKNOWN_ERROR"
        import httpx

        for attempt in range(1, max_attempts + 1):
            attempt_start = time.monotonic()
            try:
                headers = {
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "model": self._model_name,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Evaluate action risk. Return JSON with fields: "
                                "decision ('ALLOW'|'BLOCK'|'APPROVAL'|'DEFER'), "
                                "risk_level (0 to 4), reason, findings, confidence_score (0.0 to 1.0)."
                            ),
                        },
                        {"role": "user", "content": context_str},
                    ],
                }

                with httpx.Client(timeout=timeout_seconds) as client:
                    resp = client.post(OPENROUTER_API_URL, json=payload, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()

                raw_content = data["choices"][0]["message"]["content"]
                parsed = json.loads(raw_content)
                validated = JEVStructuredResponse.model_validate(parsed)

                tokens = data.get("usage", {}).get("total_tokens", 0)
                latency_ms = (time.monotonic() - start_time) * 1000

                return JEVResult(
                    provider=self.provider_name,
                    model=self.model_name,
                    decision=validated.decision,
                    risk_level=validated.risk_level,
                    findings=f"{validated.reason}. {validated.findings}",
                    latency_ms=latency_ms,
                    token_usage=tokens,
                    attempt=attempt,
                    error=None,
                )

            except Exception as exc:
                elapsed = time.monotonic() - attempt_start
                if elapsed >= timeout_seconds:
                    last_error = f"JEV_TIMEOUT: attempt {attempt} exceeded {timeout_seconds}s"
                else:
                    last_error = f"JEV_ERROR: {str(exc)}"

        return JEVResult(
            provider=self.provider_name,
            model=self.model_name,
            decision=Decision.BLOCK,
            risk_level=RiskLevel.HIGH,
            findings="",
            latency_ms=(time.monotonic() - start_time) * 1000,
            token_usage=0,
            attempt=max_attempts,
            error=last_error,
        )

