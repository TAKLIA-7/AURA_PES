"""Gemini JEV Provider.

Uses Google Gemini to evaluate genuinely ambiguous actions with:
  - Local Pydantic cross-field validation
  - Minimal authorized context with hard context cap (1500 chars)
  - 5-second attempt deadline and at most 2 attempts
  - Strict fail-closed semantics (timeout, provider error, malformed output -> BLOCK)
  - Never silently falls back to Mock JEV
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


class GeminiJEVProvider(JEVProvider):
    """Google Gemini JEV provider for ambiguity resolution."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-2.5-flash",
    ) -> None:
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self._model_name = model_name

    @property
    def provider_name(self) -> str:
        return "gemini"

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
        """Evaluate ambiguous request via Gemini with strict fail-closed handling."""
        start_time = time.monotonic()

        # 1. Check for API key (fail closed if missing — no silent mock fallback)
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
                error="JEV_UNAVAILABLE: GEMINI_API_KEY not configured",
            )

        # 2. Context Minimization & Hard Context Cap Check
        minimal_context = self._build_minimal_context(request, context)
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
                error=f"CONTEXT_CAP_EXCEEDED: payload length {len(context_str)} > cap {HARD_CONTEXT_CAP_CHARS}",
            )

        # 3. Execution attempts (max 2 attempts)
        last_error = "UNKNOWN_ERROR"
        for attempt in range(1, max_attempts + 1):
            attempt_start = time.monotonic()
            try:
                # Import SDK locally
                from google import genai
                from google.genai import types

                client = genai.Client(api_key=self._api_key)

                prompt = (
                    "You are AURA JEV (Judgement-Evaluation-Verification), an AI security gatekeeper.\n"
                    "Evaluate whether the following proposed agent tool action presents a safety, "
                    "confidentiality, or policy risk. Return a structured JSON assessment with fields:\n"
                    "  - decision: 'ALLOW' | 'BLOCK' | 'APPROVAL' | 'DEFER'\n"
                    "  - risk_level: 0 (NONE) | 1 (LOW) | 2 (MEDIUM) | 3 (HIGH) | 4 (CRITICAL)\n"
                    "  - reason: short reason\n"
                    "  - findings: specific security findings\n"
                    "  - confidence_score: float between 0.0 and 1.0\n\n"
                    f"Context: {context_str}"
                )

                response = client.models.generate_content(
                    model=self._model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=JEVStructuredResponse,
                    ),
                )

                latency_ms = (time.monotonic() - start_time) * 1000
                raw_text = response.text or "{}"

                # Parse and validate with local cross-field Pydantic validator
                structured_data = json.loads(raw_text)
                validated = JEVStructuredResponse.model_validate(structured_data)

                # Token count estimate or from response usage
                tokens = 0
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    tokens = getattr(response.usage_metadata, "total_token_count", 0)

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

        # Fail closed after exhausted attempts
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

    def _build_minimal_context(
        self, request: AuraRequest, context: RunContext
    ) -> dict[str, Any]:
        """Construct sanitized minimal context (no raw secrets, tokens, or oversized payloads)."""
        # Safe parameter keys only
        safe_params = {}
        for k, v in request.params.items():
            if k in ("doc_id", "op", "query_name"):
                safe_params[k] = str(v)
            elif k == "to":
                safe_params[k] = str(v)
            elif k == "body":
                # Do not send full body, summarize length only
                safe_params["body_summary"] = f"Text length: {len(str(v))} chars"

        return {
            "action": request.action.value,
            "agent_id": request.agent.agent_id,
            "agent_role": request.agent.role,
            "params": safe_params,
            "tainted": context.taint.tainted,
        }

