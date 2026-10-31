"""
AURA JEV — OpenRouter provider.

Uses the OpenRouter chat-completions HTTP API (via ``httpx``) to obtain
structured risk assessments.  This provider is an *optional* alternative
to :class:`~aura.jev.gemini.GeminiJEVProvider` and is useful when
access to the Google AI SDK is unavailable or when a different backing
model is preferred.

Environment
-----------
``OPENROUTER_API_KEY``
    Must be set to a valid OpenRouter API key.  If missing the provider
    returns a ``BLOCK`` result immediately.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

import httpx

from aura.jev.base import JEVProvider
from aura.models import (
    JEVAssessment,
    JEVResult,
    RunContext,
    ToolRequest,
)

# ── Prompt constants ─────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a security risk assessor embedded in a policy enforcement "
    "system.  Analyse the following AI agent tool request and return a "
    "risk assessment as **valid JSON only** — no commentary, no markdown "
    "fences, no extra text."
)

_RESPONSE_SCHEMA = (
    '{"risk_level": "LOW|MEDIUM|HIGH|CRITICAL", '
    '"findings": ["..."], '
    '"recommendation": "ALLOW|BLOCK|APPROVAL|DEFER", '
    '"confidence": 0.0-1.0, '
    '"reasoning": "..."}'
)

_MAX_COMPLETION_TOKENS = 300


class OpenRouterJEVProvider(JEVProvider):
    """JEV provider backed by the OpenRouter API.

    Parameters
    ----------
    model:
        Model identifier on OpenRouter.  Defaults to
        ``"google/gemini-2.5-flash"``.
    """

    def __init__(self, model: str = "google/gemini-2.5-flash") -> None:
        self._model = model
        self._api_key: str = os.environ.get("OPENROUTER_API_KEY", "")
        self._base_url: str = "https://openrouter.ai/api/v1"

    # ── properties ───────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        """Provider identifier: ``"openrouter"``."""
        return "openrouter"

    @property
    def model_name(self) -> str:  # noqa: D401
        """Configured OpenRouter model name."""
        return self._model

    # ── assess ───────────────────────────────────────────────────────

    async def assess(
        self,
        request: ToolRequest,
        context: RunContext,
        timeout_seconds: float = 5.0,
        max_context_tokens: int = 4096,
    ) -> JEVResult:
        """Query OpenRouter for a structured risk assessment.

        Workflow
        --------
        1. Verify ``OPENROUTER_API_KEY`` is available.
        2. Build minimal context via :meth:`_build_minimal_context`.
        3. Check estimated tokens against ``max_context_tokens``.
        4. POST to OpenRouter ``/chat/completions`` with ``httpx``,
           respecting ``timeout_seconds``.
        5. Parse JSON response into :class:`~aura.models.JEVAssessment`.
        6. On any failure ➜ retry once (max 2 attempts) ➜ fail closed.

        Parameters
        ----------
        request:
            The tool request to evaluate.
        context:
            Trusted execution context.
        timeout_seconds:
            Hard wall-clock timeout for all attempts combined.
        max_context_tokens:
            Maximum estimated token budget for the context payload.

        Returns
        -------
        JEVResult
            Always returns — never raises.
        """
        if not self._api_key:
            return self._failure_result("OPENROUTER_API_KEY not set")

        start = time.perf_counter()
        attempts = 0
        last_error = ""

        while attempts < 2:
            attempts += 1
            try:
                result = await self._single_attempt(
                    request,
                    context,
                    timeout_seconds,
                    max_context_tokens,
                    start,
                    attempts,
                )
                if result is not None:
                    return result
                # None → context too large; no point retrying.
                break
            except asyncio.TimeoutError:
                last_error = "JEV_TIMEOUT"
            except httpx.TimeoutException:
                last_error = "JEV_TIMEOUT"
            except json.JSONDecodeError as exc:
                last_error = f"JEV_MALFORMED_OUTPUT: {exc}"
            except httpx.HTTPStatusError as exc:
                last_error = (
                    f"JEV_ERROR: HTTPStatusError: "
                    f"{exc.response.status_code} {exc.response.reason_phrase}"
                )
            except Exception as exc:  # noqa: BLE001 — fail closed
                last_error = f"JEV_ERROR: {type(exc).__name__}: {exc}"

        latency_ms = (time.perf_counter() - start) * 1000
        return self._failure_result(last_error or "JEV_UNKNOWN", latency_ms, attempts)

    # ── internal ─────────────────────────────────────────────────────

    async def _single_attempt(
        self,
        request: ToolRequest,
        context: RunContext,
        timeout_seconds: float,
        max_context_tokens: int,
        start: float,
        attempts: int,
    ) -> JEVResult | None:
        """Execute a single OpenRouter call.

        Returns ``None`` when the context exceeds the token cap (caller
        should stop retrying).  Raises on timeout, JSON parse failure,
        or HTTP errors so the caller can catch and retry.
        """
        minimal_context = self._build_minimal_context(
            request, context, max_context_tokens,
        )

        estimated_tokens = len(minimal_context) // 4
        if estimated_tokens > max_context_tokens:
            latency_ms = (time.perf_counter() - start) * 1000
            return self._failure_result(
                "Context exceeds token cap", latency_ms, attempts,
            )

        prompt = (
            f"{_SYSTEM_PROMPT}\n\n"
            f"Tool Request Context:\n{minimal_context}\n\n"
            f"Return ONLY valid JSON: {_RESPONSE_SCHEMA}"
        )

        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": _MAX_COMPLETION_TOKENS,
                },
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()

        latency_ms = (time.perf_counter() - start) * 1000

        text = self._extract_json_text(
            data["choices"][0]["message"]["content"],
        )
        parsed: dict[str, Any] = json.loads(text)
        assessment = JEVAssessment(**parsed)

        usage: dict[str, int] = data.get("usage", {})
        input_tokens: int = usage.get("prompt_tokens", estimated_tokens)
        output_tokens: int = usage.get("completion_tokens", len(text) // 4)

        return JEVResult(
            invoked=True,
            assessment=assessment,
            provider=self.provider_name,
            model=self.model_name,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=0.0,
            attempts=attempts,
            schema_valid=True,
        )

    @staticmethod
    def _extract_json_text(raw: str) -> str:
        """Strip optional markdown fences from a model response.

        Parameters
        ----------
        raw:
            Raw text from the model response.

        Returns
        -------
        str
            Cleaned text suitable for ``json.loads``.
        """
        text = raw.strip()
        if text.startswith("```"):
            parts = text.split("```")
            inner = parts[1] if len(parts) >= 2 else text
            if inner.startswith("json"):
                inner = inner[4:]
            text = inner.strip()
        return text
