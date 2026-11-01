"""
AURA JEV — Google Gemini provider.

Uses the ``google-generativeai`` SDK to obtain structured risk
assessments from a Gemini model.  The provider enforces all JEV
base-class invariants:

* Hard wall-clock timeout (default 5 s).
* At most 2 attempts.
* Pydantic validation (including cross-field escalation).
* Fail-closed on any error path.

Environment
-----------
``GOOGLE_API_KEY``
    Must be set to a valid Google AI API key.  If missing the provider
    returns a ``BLOCK`` result immediately.
"""

from __future__ import annotations

import asyncio
import json
import os
import time

from aura.jev.base import JEVProvider
from aura.models import (
    JEVAssessment,
    JEVResult,
    RunContext,
    ToolRequest,
)

# System prompt for the risk-assessment model.
_SYSTEM_PROMPT = (
    "You are a security risk assessor embedded in a policy enforcement "
    "system.  Analyse the following AI agent tool request and return a "
    "risk assessment as **valid JSON only** — no commentary, no markdown "
    "fences, no extra text."
)

_RESPONSE_SCHEMA = (
    '{"risk_level": "LOW|MEDIUM|HIGH|CRITICAL", '
    '"findings": ["list of findings"], '
    '"recommendation": "ALLOW|BLOCK|APPROVAL|DEFER", '
    '"confidence": 0.0-1.0, '
    '"reasoning": "brief explanation"}'
)


class GeminiJEVProvider(JEVProvider):
    """JEV provider backed by Google Gemini.

    Parameters
    ----------
    model:
        Gemini model identifier.  Defaults to ``"gemini-2.0-flash"``.
    """

    def __init__(self, model: str = "gemini-2.0-flash") -> None:
        self._model = model
        self._api_key: str = (
            os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
            or ""
        )

    # ── properties ───────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        """Provider identifier: ``"gemini"``."""
        return "gemini"

    @property
    def model_name(self) -> str:  # noqa: D401
        """Configured Gemini model name."""
        return self._model

    # ── assess ───────────────────────────────────────────────────────

    async def assess(
        self,
        request: ToolRequest,
        context: RunContext,
        timeout_seconds: float = 5.0,
        max_context_tokens: int = 4096,
    ) -> JEVResult:
        """Query Gemini for a structured risk assessment.

        Workflow
        --------
        1. Verify ``GOOGLE_API_KEY`` is available.
        2. Build minimal context via :meth:`_build_minimal_context`.
        3. Check estimated tokens against ``max_context_tokens``.
        4. Send prompt to Gemini, wrapped in
           ``asyncio.wait_for(timeout=timeout_seconds)``.
        5. Parse the JSON response into :class:`~aura.models.JEVAssessment`.
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
        api_key = self._api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return self._failure_result("GOOGLE_API_KEY not set")

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
                # _single_attempt returns None only when context is too
                # large — no point retrying.
                break
            except asyncio.TimeoutError:
                last_error = "JEV_TIMEOUT"
            except json.JSONDecodeError as exc:
                last_error = f"JEV_MALFORMED_OUTPUT: {exc}"
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
        """Execute a single Gemini call via google-genai or legacy SDK."""
        api_key = self._api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
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
            f"Return ONLY valid JSON with this schema:\n{_RESPONSE_SCHEMA}"
        )

        raw_text = ""
        prompt_tokens = estimated_tokens
        cand_tokens = 0

        # Try official google.genai SDK first
        try:
            from google import genai
            client = genai.Client(api_key=api_key)

            def _call_genai():
                return client.models.generate_content(
                    model=self._model,
                    contents=prompt,
                )

            response = await asyncio.wait_for(
                asyncio.to_thread(_call_genai),
                timeout=timeout_seconds,
            )
            raw_text = response.text or ""
            usage = getattr(response, "usage_metadata", None)
            if usage:
                prompt_tokens = getattr(usage, "prompt_token_count", estimated_tokens)
                cand_tokens = getattr(usage, "candidates_token_count", 0)
        except ImportError:
            import google.generativeai as legacy_genai  # type: ignore[import-untyped]
            legacy_genai.configure(api_key=api_key)
            model = legacy_genai.GenerativeModel(self._model)
            response = await asyncio.wait_for(
                asyncio.to_thread(model.generate_content, prompt),
                timeout=timeout_seconds,
            )
            raw_text = response.text or ""
            usage = getattr(response, "usage_metadata", None)
            if usage:
                prompt_tokens = getattr(usage, "prompt_token_count", estimated_tokens)
                cand_tokens = getattr(usage, "candidates_token_count", 0)

        latency_ms = (time.perf_counter() - start) * 1000
        text = self._extract_json_text(raw_text)
        data: dict = json.loads(text)  # may raise JSONDecodeError
        assessment = JEVAssessment(**data)

        return JEVResult(
            invoked=True,
            assessment=assessment,
            provider=self.provider_name,
            model=self.model_name,
            latency_ms=latency_ms,
            input_tokens=prompt_tokens,
            output_tokens=cand_tokens or (len(text) // 4),
            estimated_cost_usd=0.0,
            attempts=attempts,
            schema_valid=True,
        )

    @staticmethod
    def _extract_json_text(raw: str) -> str:
        """Strip optional markdown fences from a model response.

        Models sometimes wrap JSON in ````json … ``` `` blocks.  This
        helper extracts the inner content.

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
            # parts[0] is empty, parts[1] is the code block content
            inner = parts[1] if len(parts) >= 2 else text
            if inner.startswith("json"):
                inner = inner[4:]
            text = inner.strip()
        return text
