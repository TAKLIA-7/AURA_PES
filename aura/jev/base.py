"""
AURA JEV — Abstract base class for Judgment and Evaluation providers.

Every JEV provider *must* subclass :class:`JEVProvider` and implement
:pymethod:`assess`.  The base class supplies safe helpers for building
minimal LLM context and generating fail-closed results.

Design invariants
-----------------
* **Fail closed** — any error, timeout, or malformed output produces a
  ``BLOCK`` decision with a descriptive ``failure_reason``.
* **Minimal context** — only tool name, parameter *keys* (never full
  values), agent role, and resource id are sent to the model.
* **Hard timeout** — providers must enforce a wall-clock timeout
  (default 5 s) via ``asyncio.wait_for`` or equivalent.
* **Bounded retries** — at most 2 attempts per assessment.
* **Pydantic validation** — every model response is parsed into
  :class:`~aura.models.JEVAssessment` so cross-field validators fire.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from aura.models import (
    Decision,
    JEVAssessment,
    JEVResult,
    RiskLevel,
    RunContext,
    ToolRequest,
)


class JEVProvider(ABC):
    """Abstract base class for all JEV (Judgment and Evaluation) providers.

    Subclasses must implement :pyattr:`provider_name`,
    :pyattr:`model_name`, and :pymethod:`assess`.
    """

    # ── abstract properties ──────────────────────────────────────────

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short, unique identifier for this provider (e.g. ``"gemini"``)."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier used by this provider (e.g. ``"gemini-2.0-flash"``)."""
        ...

    # ── abstract methods ─────────────────────────────────────────────

    @abstractmethod
    async def assess(
        self,
        request: ToolRequest,
        context: RunContext,
        timeout_seconds: float = 5.0,
        max_context_tokens: int = 4096,
    ) -> JEVResult:
        """Assess a tool request for risk and return a validated result.

        **Contract every implementation must honour:**

        1. Enforce a hard wall-clock timeout (``timeout_seconds``).
        2. Limit to **at most 2 attempts**.
        3. Parse the model response via :class:`~aura.models.JEVAssessment`
           so that Pydantic cross-field validators are applied.
        4. On *any* failure (timeout, parse error, network error, etc.)
           return :meth:`_failure_result` — never raise.
        5. Record ``provider``, ``model``, ``latency_ms``, token counts,
           and ``attempts`` in the returned :class:`~aura.models.JEVResult`.

        Parameters
        ----------
        request:
            The tool request to evaluate.
        context:
            Trusted execution context for the request.
        timeout_seconds:
            Maximum wall-clock seconds for the entire assessment
            (including all retry attempts).  Default ``5.0``.
        max_context_tokens:
            Rough token budget for the context string sent to the model.
            Uses the heuristic *4 chars ≈ 1 token*.  Default ``4096``.

        Returns
        -------
        JEVResult
            Always returns — never raises.
        """
        ...

    # ── helpers ──────────────────────────────────────────────────────

    def _build_minimal_context(
        self,
        request: ToolRequest,
        context: RunContext,
        max_tokens: int,
    ) -> str:
        """Build a *minimal*, authorised context string for the JEV model.

        Only the following fields are exposed:

        * ``tool_name``
        * parameter **keys** (values are redacted)
        * ``agent_role``
        * ``resource_id`` (if derivable from parameters)
        * ``tainted`` flag and ``taint_sources``

        Full parameter values, conversation history, and any other
        potentially sensitive information are **never** included.

        Parameters
        ----------
        request:
            The tool request being evaluated.
        context:
            Trusted run context.
        max_tokens:
            Approximate token cap.  The string is truncated to
            ``max_tokens * 4`` characters (4 chars ≈ 1 token).

        Returns
        -------
        str
            A JSON-serialised summary suitable for an LLM prompt.
        """
        resource_id: str = str(request.parameters.get("resource_id", ""))
        summary: dict[str, Any] = {
            "tool_name": request.tool_name,
            "parameter_keys": sorted(request.parameters.keys()),
            "agent_role": context.agent_role,
            "resource_id": resource_id,
            "tainted": context.tainted,
            "taint_sources": context.taint_sources,
            "confidential_data_accessed": context.confidential_data_accessed,
        }
        raw = json.dumps(summary, sort_keys=True, separators=(",", ":"))
        max_chars = max_tokens * 4
        if len(raw) > max_chars:
            raw = raw[:max_chars]
        return raw

    def _failure_result(
        self,
        reason: str,
        latency_ms: float = 0.0,
        attempts: int = 0,
    ) -> JEVResult:
        """Create a fail-closed :class:`~aura.models.JEVResult`.

        The returned result has ``invoked=True`` (the provider *was*
        called), ``schema_valid=False``, and a ``failure_reason`` that
        records what went wrong.  The assessment is a hard ``BLOCK``
        with ``CRITICAL`` risk so the gateway never accidentally allows
        a request when JEV is unavailable.

        Parameters
        ----------
        reason:
            Human-readable failure reason (e.g. ``"JEV_TIMEOUT"``).
        latency_ms:
            Elapsed milliseconds before the failure was declared.
        attempts:
            Number of attempts made before giving up.

        Returns
        -------
        JEVResult
            A ``BLOCK`` / ``CRITICAL`` result.
        """
        return JEVResult(
            invoked=True,
            assessment=JEVAssessment(
                risk_level=RiskLevel.CRITICAL,
                findings=[f"JEV failure: {reason}"],
                recommendation=Decision.BLOCK,
                confidence=0.0,
                reasoning=f"JEV provider unavailable: {reason}",
            ),
            provider=self.provider_name,
            model=self.model_name,
            latency_ms=latency_ms,
            attempts=attempts,
            failure_reason=reason,
            schema_valid=False,
        )
