"""JEV provider base interface.

JEV (Judgement-Evaluation-Verification) is invoked only for genuinely
ambiguous cases after deterministic rules have run.  The provider
interface is intentionally simple and synchronous for Phase 1.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aura.models import AuraRequest, JEVResult, RunContext


class JEVProvider(ABC):
    """Abstract base for JEV providers (Mock, Gemini, OpenRouter)."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name for audit logging."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier for audit logging."""
        ...

    @abstractmethod
    def evaluate(
        self,
        request: AuraRequest,
        context: RunContext,
        *,
        timeout_seconds: float = 5.0,
        max_attempts: int = 2,
    ) -> JEVResult:
        """Evaluate the request for ambiguity resolution.

        Must return within ``timeout_seconds`` per attempt, with at most
        ``max_attempts``.  On failure, must return a JEVResult with
        ``decision=BLOCK`` and a descriptive error.
        """
        ...

