"""AURA JEV Structured Response Schema and Cross-Field Validators.

Enforces cross-field consistency for all LLM-backed JEV assessments.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from aura.models import Decision, RiskLevel


class JEVStructuredResponse(BaseModel):
    """Structured output expected from JEV models (Gemini / OpenRouter).

    Invariants:
      - Cross-field consistency: Decisions and risk levels must be logically consistent.
      - If decision is BLOCK, risk must be at least MEDIUM.
      - If risk is CRITICAL, decision must be BLOCK.
      - If decision is ALLOW, risk must NOT be CRITICAL or HIGH.
    """
    decision: Decision
    risk_level: RiskLevel
    reason: str = Field(..., min_length=1, description="Concise rationale for assessment")
    findings: str = Field(..., min_length=1, description="Specific safety/policy findings")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Model confidence 0.0-1.0")

    @model_validator(mode="after")
    def _validate_cross_field_consistency(self) -> JEVStructuredResponse:
        dec = self.decision
        risk = self.risk_level

        # Critical risk must always be blocked
        if risk == RiskLevel.CRITICAL and dec != Decision.BLOCK:
            raise ValueError(f"Cross-field inconsistency: risk is CRITICAL but decision is '{dec.value}'")

        # BLOCK should not have NONE or LOW risk
        if dec == Decision.BLOCK and risk in (RiskLevel.NONE, RiskLevel.LOW):
            raise ValueError(f"Cross-field inconsistency: decision is BLOCK but risk level is '{risk.name}'")

        # ALLOW should not have HIGH or CRITICAL risk
        if dec == Decision.ALLOW and risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            raise ValueError(f"Cross-field inconsistency: decision is ALLOW but risk level is '{risk.name}'")

        return self

