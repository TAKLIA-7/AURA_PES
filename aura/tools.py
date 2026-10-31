"""AURA Tool Adapters.

Stub for Phase 1.  Narrow typed adapters will be implemented in Phase 4.
Agents receive schemas, not adapter callables or credentials.
"""

from __future__ import annotations


class ToolAdapter:
    """Base class for tool adapters (Phase 4)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.call_count = 0

    def execute(self, params: dict) -> dict:
        raise NotImplementedError(f"ToolAdapter '{self.name}' — Phase 4")
