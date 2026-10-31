"""Shared test fixtures for AURA test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aura.models import (
    AgentIdentity,
    AuraRequest,
    Decision,
    ResourceInfo,
    ResourceSensitivity,
    RiskLevel,
    RunContext,
    TaintState,
    ToolAction,
)
from aura.rbac import RBACManager
from aura.resources import ResourceRegistry


# ── Paths ────────────────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "config"


# ── Agent fixtures ───────────────────────────────────────────────

@pytest.fixture
def admin_agent() -> AgentIdentity:
    return AgentIdentity(agent_id="admin_agent", role="admin")


@pytest.fixture
def analyst_agent() -> AgentIdentity:
    return AgentIdentity(agent_id="analyst_agent", role="analyst")


@pytest.fixture
def reader_agent() -> AgentIdentity:
    return AgentIdentity(agent_id="reader_agent", role="reader")


@pytest.fixture
def mailer_agent() -> AgentIdentity:
    return AgentIdentity(agent_id="mailer_agent", role="mailer")


@pytest.fixture
def unknown_agent() -> AgentIdentity:
    return AgentIdentity(agent_id="unknown_agent", role="unknown")


# ── RBAC fixtures ────────────────────────────────────────────────

@pytest.fixture
def rbac_manager() -> RBACManager:
    return RBACManager.from_yaml(FIXTURES_DIR / "agents.yaml")


# ── Resource Registry fixtures ───────────────────────────────────

@pytest.fixture
def resource_registry() -> ResourceRegistry:
    return ResourceRegistry.from_yaml(FIXTURES_DIR / "resources.yaml")


# ── Request factories ───────────────────────────────────────────

@pytest.fixture
def make_request():
    """Factory fixture for creating AuraRequest instances."""
    _counter = 0

    def _make(
        action: ToolAction = ToolAction.READ_FILE,
        params: dict | None = None,
        agent: AgentIdentity | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> AuraRequest:
        nonlocal _counter
        _counter += 1
        return AuraRequest(
            request_id=request_id or f"req-{_counter:04d}",
            action=action,
            params=params or {},
            agent=agent or AgentIdentity(agent_id="test_agent", role="tester"),
            idempotency_key=idempotency_key,
        )

    return _make


@pytest.fixture
def make_context(make_request):
    """Factory fixture for creating RunContext instances."""

    def _make(
        request: AuraRequest | None = None,
        tainted: bool = False,
        taint_source: str | None = None,
        taint_level: ResourceSensitivity | None = None,
        resource_info: ResourceInfo | None = None,
    ) -> RunContext:
        req = request or make_request()
        taint = TaintState(
            tainted=tainted,
            taint_source=taint_source or ("" if not tainted else "test"),
            taint_reason="test taint" if tainted else None,
            taint_level=taint_level,
        )
        return RunContext(
            request=req,
            taint=taint,
            resource_info=resource_info,
        )

    return _make

