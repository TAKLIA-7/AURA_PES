"""AURA Role-Based Access Control (RBAC).

RBAC applies to AI agents.  Each agent has a trusted identity, assigned
role, and explicit tool/resource permissions.

Deny-by-default: if no permission entry matches, access is denied.
Wildcard ``"*"`` matches any action or resource.
Resource patterns support trailing glob: ``"public/*"`` matches
``"public/readme"``, ``"public/faq"``, etc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from aura.models import AgentIdentity, ToolAction


@dataclass(frozen=True)
class PermissionEntry:
    """A single permission grant: action + resource patterns."""
    action: str  # ToolAction value or "*"
    resources: list[str] = field(default_factory=list)  # glob patterns


@dataclass(frozen=True)
class AgentConfig:
    """RBAC configuration for a single agent."""
    agent_id: str
    role: str
    description: str = ""
    permissions: list[PermissionEntry] = field(default_factory=list)


class RBACManager:
    """Manages agent RBAC from a YAML configuration.

    Usage::

        rbac = RBACManager.from_yaml("config/agents.yaml")
        allowed = rbac.check_permission(agent, ToolAction.READ_FILE, "public/readme")
    """

    def __init__(self, agents: dict[str, AgentConfig]) -> None:
        self._agents = agents

    # ── Factory ──────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> RBACManager:
        """Load RBAC configuration from a YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RBACManager:
        """Build an RBACManager from a parsed YAML dict."""
        agents: dict[str, AgentConfig] = {}
        for agent_id, agent_data in data.get("agents", {}).items():
            permissions = []
            for perm in agent_data.get("permissions", []):
                permissions.append(
                    PermissionEntry(
                        action=perm["action"],
                        resources=perm.get("resources", []),
                    )
                )
            agents[agent_id] = AgentConfig(
                agent_id=agent_id,
                role=agent_data.get("role", ""),
                description=agent_data.get("description", ""),
                permissions=permissions,
            )
        return cls(agents)

    # ── Queries ──────────────────────────────────────────────────

    def get_agent_config(self, agent_id: str) -> AgentConfig | None:
        """Look up the configuration for a given agent ID."""
        return self._agents.get(agent_id)

    def check_permission(
        self,
        agent: AgentIdentity,
        action: ToolAction,
        resource_id: str | None = None,
    ) -> bool:
        """Check whether *agent* is permitted to perform *action* on *resource_id*.

        Returns ``True`` only if an explicit permission entry matches.
        Deny-by-default: unknown agents or unmatched actions are denied.
        """
        config = self._agents.get(agent.agent_id)
        if config is None:
            return False

        # Ensure the agent's claimed role matches config.
        if config.role != agent.role:
            return False

        action_value = action.value if isinstance(action, ToolAction) else str(action)

        for perm in config.permissions:
            # Check action match.
            if perm.action != "*" and perm.action != action_value:
                continue

            # Check resource match.
            if resource_id is None or resource_id == "":
                # No resource to check — action-level permission suffices.
                return True

            for pattern in perm.resources:
                if pattern == "*" or fnmatch(resource_id, pattern):
                    return True

        return False

    def list_agents(self) -> list[str]:
        """Return all configured agent IDs."""
        return list(self._agents.keys())

    def list_permissions(self, agent_id: str) -> list[PermissionEntry]:
        """Return the permission entries for a given agent."""
        config = self._agents.get(agent_id)
        if config is None:
            return []
        return list(config.permissions)

