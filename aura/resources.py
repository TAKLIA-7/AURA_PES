"""AURA Resource Registry.

Trusted source for resource existence and sensitivity classification.
Only resources listed in the registry are considered valid targets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aura.models import ResourceInfo, ResourceSensitivity


class ResourceRegistry:
    """In-memory resource registry loaded from YAML.

    Usage::

        registry = ResourceRegistry.from_yaml("config/resources.yaml")
        info = registry.lookup("public/readme")
    """

    def __init__(self, resources: dict[str, ResourceInfo]) -> None:
        self._resources = resources

    @classmethod
    def from_yaml(cls, path: str | Path) -> ResourceRegistry:
        """Load resource definitions from a YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceRegistry:
        """Build a ResourceRegistry from a parsed YAML dict."""
        resources: dict[str, ResourceInfo] = {}
        for res_id, res_data in data.get("resources", {}).items():
            resources[res_id] = ResourceInfo(
                resource_id=res_id,
                sensitivity=ResourceSensitivity(res_data["sensitivity"]),
                resource_type=res_data.get("resource_type", "file"),
                exists=True,
                description=res_data.get("description", ""),
                metadata=res_data.get("metadata", {}),
            )
        return cls(resources)

    def lookup(self, resource_id: str) -> ResourceInfo | None:
        """Look up a resource by ID.  Returns ``None`` if not registered."""
        return self._resources.get(resource_id)

    def list_resources(self) -> list[str]:
        """Return all registered resource IDs."""
        return list(self._resources.keys())

    def get_sensitivity(self, resource_id: str) -> ResourceSensitivity | None:
        """Return the sensitivity level for a resource, or ``None``."""
        info = self._resources.get(resource_id)
        return info.sensitivity if info else None
