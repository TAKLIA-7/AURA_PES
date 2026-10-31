"""
AURA Resource Registry — Trusted resource lookup, sensitivity classification, and SQL allowlisting.

All resource metadata (sensitivity, allowed roles, SQL definitions) is loaded from
the server-side ``resources.yaml`` at init time.  Agents never supply their own
sensitivity claims — every lookup returns the *trusted* classification.

Key capabilities
----------------
* **Sensitivity lookup**: constant-time access to the trusted ``ResourceSensitivity``
  for any registered resource.
* **Role-based access**: check whether an agent role is permitted for a given resource.
* **SQL allowlisting**: validate named queries and their parameters against a
  pre-defined allowlist, preventing ad-hoc query injection.
"""

from __future__ import annotations

from typing import Any, Optional

from aura.models import ResourceEntry, ResourceSensitivity, SQLQueryDef


class ResourceRegistry:
    """Registry of trusted resources and allowlisted SQL queries.

    Parameters
    ----------
    resources_config:
        The parsed ``resources.yaml`` dict.  Expected top-level keys:

        * ``"resources"`` — list of resource dicts, each matching
          :class:`~aura.models.ResourceEntry`.
        * ``"sql_queries"`` — list of SQL query dicts, each matching
          :class:`~aura.models.SQLQueryDef`.
    """

    def __init__(self, resources_config: dict[str, Any]) -> None:
        if not isinstance(resources_config, dict):
            raise TypeError(
                f"resources_config must be a dict, got {type(resources_config).__name__}"
            )

        # ── Build resource index ─────────────
        self._resources: dict[str, ResourceEntry] = {}
        raw_resources = resources_config.get("resources", {})
        resource_items = raw_resources.values() if isinstance(raw_resources, dict) else raw_resources
        for raw in resource_items:
            entry = ResourceEntry(**raw) if isinstance(raw, dict) else raw
            self._resources[entry.id] = entry

        # ── Build SQL query index ────────────
        self._sql_queries: dict[str, SQLQueryDef] = {}
        raw_queries = resources_config.get("sql_queries", {})
        query_items = raw_queries.values() if isinstance(raw_queries, dict) else raw_queries
        for raw in query_items:
            query = SQLQueryDef(**raw) if isinstance(raw, dict) else raw
            self._sql_queries[query.name] = query

    # ── Resource lookup ─────────────────────────

    def lookup(self, resource_id: str) -> Optional[ResourceEntry]:
        """Look up a resource by its unique ID.

        Returns
        -------
        ResourceEntry | None
            The trusted resource entry, or ``None`` if the resource is not
            registered.
        """
        return self._resources.get(resource_id)

    def get_sensitivity(self, resource_id: str) -> Optional[ResourceSensitivity]:
        """Return the **trusted** sensitivity level for *resource_id*.

        Returns
        -------
        ResourceSensitivity | None
            The sensitivity enum value, or ``None`` if the resource is not
            registered.
        """
        entry = self._resources.get(resource_id)
        if entry is None:
            return None
        return entry.sensitivity

    def is_confidential(self, resource_id: str) -> bool:
        """Return ``True`` if the resource is ``CONFIDENTIAL`` or ``TOP_SECRET``.

        An unregistered resource is *not* considered confidential (returns
        ``False``).  Callers should separately handle the "unknown resource" case.
        """
        sensitivity = self.get_sensitivity(resource_id)
        if sensitivity is None:
            return False
        return sensitivity in (
            ResourceSensitivity.CONFIDENTIAL,
            ResourceSensitivity.TOP_SECRET,
        )

    def check_role_access(self, resource_id: str, agent_role: str) -> bool:
        """Check whether *agent_role* is listed in the resource's ``allowed_roles``.

        Returns
        -------
        bool
            ``True`` if the role is allowed, ``False`` if the resource is not
            found or the role is not in ``allowed_roles``.
        """
        entry = self._resources.get(resource_id)
        if entry is None:
            return False
        return agent_role in entry.allowed_roles

    # ── SQL allowlist ───────────────────────────

    def get_sql_query(self, query_name: str) -> Optional[SQLQueryDef]:
        """Look up an allowlisted SQL query by its unique name.

        Returns
        -------
        SQLQueryDef | None
            The query definition, or ``None`` if not in the allowlist.
        """
        return self._sql_queries.get(query_name)

    def validate_sql_params(
        self, query_name: str, params: dict[str, Any]
    ) -> tuple[bool, str]:
        """Validate *params* against the allowlist definition for *query_name*.

        Checks performed
        ~~~~~~~~~~~~~~~~
        1. Query must exist in the allowlist.
        2. Every supplied param key must be declared in ``allowed_params``.
        3. Every param value must match the declared type (``"str"``, ``"int"``,
           ``"float"``, ``"bool"``).
        4. Required params (those with ``"required": True``) must be present.

        Returns
        -------
        tuple[bool, str]
            ``(True, "")`` on success; ``(False, "<error message>")`` on failure.
        """
        query_def = self._sql_queries.get(query_name)
        if query_def is None:
            return False, f"SQL query '{query_name}' is not in the allowlist"

        allowed = query_def.allowed_params

        # Check for unexpected parameters -----------------------------------
        unexpected = set(params.keys()) - set(allowed.keys())
        if unexpected:
            return False, f"Unexpected parameters: {sorted(unexpected)}"

        # Validate each declared parameter ----------------------------------
        for param_name, param_spec in allowed.items():
            value = params.get(param_name)

            # Required check
            is_required = param_spec.get("required", False)
            if is_required and value is None and param_name not in params:
                return False, f"Required parameter '{param_name}' is missing"

            # Type check (only when value is supplied)
            if value is not None:
                expected_type_str = param_spec.get("type", "str")
                if not self._type_matches(value, expected_type_str):
                    return (
                        False,
                        f"Parameter '{param_name}' expected type '{expected_type_str}', "
                        f"got '{type(value).__name__}'",
                    )

        return True, ""

    # ── Private helpers ─────────────────────────

    @staticmethod
    def _type_matches(value: Any, expected_type: str) -> bool:
        """Check that *value* matches the expected type string.

        Supported type strings: ``"str"``, ``"int"``, ``"float"``, ``"bool"``.
        """
        type_map: dict[str, type] = {
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
        }
        expected = type_map.get(expected_type)
        if expected is None:
            # Unknown type spec — treat as valid (lenient forward-compat)
            return True
        # Special case: bools are ints in Python, but we want strict checking
        if expected is int and isinstance(value, bool):
            return False
        return isinstance(value, expected)
