"""
AURA Tool Adapters — Private typed tool implementations.

Only AURA holds access to these adapter callables. The AI agent receives
tool *schemas* only (via ``ToolRegistry.get_tool_schemas()``), never direct
references to the adapter objects. This separation enforces the invariant
that every tool call must transit the AURA gateway and satisfy all policy
checks before execution.

Each adapter:
  - Inherits from ``ToolAdapter`` for consistent call-counting and thread safety.
  - Accepts pre-validated, pre-authorized inputs (the gateway is responsible for
    input validation and policy enforcement *before* calling an adapter).
  - Returns a structured ``dict[str, Any]`` result that the gateway can audit,
    digest, and relay to the agent.

Thread Safety
~~~~~~~~~~~~~
All adapters use a ``threading.Lock`` for mutable state (call counters, log
lists). This makes them safe for concurrent gateway invocations.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Optional

from aura.models import ResourceEntry, SQLQueryDef


# ──────────────────────────────────────────────
# Base Adapter
# ──────────────────────────────────────────────


class ToolAdapter:
    """Base class for private typed tool adapters.

    Provides:
      - A human-readable ``name`` identifier.
      - A thread-safe ``call_count`` counter for rate-limiting / telemetry.
      - ``reset_counter`` / ``_increment`` helpers.
    """

    def __init__(self, name: str) -> None:
        self.name: str = name
        self._call_count: int = 0
        self._lock: threading.Lock = threading.Lock()

    @property
    def call_count(self) -> int:
        """Return the number of times this adapter has been executed."""
        return self._call_count

    def reset_counter(self) -> None:
        """Reset the call counter to zero (thread-safe)."""
        with self._lock:
            self._call_count = 0

    def _increment(self) -> None:
        """Atomically increment the call counter."""
        with self._lock:
            self._call_count += 1


# ──────────────────────────────────────────────
# Concrete Adapters
# ──────────────────────────────────────────────


class ReadFileAdapter(ToolAdapter):
    """Read an authorized document by ID.

    Does **NOT** expose arbitrary filesystem paths. Content is served
    exclusively from the trusted :class:`~aura.models.ResourceEntry`
    registry, which binds each document ID to sensitivity metadata.
    """

    def __init__(self) -> None:
        super().__init__("read_file")

    def execute(self, doc_id: str, resource: ResourceEntry) -> dict[str, Any]:
        """Return the content of a registered resource.

        Parameters
        ----------
        doc_id:
            The document identifier (e.g. ``"doc:public_report"``).
        resource:
            The trusted :class:`ResourceEntry` resolved by the gateway.

        Returns
        -------
        dict[str, Any]
            ``{"doc_id", "name", "content", "sensitivity"}``.
        """
        self._increment()
        return {
            "doc_id": doc_id,
            "name": resource.name,
            "content": resource.content or "(empty)",
            "sensitivity": resource.sensitivity.value,
        }


class SendEmailAdapter(ToolAdapter):
    """Send an email (mock).

    Does **NOT** send real emails — the intent is logged in
    :pyattr:`sent_emails` for auditability and testing.
    """

    def __init__(self) -> None:
        super().__init__("send_email")
        self.sent_emails: list[dict[str, Any]] = []

    def execute(self, to: str, subject: str, body: str) -> dict[str, Any]:
        """Record a mock email send.

        Parameters
        ----------
        to:
            Recipient email address (already validated by the gateway).
        subject:
            Email subject line.
        body:
            Email body text.

        Returns
        -------
        dict[str, Any]
            ``{"status": "sent", "to", "subject", "message_id"}``.
        """
        self._increment()
        ts = time.time()
        message_id: str = hashlib.sha256(
            f"{to}{subject}{ts}".encode()
        ).hexdigest()[:16]
        email: dict[str, Any] = {
            "to": to,
            "subject": subject,
            "body": body,
            "timestamp": ts,
            "message_id": message_id,
        }
        with self._lock:
            self.sent_emails.append(email)
        return {
            "status": "sent",
            "to": to,
            "subject": subject,
            "message_id": message_id,
        }


class RunQueryAdapter(ToolAdapter):
    """Execute a named, allowlisted SQL query with parameterized inputs.

    **Never** executes raw SQL supplied by the agent. The gateway resolves
    the ``query_name`` to a trusted :class:`~aura.models.SQLQueryDef` before
    calling this adapter.
    """

    def __init__(self) -> None:
        super().__init__("run_query")
        self.executed_queries: list[dict[str, Any]] = []

    def execute(
        self, query_def: SQLQueryDef, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a mock SQL query and return canned results.

        Parameters
        ----------
        query_def:
            The trusted, allowlisted query definition.
        params:
            Validated query parameters (bound positionally / by name).

        Returns
        -------
        dict[str, Any]
            ``{"query_name", "params", "results", "row_count"}``.

        Notes
        -----
        In production this adapter would hold a read-only database
        connection pool and execute ``query_def.sql`` with parameterised
        bindings. The mock implementation returns deterministic canned
        results keyed on ``query_def.name``.
        """
        self._increment()

        # Deterministic mock results keyed on query name.
        mock_results: dict[str, list[dict[str, Any]]] = {
            "get_user_count": [{"user_count": 1542}],
            "get_revenue_summary": [
                {"quarter": "Q1", "total": 520000},
                {"quarter": "Q2", "total": 610000},
                {"quarter": "Q3", "total": 580000},
            ],
            "get_top_products": [
                {"product_name": "Enterprise Suite", "sales_count": 2341},
                {"product_name": "Cloud Platform", "sales_count": 1876},
            ],
            "insert_audit_note": [{"rows_affected": 1}],
        }

        rows: list[dict[str, Any]] = mock_results.get(query_def.name, [])
        result: dict[str, Any] = {
            "query_name": query_def.name,
            "params": params,
            "results": rows,
            "row_count": len(rows),
        }
        with self._lock:
            self.executed_queries.append(result)
        return result


class CallAPIAdapter(ToolAdapter):
    """Call a registered API operation (mock).

    All API operations are pre-registered in the trusted configuration.
    The gateway validates the operation name before delegating here.
    """

    def __init__(self) -> None:
        super().__init__("call_api")
        self.api_calls: list[dict[str, Any]] = []

    def execute(
        self, operation: str, params: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """Record and execute a mock API call.

        Parameters
        ----------
        operation:
            API operation name (must be an allowed operation).
        params:
            Optional operation parameters.

        Returns
        -------
        dict[str, Any]
            ``{"status": "ok", "operation", "response": {"success": True}}``.
        """
        self._increment()
        call: dict[str, Any] = {
            "operation": operation,
            "params": params or {},
            "timestamp": time.time(),
        }
        with self._lock:
            self.api_calls.append(call)
        return {
            "status": "ok",
            "operation": operation,
            "response": {"success": True},
        }


# ──────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────


class ToolRegistry:
    """Registry of all private tool adapters.

    Only the AURA gateway accesses this registry.  The agent never receives
    adapter references — only JSON schemas (see :meth:`get_tool_schemas`).
    """

    def __init__(self) -> None:
        self.read_file: ReadFileAdapter = ReadFileAdapter()
        self.send_email: SendEmailAdapter = SendEmailAdapter()
        self.run_query: RunQueryAdapter = RunQueryAdapter()
        self.call_api: CallAPIAdapter = CallAPIAdapter()

        self._adapters: dict[str, ToolAdapter] = {
            "read_file": self.read_file,
            "send_email": self.send_email,
            "run_query": self.run_query,
            "call_api": self.call_api,
        }

    def get_adapter(self, tool_name: str) -> Optional[ToolAdapter]:
        """Return the adapter for *tool_name*, or ``None`` if unregistered."""
        return self._adapters.get(tool_name)

    def get_all_call_counts(self) -> dict[str, int]:
        """Return ``{tool_name: call_count}`` for every registered tool."""
        return {
            name: adapter.call_count
            for name, adapter in self._adapters.items()
        }

    def reset_all_counters(self) -> None:
        """Reset every adapter's call counter to zero."""
        for adapter in self._adapters.values():
            adapter.reset_counter()

    # ── Agent-facing schemas (NO adapter references) ───────────

    @staticmethod
    def get_tool_schemas() -> list[dict[str, Any]]:
        """Return tool schemas for the agent.

        These are pure JSON-Schema descriptions of the tools the agent may
        *request*.  They do **not** contain adapter callables, internal
        field names, or any implementation detail.
        """
        return [
            {
                "name": "read_file",
                "description": (
                    "Read an authorized document by its registered ID."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "doc_id": {
                            "type": "string",
                            "description": (
                                "The document resource ID "
                                "(e.g., 'doc:public_report')"
                            ),
                        }
                    },
                    "required": ["doc_id"],
                },
            },
            {
                "name": "send_email",
                "description": (
                    "Send an email to a recipient. "
                    "Subject to policy enforcement."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {
                            "type": "string",
                            "description": "Recipient email address",
                        },
                        "subject": {
                            "type": "string",
                            "description": "Email subject",
                        },
                        "body": {
                            "type": "string",
                            "description": "Email body",
                        },
                    },
                    "required": ["to", "subject", "body"],
                },
            },
            {
                "name": "run_query",
                "description": (
                    "Execute a named, pre-approved SQL query with parameters."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query_name": {
                            "type": "string",
                            "description": (
                                "Name of the allowlisted query "
                                "(e.g., 'get_user_count')"
                            ),
                        },
                        "params": {
                            "type": "object",
                            "description": "Query parameters",
                        },
                    },
                    "required": ["query_name"],
                },
            },
            {
                "name": "call_api",
                "description": "Call a registered API operation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "description": "API operation name",
                        },
                        "params": {
                            "type": "object",
                            "description": "Operation parameters",
                        },
                    },
                    "required": ["operation"],
                },
            },
        ]
