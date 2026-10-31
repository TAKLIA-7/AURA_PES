"""AURA Tool Adapters, Schema Declarations, and Controlled SQL Engine.

Exposes only narrow, typed adapters:
  - read_file(doc_id)
  - send_email(to, body)
  - run_query(query_name, params)
  - call_api(op)

Security Invariants:
  - Agents receive schemas only, never adapter callables or credentials.
  - No raw shell, raw SQL, arbitrary filesystem paths, or arbitrary URLs.
  - Path traversal attempts (../, etc.) are strictly rejected.
  - SQL execution uses named allowlisted queries, parameterized SQL, and typed validation.
  - For any blocked or failed action, adapter call counters remain zero.
"""

from __future__ import annotations

import re
import sqlite3
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field, field_validator

from aura.models import ToolAction


# ── Parameter Schemas ───────────────────────────────────────────────

class ReadFileParams(BaseModel):
    """Parameters for reading a registered document."""
    doc_id: str = Field(..., min_length=1, description="Registered document ID (e.g. public/readme)")

    @field_validator("doc_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        # Strictly reject path traversal or arbitrary filesystem paths
        if ".." in v or v.startswith("/") or v.startswith("\\") or ":" in v:
            raise ValueError("Invalid document ID: path traversal and absolute paths are forbidden")
        return v


class SendEmailParams(BaseModel):
    """Parameters for sending an email message."""
    to: str = Field(..., min_length=3, description="Recipient email address")
    body: str = Field(..., max_length=10000, description="Email body content")

    @field_validator("to")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        # Basic email format check
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v.strip()


class RunQueryParams(BaseModel):
    """Parameters for executing a named allowlisted database query."""
    query_name: str = Field(..., min_length=1, description="Name of allowlisted query")
    params: dict[str, Any] = Field(default_factory=dict, description="Named parameters for the query")

    @field_validator("query_name")
    @classmethod
    def _validate_not_raw_sql(cls, v: str) -> str:
        # Reject attempts to pass raw SQL strings
        upper = v.upper()
        for forbidden in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "UNION ", ";", "--"):
            if forbidden in upper:
                raise ValueError("Raw SQL execution is prohibited. Provide an allowlisted query name.")
        return v


class CallApiParams(BaseModel):
    """Parameters for invoking a named allowlisted API operation."""
    op: str = Field(..., min_length=1, description="Allowlisted operation identifier")

    @field_validator("op")
    @classmethod
    def _validate_safe_op(cls, v: str) -> str:
        # Reject arbitrary URLs
        if v.startswith("http://") or v.startswith("https://") or "://" in v:
            raise ValueError("Arbitrary URLs are prohibited. Provide an allowlisted operation identifier.")
        return v


# ── Controlled SQL Engine ──────────────────────────────────────────

class AllowlistedQuery(BaseModel):
    """Definition of an allowlisted parameterized query."""
    name: str
    sql: str
    required_params: list[str] = Field(default_factory=list)
    description: str = ""


class QueryEngine:
    """Manages allowlisted parameterized queries executed against SQLite."""

    DEFAULT_QUERIES: dict[str, AllowlistedQuery] = {
        "reports/monthly_summary": AllowlistedQuery(
            name="reports/monthly_summary",
            sql="SELECT month, revenue, expenses FROM monthly_reports WHERE year = :year ORDER BY month ASC;",
            required_params=["year"],
            description="Retrieve monthly financial summary for a given year",
        ),
        "analytics/user_stats": AllowlistedQuery(
            name="analytics/user_stats",
            sql="SELECT user_id, active_days, tier FROM user_metrics WHERE tier = :tier LIMIT :limit;",
            required_params=["tier", "limit"],
            description="Retrieve user metrics filtered by tier with limit",
        ),
    }

    def __init__(
        self,
        db_conn: sqlite3.Connection | None = None,
        queries: dict[str, AllowlistedQuery] | None = None,
    ) -> None:
        self.queries = queries or dict(self.DEFAULT_QUERIES)
        self.conn = db_conn or self._create_seed_database()

    def _create_seed_database(self) -> sqlite3.Connection:
        """Create an in-memory sample database with seed data."""
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute(
                """
                CREATE TABLE monthly_reports (
                    year INTEGER, month INTEGER, revenue REAL, expenses REAL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE user_metrics (
                    user_id TEXT, active_days INTEGER, tier TEXT
                );
                """
            )
            # Seed rows
            conn.execute("INSERT INTO monthly_reports VALUES (2026, 1, 100000.0, 60000.0);")
            conn.execute("INSERT INTO monthly_reports VALUES (2026, 2, 115000.0, 65000.0);")
            conn.execute("INSERT INTO user_metrics VALUES ('usr-001', 25, 'gold');")
            conn.execute("INSERT INTO user_metrics VALUES ('usr-002', 12, 'silver');")
            conn.execute("INSERT INTO user_metrics VALUES ('usr-003', 28, 'gold');")
        return conn

    def execute_query(self, query_name: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Safely execute an allowlisted query with parameter binding."""
        query_def = self.queries.get(query_name)
        if query_def is None:
            raise ValueError(f"QUERY_NOT_ALLOWLISTED: '{query_name}' is not an authorized query")

        # Validate all required parameters are present
        for required in query_def.required_params:
            if required not in params:
                raise ValueError(f"MISSING_PARAMETER: query '{query_name}' requires parameter '{required}'")

        # Safe parameterized execution: parameters are passed as bindings, NEVER formatted into SQL!
        cur = self.conn.cursor()
        cur.execute(query_def.sql, params)
        rows = cur.fetchall()
        return [dict(row) for row in rows]


# ── Tool Adapters ──────────────────────────────────────────────────

class BaseToolAdapter(ABC):
    """Abstract base class for all AURA tool adapters."""

    def __init__(self, action: ToolAction) -> None:
        self.action = action
        self.call_count = 0

    @abstractmethod
    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute the protected tool action with validated parameters."""
        ...

    def reset_counter(self) -> None:
        self.call_count = 0


class ReadFileAdapter(BaseToolAdapter):
    """Narrow adapter for reading registered documents safely."""

    def __init__(self, storage: dict[str, str] | None = None) -> None:
        super().__init__(ToolAction.READ_FILE)
        self.storage = storage or {
            "public/readme": "# AURA Project\nWelcome to AURA enforcement gateway.",
            "public/faq": "Q: What is AURA?\nA: Security layer for AI agents.",
            "internal/report_q4": "Q4 Financials: Revenue up 15%. Internal only.",
            "internal/roadmap": "2027 Roadmap: Expand JEV capabilities.",
            "confidential/hr_records": "CONFIDENTIAL HR RECORDS: Employee salaries and PII.",
            "confidential/financial_data": "RESTRICTED BANKING DETAILS: Account 987654321.",
        }

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        validated = ReadFileParams.model_validate(params)
        self.call_count += 1
        content = self.storage.get(validated.doc_id, f"[Content for {validated.doc_id}]")
        return {"doc_id": validated.doc_id, "content": content}


class SendEmailAdapter(BaseToolAdapter):
    """Narrow adapter for sending emails safely."""

    def __init__(self) -> None:
        super().__init__(ToolAction.SEND_EMAIL)
        self.sent_messages: list[dict[str, str]] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        validated = SendEmailParams.model_validate(params)
        self.call_count += 1
        record = {"to": validated.to, "body": validated.body}
        self.sent_messages.append(record)
        return {"status": "sent", "recipient": validated.to}


class RunQueryAdapter(BaseToolAdapter):
    """Narrow adapter for allowlisted parameterized SQL queries."""

    def __init__(self, engine: QueryEngine | None = None) -> None:
        super().__init__(ToolAction.RUN_QUERY)
        self.engine = engine or QueryEngine()

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        validated = RunQueryParams.model_validate(params)
        # Validate query before incrementing counter
        query_def = self.engine.queries.get(validated.query_name)
        if query_def is None:
            raise ValueError(f"QUERY_NOT_ALLOWLISTED: '{validated.query_name}' is not an authorized query")
        for required in query_def.required_params:
            if required not in validated.params:
                raise ValueError(f"MISSING_PARAMETER: query '{validated.query_name}' requires parameter '{required}'")

        self.call_count += 1
        rows = self.engine.execute_query(validated.query_name, validated.params)
        return {
            "query_name": validated.query_name,
            "rows": rows,
            "row_count": len(rows),
        }


class CallApiAdapter(BaseToolAdapter):
    """Narrow adapter for allowlisted API operations."""

    def __init__(self, allowlisted_ops: set[str] | None = None) -> None:
        super().__init__(ToolAction.CALL_API)
        self.allowlisted_ops = allowlisted_ops or {
            "api/public_status",
            "api/internal_deploy",
        }
        self.called_ops: list[str] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        validated = CallApiParams.model_validate(params)
        if validated.op not in self.allowlisted_ops:
            raise ValueError(f"UNAUTHORIZED_API_OP: '{validated.op}' is not in the allowlist")

        self.call_count += 1
        self.called_ops.append(validated.op)
        return {"op": validated.op, "status": "executed"}


# ── Tool Registry & Schemas ──────────────────────────────────────────

class ToolRegistry:
    """Registry managing tool adapters, function calling schemas, and call counters."""

    def __init__(self, adapters: dict[ToolAction, BaseToolAdapter] | None = None) -> None:
        self._adapters: dict[ToolAction, BaseToolAdapter] = adapters or {}

    @classmethod
    def create_default(cls) -> ToolRegistry:
        """Instantiate default set of typed tool adapters."""
        return cls({
            ToolAction.READ_FILE: ReadFileAdapter(),
            ToolAction.SEND_EMAIL: SendEmailAdapter(),
            ToolAction.RUN_QUERY: RunQueryAdapter(),
            ToolAction.CALL_API: CallApiAdapter(),
        })

    def register(self, action: ToolAction, adapter: BaseToolAdapter) -> None:
        self._adapters[action] = adapter

    def get(self, action: ToolAction) -> BaseToolAdapter | None:
        return self._adapters.get(action)

    def total_calls(self) -> int:
        return sum(adapter.call_count for adapter in self._adapters.values())

    def reset_all_counters(self) -> None:
        for adapter in self._adapters.values():
            adapter.reset_counter()

    def get_schemas(self) -> list[dict[str, Any]]:
        """Return function calling schemas for the LLM agent.

        Invariants:
          - Only JSON schemas are exposed, NEVER adapter callables or credentials!
        """
        return [
            {
                "name": ToolAction.READ_FILE.value,
                "description": "Read an authorized document from the registry by its registered ID.",
                "parameters": ReadFileParams.model_json_schema(),
            },
            {
                "name": ToolAction.SEND_EMAIL.value,
                "description": "Send an email message to a specified recipient address.",
                "parameters": SendEmailParams.model_json_schema(),
            },
            {
                "name": ToolAction.RUN_QUERY.value,
                "description": "Execute a named allowlisted parameterized database query.",
                "parameters": RunQueryParams.model_json_schema(),
            },
            {
                "name": ToolAction.CALL_API.value,
                "description": "Execute an authorized internal or public API operation.",
                "parameters": CallApiParams.model_json_schema(),
            },
        ]
