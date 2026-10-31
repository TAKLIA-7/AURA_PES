"""Unit tests for AURA Tools, Controlled SQL Engine, and Parameter Validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aura.models import ToolAction
from aura.tools import (
    CallApiAdapter,
    CallApiParams,
    QueryEngine,
    ReadFileAdapter,
    ReadFileParams,
    RunQueryAdapter,
    RunQueryParams,
    SendEmailAdapter,
    SendEmailParams,
    ToolRegistry,
)


# ────────────────────────────────────────────────────────────────────
# ReadFileAdapter Tests
# ────────────────────────────────────────────────────────────────────

class TestReadFileAdapter:
    def test_valid_read(self):
        adapter = ReadFileAdapter()
        res = adapter.execute({"doc_id": "public/readme"})
        assert "AURA Project" in res["content"]
        assert adapter.call_count == 1

    def test_path_traversal_rejected(self):
        adapter = ReadFileAdapter()
        with pytest.raises(ValidationError):
            adapter.execute({"doc_id": "../../../etc/passwd"})
        # Invariant: counter remains zero on rejected call!
        assert adapter.call_count == 0

    def test_absolute_path_rejected(self):
        adapter = ReadFileAdapter()
        with pytest.raises(ValidationError):
            adapter.execute({"doc_id": "/var/log/secret"})
        with pytest.raises(ValidationError):
            adapter.execute({"doc_id": "C:\\Windows\\System32"})
        assert adapter.call_count == 0


# ────────────────────────────────────────────────────────────────────
# SendEmailAdapter Tests
# ────────────────────────────────────────────────────────────────────

class TestSendEmailAdapter:
    def test_valid_send(self):
        adapter = SendEmailAdapter()
        res = adapter.execute({"to": "test@example.com", "body": "Hello World"})
        assert res["status"] == "sent"
        assert adapter.call_count == 1
        assert len(adapter.sent_messages) == 1

    def test_invalid_email_format_rejected(self):
        adapter = SendEmailAdapter()
        with pytest.raises(ValidationError):
            adapter.execute({"to": "invalid_email_no_at", "body": "Hello"})
        assert adapter.call_count == 0


# ────────────────────────────────────────────────────────────────────
# Controlled SQL / RunQueryAdapter Tests
# ────────────────────────────────────────────────────────────────────

class TestRunQueryAdapter:
    def test_allowlisted_query_executes(self):
        adapter = RunQueryAdapter()
        res = adapter.execute({
            "query_name": "reports/monthly_summary",
            "params": {"year": 2026},
        })
        assert res["query_name"] == "reports/monthly_summary"
        assert res["row_count"] == 2
        assert adapter.call_count == 1

    def test_sql_injection_in_parameter_neutralized(self):
        """SQL injection in parameter value is neutralized by parameter binding."""
        adapter = RunQueryAdapter()
        # Malicious attempt to inject OR '1'='1'
        malicious_input = "gold' OR '1'='1"
        res = adapter.execute({
            "query_name": "analytics/user_stats",
            "params": {"tier": malicious_input, "limit": 10},
        })
        # Binding treats the string literally; matches 0 records, doesn't dump all users!
        assert res["row_count"] == 0
        assert adapter.call_count == 1

    def test_raw_sql_in_query_name_rejected(self):
        """Attempts to supply raw SQL instead of a query name are rejected."""
        adapter = RunQueryAdapter()
        with pytest.raises(ValidationError):
            adapter.execute({"query_name": "SELECT * FROM user_metrics;"})
        with pytest.raises(ValidationError):
            adapter.execute({"query_name": "DROP TABLE monthly_reports;"})
        with pytest.raises(ValidationError):
            adapter.execute({"query_name": "query -- SQL injection comment"})
        assert adapter.call_count == 0

    def test_unallowlisted_query_name_fails(self):
        adapter = RunQueryAdapter()
        with pytest.raises(ValueError, match="QUERY_NOT_ALLOWLISTED"):
            adapter.execute({"query_name": "unauthorized/delete_all", "params": {}})
        assert adapter.call_count == 0

    def test_missing_required_param_fails(self):
        adapter = RunQueryAdapter()
        with pytest.raises(ValueError, match="MISSING_PARAMETER"):
            # Missing "year" parameter for reports/monthly_summary
            adapter.execute({"query_name": "reports/monthly_summary", "params": {}})
        assert adapter.call_count == 0


# ────────────────────────────────────────────────────────────────────
# CallApiAdapter Tests
# ────────────────────────────────────────────────────────────────────

class TestCallApiAdapter:
    def test_allowlisted_op_executes(self):
        adapter = CallApiAdapter()
        res = adapter.execute({"op": "api/public_status"})
        assert res["status"] == "executed"
        assert adapter.call_count == 1

    def test_arbitrary_url_rejected(self):
        adapter = CallApiAdapter()
        with pytest.raises(ValidationError):
            adapter.execute({"op": "https://attacker.evil.com/steal"})
        assert adapter.call_count == 0

    def test_unregistered_op_rejected(self):
        adapter = CallApiAdapter()
        with pytest.raises(ValueError, match="UNAUTHORIZED_API_OP"):
            adapter.execute({"op": "api/nonexistent_op"})
        assert adapter.call_count == 0


# ────────────────────────────────────────────────────────────────────
# ToolRegistry & Function Schemas Tests
# ────────────────────────────────────────────────────────────────────

class TestToolRegistry:
    def test_get_schemas_contains_all_tools(self):
        registry = ToolRegistry.create_default()
        schemas = registry.get_schemas()

        tool_names = {s["name"] for s in schemas}
        assert ToolAction.READ_FILE.value in tool_names
        assert ToolAction.SEND_EMAIL.value in tool_names
        assert ToolAction.RUN_QUERY.value in tool_names
        assert ToolAction.CALL_API.value in tool_names

        # Verify schemas are JSON schemas without executable references
        for s in schemas:
            assert "parameters" in s
            assert "properties" in s["parameters"]
            assert callable(s) is False

    def test_reset_all_counters(self):
        registry = ToolRegistry.create_default()
        registry.get(ToolAction.READ_FILE).call_count = 5
        registry.get(ToolAction.SEND_EMAIL).call_count = 3
        assert registry.total_calls() == 8

        registry.reset_all_counters()
        assert registry.total_calls() == 0

