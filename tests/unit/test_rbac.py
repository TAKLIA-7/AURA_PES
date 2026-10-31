"""Unit tests for AURA RBAC."""

from __future__ import annotations

import pytest

from aura.models import AgentIdentity, ToolAction
from aura.rbac import RBACManager


class TestRBACManager:
    def test_load_from_yaml(self, rbac_manager):
        agents = rbac_manager.list_agents()
        assert "admin_agent" in agents
        assert "analyst_agent" in agents
        assert "reader_agent" in agents
        assert "mailer_agent" in agents

    def test_admin_wildcard(self, rbac_manager, admin_agent):
        """Admin has wildcard access to everything."""
        assert rbac_manager.check_permission(admin_agent, ToolAction.READ_FILE, "confidential/hr_records")
        assert rbac_manager.check_permission(admin_agent, ToolAction.SEND_EMAIL, "anyone@example.com")
        assert rbac_manager.check_permission(admin_agent, ToolAction.RUN_QUERY, "reports/anything")
        assert rbac_manager.check_permission(admin_agent, ToolAction.CALL_API, "api/anything")

    def test_reader_public_only(self, rbac_manager, reader_agent):
        """Reader can only read public resources."""
        assert rbac_manager.check_permission(reader_agent, ToolAction.READ_FILE, "public/readme")
        assert rbac_manager.check_permission(reader_agent, ToolAction.READ_FILE, "public/faq")
        assert not rbac_manager.check_permission(reader_agent, ToolAction.READ_FILE, "internal/report_q4")
        assert not rbac_manager.check_permission(reader_agent, ToolAction.READ_FILE, "confidential/hr_records")
        assert not rbac_manager.check_permission(reader_agent, ToolAction.SEND_EMAIL, "anyone@example.com")

    def test_analyst_read_internal(self, rbac_manager, analyst_agent):
        """Analyst can read public and internal, but not confidential."""
        assert rbac_manager.check_permission(analyst_agent, ToolAction.READ_FILE, "public/readme")
        assert rbac_manager.check_permission(analyst_agent, ToolAction.READ_FILE, "internal/report_q4")
        assert not rbac_manager.check_permission(analyst_agent, ToolAction.READ_FILE, "confidential/hr_records")

    def test_analyst_query_access(self, rbac_manager, analyst_agent):
        """Analyst can run reports and analytics queries."""
        assert rbac_manager.check_permission(analyst_agent, ToolAction.RUN_QUERY, "reports/monthly_summary")
        assert rbac_manager.check_permission(analyst_agent, ToolAction.RUN_QUERY, "analytics/user_stats")
        assert not rbac_manager.check_permission(analyst_agent, ToolAction.RUN_QUERY, "admin/dangerous_query")

    def test_mailer_permissions(self, rbac_manager, mailer_agent):
        """Mailer can send email (wildcard resource) and read public files."""
        assert rbac_manager.check_permission(mailer_agent, ToolAction.SEND_EMAIL, "anyone@example.com")
        assert rbac_manager.check_permission(mailer_agent, ToolAction.READ_FILE, "public/readme")
        assert not rbac_manager.check_permission(mailer_agent, ToolAction.READ_FILE, "internal/report_q4")
        assert not rbac_manager.check_permission(mailer_agent, ToolAction.RUN_QUERY, "reports/anything")

    def test_unknown_agent_denied(self, rbac_manager, unknown_agent):
        """Unknown agents are denied everything."""
        assert not rbac_manager.check_permission(unknown_agent, ToolAction.READ_FILE, "public/readme")
        assert not rbac_manager.check_permission(unknown_agent, ToolAction.SEND_EMAIL, "anyone@example.com")

    def test_role_mismatch_denied(self, rbac_manager):
        """Agent claims wrong role → denied even if agent_id exists."""
        spoofed = AgentIdentity(agent_id="admin_agent", role="reader")
        assert not rbac_manager.check_permission(spoofed, ToolAction.READ_FILE, "confidential/hr_records")

    def test_get_agent_config(self, rbac_manager):
        config = rbac_manager.get_agent_config("admin_agent")
        assert config is not None
        assert config.role == "admin"

    def test_get_unknown_config(self, rbac_manager):
        config = rbac_manager.get_agent_config("nonexistent")
        assert config is None

    def test_list_permissions(self, rbac_manager):
        perms = rbac_manager.list_permissions("reader_agent")
        assert len(perms) == 1
        assert perms[0].action == "read_file"

    def test_no_resource_permission_check(self, rbac_manager, admin_agent):
        """Permission check without resource_id → allowed if action matches."""
        assert rbac_manager.check_permission(admin_agent, ToolAction.READ_FILE, None)
        assert rbac_manager.check_permission(admin_agent, ToolAction.READ_FILE, "")

    def test_from_dict(self):
        """Build RBACManager from a dict (no YAML file needed)."""
        data = {
            "agents": {
                "test_agent": {
                    "role": "tester",
                    "permissions": [
                        {"action": "read_file", "resources": ["test/*"]},
                    ],
                },
            },
        }
        rbac = RBACManager.from_dict(data)
        agent = AgentIdentity(agent_id="test_agent", role="tester")
        assert rbac.check_permission(agent, ToolAction.READ_FILE, "test/doc")
        assert not rbac.check_permission(agent, ToolAction.READ_FILE, "other/doc")
