"""Tests for Repeatable Security Demos A through I."""

import pytest
from aura.demos import SecurityDemos
from aura.gateway import AuraGateway


class TestSecurityDemos:
    """Verifies all hackathon security demos A through I."""

    @pytest.fixture
    def demos(self, tmp_path):
        db_path = tmp_path / "test_demos.db"
        gw = AuraGateway.create_default(db_path=db_path)
        return SecurityDemos(gw=gw)

    def test_demo_a_authorized_execution(self, demos):
        res = demos.run_demo_a()
        assert res.passed, f"Demo A failed: {res.logs}"

    def test_demo_b_unauthorized_blocked(self, demos):
        res = demos.run_demo_b()
        assert res.passed, f"Demo B failed: {res.logs}"

    def test_demo_c_idempotent_retry(self, demos):
        res = demos.run_demo_c()
        assert res.passed, f"Demo C failed: {res.logs}"

    def test_demo_d_idempotency_conflict(self, demos):
        res = demos.run_demo_d()
        assert res.passed, f"Demo D failed: {res.logs}"

    def test_demo_e_approval_lifecycle(self, demos):
        res = demos.run_demo_e()
        assert res.passed, f"Demo E failed: {res.logs}"

    def test_demo_f_prompt_injection(self, demos):
        res = demos.run_demo_f()
        assert res.passed, f"Demo F failed: {res.logs}"

    def test_demo_g_jev_timeout(self, demos):
        res = demos.run_demo_g()
        assert res.passed, f"Demo G failed: {res.logs}"

    def test_demo_h_ambiguity_reconciliation(self, demos):
        res = demos.run_demo_h()
        assert res.passed, f"Demo H failed: {res.logs}"

    def test_demo_i_full_multi_agent_workflow(self, demos):
        res = demos.run_demo_i()
        assert res.passed, f"Demo I failed: {res.logs}"

