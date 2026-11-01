"""Unit tests for the AURA Workflow DAG Engine."""

import pytest
from aura.gateway import AuraGateway
from aura.workflow.engine import WorkflowEngine
from aura.workflow.models import TaskState, WorkflowStatus
from aura.workflow.scenarios import create_customer_refund_workflow


class TestWorkflowEngine:
    """Test suite for WorkflowEngine executing DAGs under AURA."""

    def test_customer_refund_workflow_lifecycle(self, tmp_path):
        """Test full execution of the customer refund scenario including approval pause and resumption."""
        db_path = tmp_path / "test_wf.db"
        gw = AuraGateway.create_default(db_path=db_path)

        events = []

        def on_event(w_id, task, evt):
            events.append((task.task_id, evt, task.state))

        engine = WorkflowEngine(gateway=gw, on_task_event=on_event)

        # 1. Create and register the workflow
        wf = create_customer_refund_workflow(workflow_id="wf-test-101")
        engine.register_workflow(wf)

        assert wf.status == WorkflowStatus.PENDING
        assert len(wf.tasks) == 8

        # 2. Execute until approval pause
        wf = engine.execute_workflow("wf-test-101")

        assert wf.status == WorkflowStatus.PAUSED_FOR_APPROVAL
        assert wf.tasks["task_image_inspect"].state == TaskState.COMPLETED
        assert wf.tasks["task_invoice_extract"].state == TaskState.COMPLETED
        assert wf.tasks["task_audio_transcribe"].state == TaskState.COMPLETED
        assert wf.tasks["task_order_lookup"].state == TaskState.COMPLETED
        assert wf.tasks["task_return_eligibility"].state == TaskState.COMPLETED

        # Refund and replacement must be waiting for human approval
        assert wf.tasks["task_create_refund"].state == TaskState.WAITING_FOR_APPROVAL
        assert wf.tasks["task_create_refund"].approval_id is not None
        assert wf.tasks["task_create_replacement"].state == TaskState.WAITING_FOR_APPROVAL
        assert wf.tasks["task_create_replacement"].approval_id is not None

        # Downstream notification task must still be CREATED (not executed)
        assert wf.tasks["task_notify_customer"].state == TaskState.CREATED

        # 3. Simulate human operator approval and resume
        wf = engine.resume_after_approval("wf-test-101", approver_id="test-operator")

        assert wf.status == WorkflowStatus.COMPLETED
        assert wf.tasks["task_create_refund"].state == TaskState.COMPLETED
        assert wf.tasks["task_create_refund"].result["status"] == "COMPLETED"
        assert wf.tasks["task_create_replacement"].state == TaskState.COMPLETED
        assert wf.tasks["task_create_replacement"].result["status"] == "PROCESSING"
        assert wf.tasks["task_notify_customer"].state == TaskState.COMPLETED
        assert wf.tasks["task_notify_customer"].result["status"] == "DELIVERED"

    def test_missing_image_input_blocks_workflow(self, tmp_path):
        """Verify that a missing input file fails the task and never fabricates output."""
        db_path = tmp_path / "test_wf_missing.db"
        gw = AuraGateway.create_default(db_path=db_path)
        engine = WorkflowEngine(gateway=gw)

        wf = create_customer_refund_workflow(
            workflow_id="wf-missing-img",
            image_id="photo-does-not-exist-5555.jpg",
        )
        engine.register_workflow(wf)

        wf = engine.execute_workflow("wf-missing-img")

        assert wf.status == WorkflowStatus.FAILED
        assert wf.tasks["task_image_inspect"].state in (TaskState.FAILED, TaskState.BLOCKED)
        assert (
            "RESOURCE_NOT_FOUND" in (wf.tasks["task_image_inspect"].error or "")
            or "IMAGE_NOT_FOUND" in (wf.tasks["task_image_inspect"].error or "")
        )
        # Critical security invariant: Dependent refund task was NOT executed
        assert wf.tasks["task_create_refund"].state == TaskState.CREATED
        assert wf.tasks["task_create_refund"].result is None

    def test_declined_approval_blocks_execution(self, tmp_path):
        """Verify that declining human approval blocks execution and marks status REJECTED."""
        db_path = tmp_path / "test_wf_decline.db"
        gw = AuraGateway.create_default(db_path=db_path)
        engine = WorkflowEngine(gateway=gw)

        wf = create_customer_refund_workflow(workflow_id="wf-test-decline")
        engine.register_workflow(wf)
        wf = engine.execute_workflow("wf-test-decline")

        assert wf.status == WorkflowStatus.PAUSED_FOR_APPROVAL
        approval_id = wf.tasks["task_create_refund"].approval_id
        assert approval_id is not None

        # Decline the approval
        wf = engine.decline_approval("wf-test-decline", approval_id=approval_id, reason="Customer provided incomplete claim")

        assert wf.status == WorkflowStatus.FAILED
        assert wf.tasks["task_create_refund"].state == TaskState.BLOCKED
        assert "APPROVAL_DECLINED" in (wf.tasks["task_create_refund"].error or "")
        # Adapter call count must remain 0
        refund_adapter = gw.tool_registry.get(wf.tasks["task_create_refund"].tool_action)
        assert refund_adapter.call_count == 0

    def test_meeting_room_workflow_lifecycle(self, tmp_path):
        """Verify collaborative general-purpose meeting room research and reservation workflow."""
        from aura.workflow.scenarios import create_meeting_room_workflow

        db_path = tmp_path / "test_wf_room.db"
        gw = AuraGateway.create_default(db_path=db_path)
        engine = WorkflowEngine(gateway=gw)

        wf = create_meeting_room_workflow(workflow_id="wf-test-room-01")
        engine.register_workflow(wf)

        # 1. Execute until approval pause
        wf = engine.execute_workflow("wf-test-room-01")
        assert wf.status == WorkflowStatus.PAUSED_FOR_APPROVAL
        assert wf.tasks["task_research_rooms"].state == TaskState.COMPLETED
        assert wf.tasks["task_analyze_and_rank"].state == TaskState.COMPLETED
        assert wf.tasks["task_create_reservation"].state == TaskState.WAITING_FOR_APPROVAL

        # 2. Approve and resume
        wf = engine.resume_after_approval("wf-test-room-01", approver_id="office_manager")
        assert wf.status == WorkflowStatus.COMPLETED
        assert wf.tasks["task_create_reservation"].state == TaskState.COMPLETED
        assert wf.tasks["task_create_reservation"].result["status"] == "CONFIRMED"
        assert wf.tasks["task_send_invites"].state == TaskState.COMPLETED
        assert wf.tasks["task_send_invites"].result["status"] == "DELIVERED"
