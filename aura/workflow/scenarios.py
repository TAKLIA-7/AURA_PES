"""Pre-built Multi-Agent Workflow Scenarios for Hackathon Evaluation."""

from __future__ import annotations

import uuid
from aura.models import ToolAction
from aura.workflow.models import WorkflowInstance, WorkflowTask


def create_customer_refund_workflow(
    workflow_id: str | None = None,
    image_id: str = "photo-5521.jpg",
    doc_id: str = "invoice-8834.pdf",
    audio_id: str = "voice-2210.mp3",
) -> WorkflowInstance:
    """Create the Primary Demonstration Scenario DAG:

    'My blender arrived broken. Here's a photo (photo-5521.jpg), my invoice
    (invoice-8834.pdf), and I recorded a message (voice-2210.mp3). I want a
    refund and a replacement.'
    """
    wf_id = workflow_id or f"wf-{uuid.uuid4().hex[:8]}"

    wf = WorkflowInstance(
        workflow_id=wf_id,
        name="Customer Refund and Replacement Multi-Agent Workflow",
        description="End-to-end multi-modal case resolution: damage inspection, invoice extraction, audio transcription, order verification, financial refund, and replacement fulfillment under AURA security enforcement.",
        metadata={
            "customer_claim": "Broken blender arrived; requesting refund and replacement",
            "image_id": image_id,
            "doc_id": doc_id,
            "audio_id": audio_id,
        },
    )

    # 1. Independent specialist tasks (can run concurrently)
    t_image = WorkflowTask(
        task_id="task_image_inspect",
        workflow_id=wf_id,
        name="Inspect Product Photo for Damage",
        assigned_agent_id="image_agent",
        assigned_agent_role="image_inspector",
        tool_action=ToolAction.ANALYZE_DAMAGE,
        tool_params={"image_id": image_id},
        depends_on=[],
        idempotency_key=f"idem-img-{wf_id}",
    )

    t_invoice = WorkflowTask(
        task_id="task_invoice_extract",
        workflow_id=wf_id,
        name="Extract Invoice PDF Details",
        assigned_agent_id="invoice_agent",
        assigned_agent_role="invoice_processor",
        tool_action=ToolAction.EXTRACT_INVOICE_DETAILS,
        tool_params={"doc_id": doc_id},
        depends_on=[],
        idempotency_key=f"idem-inv-{wf_id}",
    )

    t_audio = WorkflowTask(
        task_id="task_audio_transcribe",
        workflow_id=wf_id,
        name="Transcribe Customer Audio Message",
        assigned_agent_id="audio_agent",
        assigned_agent_role="audio_processor",
        tool_action=ToolAction.TRANSPARENT_AUDIO if hasattr(ToolAction, "TRANSPARENT_AUDIO") else ToolAction.TRANSCRIBE_CUSTOMER_AUDIO,
        tool_params={"audio_id": audio_id},
        depends_on=[],
        idempotency_key=f"idem-aud-{wf_id}",
    )

    # 2. Order verification steps (dependent on invoice extraction)
    t_order = WorkflowTask(
        task_id="task_order_lookup",
        workflow_id=wf_id,
        name="Verify Order in Database",
        assigned_agent_id="order_agent",
        assigned_agent_role="order_verifier",
        tool_action=ToolAction.LOOKUP_ORDER,
        tool_params={},
        param_bindings={"order_id": "task_invoice_extract.order_id"},
        depends_on=["task_invoice_extract"],
        idempotency_key=f"idem-ord-{wf_id}",
    )

    t_eligibility = WorkflowTask(
        task_id="task_return_eligibility",
        workflow_id=wf_id,
        name="Check Return and Replacement Eligibility",
        assigned_agent_id="order_agent",
        assigned_agent_role="order_verifier",
        tool_action=ToolAction.CHECK_RETURN_ELIGIBILITY,
        tool_params={},
        param_bindings={"order_id": "task_invoice_extract.order_id"},
        depends_on=["task_order_lookup"],
        idempotency_key=f"idem-elg-{wf_id}",
    )

    # 3. Sensitive financial and fulfillment actions (require human approval)
    t_refund = WorkflowTask(
        task_id="task_create_refund",
        workflow_id=wf_id,
        name="Authorize and Create Financial Refund",
        assigned_agent_id="resolution_agent",
        assigned_agent_role="resolution_specialist",
        tool_action=ToolAction.CREATE_REFUND,
        tool_params={},
        param_bindings={
            "order_id": "task_invoice_extract.order_id",
            "amount": "task_invoice_extract.total_amount",
        },
        depends_on=["task_image_inspect", "task_audio_transcribe", "task_return_eligibility"],
        idempotency_key=f"idem-ref-{wf_id}",
    )

    t_replacement = WorkflowTask(
        task_id="task_create_replacement",
        workflow_id=wf_id,
        name="Authorize and Create Product Replacement Order",
        assigned_agent_id="fulfillment_agent",
        assigned_agent_role="fulfillment_specialist",
        tool_action=ToolAction.CREATE_REPLACEMENT,
        tool_params={},
        param_bindings={
            "order_id": "task_invoice_extract.order_id",
            "product_id": "task_order_lookup.product_id",
        },
        depends_on=["task_image_inspect", "task_audio_transcribe", "task_return_eligibility"],
        idempotency_key=f"idem-rep-{wf_id}",
    )

    # 4. Outbound customer notification (runs after refund and replacement succeed)
    t_notify = WorkflowTask(
        task_id="task_notify_customer",
        workflow_id=wf_id,
        name="Send Confirmation to Customer",
        assigned_agent_id="resolution_agent",
        assigned_agent_role="resolution_specialist",
        tool_action=ToolAction.SEND_CUSTOMER_UPDATE,
        tool_params={
            "email": "sarah.connor@example.com",
            "message": "Good news! Your refund of $129.99 has been approved, and a brand new replacement blender (PROD-BLENDER-7) has been dispatched.",
        },
        depends_on=["task_create_refund", "task_create_replacement"],
        idempotency_key=f"idem-not-{wf_id}",
    )

    wf.add_task(t_image)
    wf.add_task(t_invoice)
    wf.add_task(t_audio)
    wf.add_task(t_order)
    wf.add_task(t_eligibility)
    wf.add_task(t_refund)
    wf.add_task(t_replacement)
    wf.add_task(t_notify)

    return wf


def create_meeting_room_workflow(
    workflow_id: str | None = None,
    location: str = "office",
    capacity: int = 4,
    date: str = "2026-11-02",
    duration_hours: int = 2,
    max_budget: float = 100.0,
    attendees: list[str] | None = None,
) -> WorkflowInstance:
    """Create the General-Purpose Meeting Room Research & Reservation DAG:

    'I need a meeting room for four people tomorrow afternoon for two hours.
    Find suitable options near my office, compare availability and prices,
    choose the best option under my budget of $100, prepare the reservation,
    and send an invitation to the attendees.'
    """
    wf_id = workflow_id or f"wf-room-{uuid.uuid4().hex[:8]}"
    attendee_list = attendees or [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
        "dana@example.com",
    ]

    wf = WorkflowInstance(
        workflow_id=wf_id,
        name="Meeting Room Research & Reservation Multi-Agent Workflow",
        description="Collaborative 4-agent workflow: research room inventory, analyze budget and schedule constraints, request human approval for reservation, book room, and dispatch calendar invites.",
        metadata={
            "user_request": "Book a meeting room for 4 people tomorrow afternoon for 2 hours under $100 budget and invite attendees.",
            "location": location,
            "capacity": capacity,
            "date": date,
            "duration_hours": duration_hours,
            "max_budget": max_budget,
            "attendees": attendee_list,
        },
    )

    # 1. Research Agent: queries available rooms
    t_research = WorkflowTask(
        task_id="task_research_rooms",
        workflow_id=wf_id,
        name="Research Meeting Room Options Near Office",
        assigned_agent_id="researcher_agent",
        assigned_agent_role="researcher",
        tool_action=ToolAction.SEARCH_MEETING_ROOMS,
        tool_params={"location": location, "capacity": capacity, "date": date},
        depends_on=[],
        idempotency_key=f"idem-rsh-{wf_id}",
    )

    # 2. Analyst Agent: compares availability, pricing, and budget constraints
    t_analyze = WorkflowTask(
        task_id="task_analyze_and_rank",
        workflow_id=wf_id,
        name="Analyze Constraints, Pricing & Rank Best Option",
        assigned_agent_id="analyst_agent",
        assigned_agent_role="analyst",
        tool_action=ToolAction.READ_FILE,
        tool_params={"doc_id": "internal/roadmap"},
        depends_on=["task_research_rooms"],
        idempotency_key=f"idem-anl-{wf_id}",
    )

    # 3. Execution Agent: Prepares and requests reservation (GATED ON HUMAN APPROVAL)
    t_reserve = WorkflowTask(
        task_id="task_create_reservation",
        workflow_id=wf_id,
        name="Authorize and Book Meeting Room Reservation",
        assigned_agent_id="executor_agent",
        assigned_agent_role="executor",
        tool_action=ToolAction.CREATE_RESERVATION,
        tool_params={
            "room_id": "rooms/maple",
            "room_name": "Maple Conference Room",
            "date": date,
            "start_time": "14:00",
            "duration_hours": duration_hours,
            "attendees": capacity,
            "total_price": 80.0,
        },
        depends_on=["task_analyze_and_rank"],
        idempotency_key=f"idem-rsv-{wf_id}",
    )

    # 4. Execution Agent: Dispatches calendar invitations to attendees
    t_invite = WorkflowTask(
        task_id="task_send_invites",
        workflow_id=wf_id,
        name="Send Calendar Invites to Attendees",
        assigned_agent_id="executor_agent",
        assigned_agent_role="executor",
        tool_action=ToolAction.SEND_MEETING_INVITE,
        tool_params={
            "to_emails": attendee_list,
            "subject": "Invitation: Team Sync @ Maple Conference Room",
            "body": f"Meeting confirmed for {date} from 14:00 to 16:00 in Maple Conference Room (2nd Floor). Total reserved: {duration_hours} hours for {capacity} attendees.",
        },
        depends_on=["task_create_reservation"],
        idempotency_key=f"idem-inv-{wf_id}",
    )

    wf.add_task(t_research)
    wf.add_task(t_analyze)
    wf.add_task(t_reserve)
    wf.add_task(t_invite)

    return wf
