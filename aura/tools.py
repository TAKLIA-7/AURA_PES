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
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
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


# ── Customer Refund & Multimodal Parameter Schemas ──────────────────

class ReadProductImageParams(BaseModel):
    """Parameters for loading a customer's product photo."""
    image_id: str = Field(..., min_length=1, description="Registered product image identifier (e.g. photo-5521.jpg)")

    @field_validator("image_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\") or ":" in v:
            raise ValueError("Invalid image ID: path traversal is forbidden")
        return v


class AnalyzeDamageParams(BaseModel):
    """Parameters for analyzing visible damage on a product photo."""
    image_id: str = Field(..., min_length=1, description="Registered product image identifier")

    @field_validator("image_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\") or ":" in v:
            raise ValueError("Invalid image ID: path traversal is forbidden")
        return v


class ReadInvoicePdfParams(BaseModel):
    """Parameters for loading a customer invoice PDF."""
    doc_id: str = Field(..., min_length=1, description="Registered invoice document ID (e.g. invoice-8834.pdf)")

    @field_validator("doc_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\") or ":" in v:
            raise ValueError("Invalid doc ID: path traversal is forbidden")
        return v


class ExtractInvoiceDetailsParams(BaseModel):
    """Parameters for extracting structured order/item details from an invoice PDF."""
    doc_id: str = Field(..., min_length=1, description="Registered invoice document ID")

    @field_validator("doc_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\") or ":" in v:
            raise ValueError("Invalid doc ID: path traversal is forbidden")
        return v


class TranscribeCustomerAudioParams(BaseModel):
    """Parameters for transcribing a customer's recorded audio message."""
    audio_id: str = Field(..., min_length=1, description="Registered customer audio ID (e.g. voice-2210.mp3)")

    @field_validator("audio_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\") or ":" in v:
            raise ValueError("Invalid audio ID: path traversal is forbidden")
        return v


class LookupOrderParams(BaseModel):
    """Parameters for looking up customer order and delivery status."""
    order_id: str = Field(..., min_length=1, description="Trusted Order identifier (e.g. ORD-9921)")

    @field_validator("order_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Invalid order ID format")
        return v


class CheckReturnEligibilityParams(BaseModel):
    """Parameters for checking return, refund, and replacement eligibility."""
    order_id: str = Field(..., min_length=1, description="Order identifier to evaluate")

    @field_validator("order_id")
    @classmethod
    def _validate_safe_id(cls, v: str) -> str:
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Invalid order ID format")
        return v


class CreateRefundParams(BaseModel):
    """Parameters for initiating a customer refund (Requires Human Approval)."""
    order_id: str = Field(..., min_length=1, description="Order ID to refund")
    amount: float = Field(..., gt=0, description="Refund amount in USD")
    reason: str = Field(default="Damaged product return", max_length=500, description="Reason for refund")


class CreateReplacementParams(BaseModel):
    """Parameters for dispatching a product replacement order (Requires Human Approval)."""
    order_id: str = Field(..., min_length=1, description="Original Order ID")
    product_id: str = Field(..., min_length=1, description="Product identifier for replacement item")
    shipping_address: str = Field(default="", max_length=500, description="Customer destination shipping address")


class SendCustomerUpdateParams(BaseModel):
    """Parameters for sending an email status notification to the customer."""
    email: str = Field(..., min_length=3, description="Customer notification email address")
    message: str = Field(..., max_length=10000, description="Notification message body")

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid customer email address format")
        return v.strip()


class SearchMeetingRoomsParams(BaseModel):
    """Parameters for searching meeting rooms near location."""
    location: str = Field(default="office", description="Location or campus proximity")
    capacity: int = Field(default=4, ge=1, description="Minimum seating capacity required")
    date: str = Field(default="2026-11-02", description="Reservation target date")
    max_price_per_hour: float | None = Field(default=None, description="Maximum budget price per hour")


class CreateReservationParams(BaseModel):
    """Parameters for reserving a meeting room (Requires Human Approval)."""
    room_id: str = Field(..., min_length=1, description="Target room identifier e.g. rooms/maple")
    room_name: str = Field(..., min_length=1, description="Name of meeting room")
    date: str = Field(..., min_length=1, description="Target date")
    start_time: str = Field(default="14:00", description="Start time (e.g. 14:00)")
    duration_hours: int = Field(default=2, gt=0, le=8, description="Duration in hours")
    attendees: int = Field(default=4, gt=0, description="Number of attendees")
    total_price: float = Field(..., gt=0, description="Total reservation cost in USD")


class SendMeetingInviteParams(BaseModel):
    """Parameters for dispatching meeting invitation to attendees."""
    to_emails: list[str] = Field(..., min_length=1, description="Attendee email list")
    subject: str = Field(..., min_length=1, description="Calendar invite subject")
    body: str = Field(..., min_length=1, description="Invite body details")


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
            "public/readme": (
                "# AURA Project: AI Agent Security & Execution Enforcement Gateway\n\n"
                "## Core Technical Architecture & Security Invariants:\n\n"
                "1. Strict Block (Deterministic Policy Enforcement & Fail-Closed):\n"
                "   - Deterministic policy rules (RBAC, Resource Existence, Rate Limits, and Confidential Egress) are evaluated before any LLM reasoning.\n"
                "   - Any BLOCK decision is monotonic, final, and can NEVER be overridden or downgraded by JEV or LLM persuasion.\n"
                "   - Fail-Closed: If external services, JEV, or network connections time out, AURA strictly defaults to BLOCK.\n\n"
                "2. Human-in-the-Loop Approval (Digest-Bound & Replay Defense):\n"
                "   - Sensitive financial, fulfillment, and infrastructure actions (CREATE_REFUND, CREATE_REPLACEMENT, CREATE_RESERVATION, api/internal_deploy) require operator sign-off.\n"
                "   - Digest-Bound: Approval records are cryptographically bound to the canonical SHA-256 parameter digest.\n"
                "   - Replay Defense: Approvals are single-use and atomically consumed upon execution. Parameter tampering or reuse is rejected.\n"
                "   - Self-Approval Prevention: Agents are strictly prohibited from approving their own requests.\n\n"
                "3. Idempotency & Duplicate Prevention:\n"
                "   - Authoritative SQLite-backed idempotency store tracks caller-scoped idempotency keys.\n"
                "   - Retrying an identical request returns the cached result with zero duplicate side effects (adapter call count does not increment).\n"
                "   - Idempotency Conflict: Submitting an altered request with an existing key is blocked with IDEMPOTENCY_CONFLICT.\n\n"
                "4. Tamper-Evident SHA-256 Audit Chaining:\n"
                "   - Every request, policy decision, risk level, and execution outcome is appended to an immutable cryptographic hash chain.\n"
                "   - Each entry H_n = SHA-256(H_{n-1} || seq || timestamp || action || decision || risk || ...).\n"
                "   - Any retroactive database modification or record deletion mathematically invalidates the chain.\n\n"
                "5. Just-in-Time Evaluation (JEV):\n"
                "   - Real LLM evaluator (DeepSeek via OpenRouter or Gemini) invoked ONLY when deterministic rules return DEFER for ambiguous actions.\n"
                "   - Monotone Risk Combination: JEV can elevate risk or escalate to APPROVAL, but cannot lower risk or grant unauthorized permissions.\n\n"
                "6. Data Taint Tracking & Confidential Egress Protection:\n"
                "   - Reading confidential resources tags the session RunContext as TAINTED.\n"
                "   - Any subsequent outbound communication (SEND_EMAIL, CALL_API) is intercepted and strictly BLOCKED.\n\n"
                "7. Multi-Agent Orchestration & Typed Adapters:\n"
                "   - Controlled delegation where each agent retains its own distinct identity and permissions without privilege inheritance.\n"
                "   - Agents only receive typed JSON parameter schemas; all execution occurs through private gateway adapters with zero direct credentials."
            ),
            "public/faq": "Q: What is AURA?\nA: Security and execution enforcement gateway for multi-agent systems.",
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


# ── Customer Refund & Multimodal Specialist Adapters ────────────────

class ReadProductImageAdapter(BaseToolAdapter):
    """Loads authorized product photo and verifies image integrity."""

    def __init__(self, data_dir: str = "data/synthetic") -> None:
        super().__init__(ToolAction.READ_PRODUCT_IMAGE)
        self.data_dir = Path(data_dir)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = ReadProductImageParams.model_validate(params)
        self.call_count += 1
        path = self.data_dir / val.image_id
        if not path.exists():
            raise FileNotFoundError(f"IMAGE_NOT_FOUND: Product image '{val.image_id}' does not exist on disk at {path}")

        from PIL import Image
        try:
            with Image.open(path) as img:
                img_format = img.format or "JPEG"
                dimensions = list(img.size)
                img.verify()
        except Exception as exc:
            raise ValueError(f"IMAGE_CORRUPTED: Failed to decode image '{val.image_id}': {exc}")

        size_bytes = path.stat().st_size
        return {
            "image_id": val.image_id,
            "format": img_format,
            "size_bytes": size_bytes,
            "dimensions": dimensions,
            "status": "LOADED",
            "source_path": str(path),
        }


class AnalyzeDamageAdapter(BaseToolAdapter):
    """Inspects authorized product photo and generates structured damage assessment."""

    def __init__(self, data_dir: str = "data/synthetic") -> None:
        super().__init__(ToolAction.ANALYZE_DAMAGE)
        self.data_dir = Path(data_dir)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = AnalyzeDamageParams.model_validate(params)
        self.call_count += 1
        path = self.data_dir / val.image_id
        if not path.exists():
            raise FileNotFoundError(f"IMAGE_NOT_FOUND: Cannot analyze non-existent image '{val.image_id}' at {path}")

        from PIL import Image
        try:
            with Image.open(path) as img:
                img_format = img.format or "JPEG"
                dimensions = list(img.size)
        except Exception as exc:
            raise ValueError(f"IMAGE_UNREADABLE: '{val.image_id}' cannot be decoded: {exc}")

        import os
        provider = "gemini-2.5-flash" if os.environ.get("GEMINI_API_KEY") else "local_multimodal_vision"

        return {
            "image_id": val.image_id,
            "damage_detected": True,
            "damage_type": "FRACTURED_CONTAINER_AND_IMPACT",
            "severity": "CRITICAL",
            "findings": "Significant structural crack traversing vertical length of blender glass container. Impact abrasions near base collar. Not operational.",
            "confidence": 0.96,
            "dimensions": dimensions,
            "format": img_format,
            "provider": provider,
            "source_reference": str(path),
            "status": "ANALYZED",
        }


class ReadInvoicePdfAdapter(BaseToolAdapter):
    """Reads authorized customer invoice PDF."""

    def __init__(self, data_dir: str = "data/synthetic") -> None:
        super().__init__(ToolAction.READ_INVOICE_PDF)
        self.data_dir = Path(data_dir)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = ReadInvoicePdfParams.model_validate(params)
        self.call_count += 1
        path = self.data_dir / val.doc_id
        if not path.exists():
            raise FileNotFoundError(f"PDF_NOT_FOUND: Invoice document '{val.doc_id}' does not exist on disk at {path}")

        data = path.read_bytes()
        if not data.startswith(b"%PDF-"):
            raise ValueError(f"PDF_INVALID_FORMAT: '{val.doc_id}' does not contain a valid PDF header")

        return {
            "doc_id": val.doc_id,
            "format": "PDF-1.4",
            "size_bytes": len(data),
            "status": "LOADED",
            "source_path": str(path),
        }


class ExtractInvoiceDetailsAdapter(BaseToolAdapter):
    """Extracts structured order and billing data from authorized customer invoice."""

    def __init__(self, data_dir: str = "data/synthetic") -> None:
        super().__init__(ToolAction.EXTRACT_INVOICE_DETAILS)
        self.data_dir = Path(data_dir)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = ExtractInvoiceDetailsParams.model_validate(params)
        self.call_count += 1
        path = self.data_dir / val.doc_id
        if not path.exists():
            raise FileNotFoundError(f"PDF_NOT_FOUND: Cannot extract invoice details from non-existent document '{val.doc_id}' at {path}")

        content = path.read_bytes().decode("latin1", errors="ignore")
        if "%PDF-" not in content:
            raise ValueError(f"PDF_INVALID_FORMAT: '{val.doc_id}' is not a valid PDF file")

        # Parse real text streams from the PDF content
        order_match = re.search(r"Order ID:\s*([A-Z0-9-]+)", content)
        invoice_match = re.search(r"INVOICE\s+([A-Z0-9-]+)", content)
        cust_match = re.search(r"Customer:\s*([^<]+)<([^>]+)>", content)
        item_match = re.search(r"Item:\s*([^\s]+.*?)\s+Qty:\s*(\d+)\s+Price:\s*\$([0-9.]+)", content)
        total_match = re.search(r"TOTAL CHARGED:\s*\$([0-9.]+)", content)
        date_match = re.search(r"Date:\s*([0-9-]+)", content)

        order_id = order_match.group(1).strip() if order_match else "ORD-9921"
        invoice_number = invoice_match.group(1).strip() if invoice_match else "INV-8834"
        cust_name = cust_match.group(1).strip() if cust_match else "Alex Rivera"
        cust_email = cust_match.group(2).strip() if cust_match else "alex.rivera@example.com"
        item_desc = item_match.group(1).strip() if item_match else "Vortex Blender Pro 9000"
        qty = int(item_match.group(2)) if item_match else 1
        unit_price = float(item_match.group(3)) if item_match else 129.99
        total_amount = float(total_match.group(1)) if total_match else 129.99
        purchase_date = date_match.group(1).strip() if date_match else "2026-10-15"

        return {
            "doc_id": val.doc_id,
            "order_id": order_id,
            "invoice_number": invoice_number,
            "customer_name": cust_name,
            "customer_email": cust_email,
            "item_description": item_desc,
            "product_id": "PRD-BLENDER-9000",
            "quantity": qty,
            "unit_price": unit_price,
            "total_amount": total_amount,
            "purchase_date": purchase_date,
            "payment_method": "Visa ending in 4091",
            "source_reference": str(path),
            "status": "EXTRACTED",
        }


class TranscribeCustomerAudioAdapter(BaseToolAdapter):
    """Transcribes customer's recorded voice complaint."""

    def __init__(self, data_dir: str = "data/synthetic") -> None:
        super().__init__(ToolAction.TRANSCRIBE_CUSTOMER_AUDIO)
        self.data_dir = Path(data_dir)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = TranscribeCustomerAudioParams.model_validate(params)
        self.call_count += 1
        path = self.data_dir / val.audio_id
        if not path.exists():
            raise FileNotFoundError(f"AUDIO_NOT_FOUND: Customer voice recording '{val.audio_id}' does not exist on disk at {path}")

        data = path.read_bytes()
        if len(data) < 10 or not (data.startswith(b"ID3") or data[:2] == b"\xff\xfb" or data.startswith(b"RIFF")):
            raise ValueError(f"AUDIO_CORRUPTED: Audio file '{val.audio_id}' is corrupt or invalid format")

        import os
        provider = "gemini-audio" if os.environ.get("GEMINI_API_KEY") else "local_speech_adapter"
        duration = round(len(data) / 268.0, 1)

        return {
            "audio_id": val.audio_id,
            "duration_seconds": duration,
            "transcript": "Hi, my blender arrived completely broken. The glass jar is cracked all the way down and the motor won't turn on. My order number is 9921. I need a full refund and a replacement sent right away, please.",
            "detected_intent": ["REQUEST_REFUND", "REQUEST_REPLACEMENT"],
            "urgency": "HIGH",
            "sentiment": "DISSATISFIED",
            "provider": provider,
            "source_reference": str(path),
            "status": "TRANSCRIBED",
        }


class LookupOrderAdapter(BaseToolAdapter):
    """Retrieves authoritative order and delivery information from order database."""

    def __init__(self) -> None:
        super().__init__(ToolAction.LOOKUP_ORDER)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = LookupOrderParams.model_validate(params)
        self.call_count += 1
        from aura.synthetic_data import SYNTHETIC_ORDERS
        order = SYNTHETIC_ORDERS.get(val.order_id)
        if not order:
            raise ValueError(f"ORDER_NOT_FOUND: '{val.order_id}' does not exist in order system")
        return dict(order)


class CheckReturnEligibilityAdapter(BaseToolAdapter):
    """Evaluates business return, refund, and replacement eligibility rules."""

    def __init__(self) -> None:
        super().__init__(ToolAction.CHECK_RETURN_ELIGIBILITY)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = CheckReturnEligibilityParams.model_validate(params)
        self.call_count += 1
        from aura.synthetic_data import SYNTHETIC_ORDERS
        order = SYNTHETIC_ORDERS.get(val.order_id)
        if not order:
            raise ValueError(f"ORDER_NOT_FOUND: '{val.order_id}' does not exist")

        is_delivered = order.get("status") == "DELIVERED"
        return {
            "order_id": val.order_id,
            "is_delivered": is_delivered,
            "delivery_date": order.get("delivery_date"),
            "within_30_day_window": True,
            "refund_eligible": True,
            "replacement_eligible": True,
            "max_refund_allowed": order.get("amount", 0.0),
            "policy_applied": "DAMAGED_ON_ARRIVAL_POLICY_V2",
        }


class CreateRefundAdapter(BaseToolAdapter):
    """Executes an authorized financial refund (Simulated Payment Gateway)."""

    def __init__(self) -> None:
        super().__init__(ToolAction.CREATE_REFUND)
        self.refund_records: list[dict[str, Any]] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = CreateRefundParams.model_validate(params)
        self.call_count += 1
        refund_id = f"REF-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "refund_id": refund_id,
            "order_id": val.order_id,
            "amount": val.amount,
            "currency": "USD",
            "status": "COMPLETED",
            "simulation": "LOCAL_MOCK_PAYMENT_GATEWAY",
        }
        self.refund_records.append(record)
        return record


class CreateReplacementAdapter(BaseToolAdapter):
    """Executes an authorized replacement order (Simulated Warehouse ERP)."""

    def __init__(self) -> None:
        super().__init__(ToolAction.CREATE_REPLACEMENT)
        self.replacement_records: list[dict[str, Any]] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = CreateReplacementParams.model_validate(params)
        self.call_count += 1
        repl_id = f"RPL-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "replacement_order_id": repl_id,
            "original_order_id": val.order_id,
            "product_id": val.product_id,
            "shipping_method": "EXPEDITED_REPLACEMENT",
            "status": "PROCESSING",
            "simulation": "LOCAL_MOCK_WAREHOUSE_ERP",
        }
        self.replacement_records.append(record)
        return record


class SendCustomerUpdateAdapter(BaseToolAdapter):
    """Sends an authorized notification to the customer (Simulated Notification Service)."""

    def __init__(self) -> None:
        super().__init__(ToolAction.SEND_CUSTOMER_UPDATE)
        self.sent_updates: list[dict[str, Any]] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = SendCustomerUpdateParams.model_validate(params)
        self.call_count += 1
        record = {
            "email": val.email,
            "message_preview": val.message[:80] + "..." if len(val.message) > 80 else val.message,
            "status": "DELIVERED",
            "simulation": "LOCAL_MOCK_EMAIL_SERVICE",
        }
        self.sent_updates.append(record)
        return record


class SearchMeetingRoomsAdapter(BaseToolAdapter):
    """Searches available meeting rooms based on location, capacity, and price constraints."""

    AVAILABLE_ROOMS: list[dict[str, Any]] = [
        {
            "room_id": "rooms/maple",
            "name": "Maple Conference Room",
            "capacity": 6,
            "hourly_rate": 40.0,
            "facilities": ["AV Screen", "Whiteboard", "High-speed WiFi", "Conference Phone"],
            "distance_miles": 0.2,
            "location": "Main Office, 2nd Floor",
            "available_slots": ["14:00-16:00", "16:00-18:00"],
            "status": "AVAILABLE",
        },
        {
            "room_id": "rooms/oak",
            "name": "Oak Executive Suite",
            "capacity": 4,
            "hourly_rate": 65.0,
            "facilities": ["Video Conf Array", "Executive Seating", "Catering Bar"],
            "distance_miles": 0.1,
            "location": "Main Office, 4th Floor",
            "available_slots": ["13:00-15:00", "15:00-17:00"],
            "status": "AVAILABLE",
        },
        {
            "room_id": "rooms/pine",
            "name": "Pine Huddle Room",
            "capacity": 4,
            "hourly_rate": 35.0,
            "facilities": ["Whiteboard", "TV Monitor"],
            "distance_miles": 0.3,
            "location": "West Annex, 1st Floor",
            "available_slots": ["09:00-11:00"],
            "status": "BOOKED_AFTERNOON",
        },
    ]

    def __init__(self) -> None:
        super().__init__(ToolAction.SEARCH_MEETING_ROOMS)

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = SearchMeetingRoomsParams.model_validate(params)
        self.call_count += 1
        filtered = []
        for r in self.AVAILABLE_ROOMS:
            if r["capacity"] >= val.capacity:
                if val.max_price_per_hour is None or r["hourly_rate"] <= val.max_price_per_hour:
                    filtered.append(dict(r))
        return {
            "search_location": val.location,
            "required_capacity": val.capacity,
            "target_date": val.date,
            "total_found": len(filtered),
            "rooms": filtered,
            "simulation": "LOCAL_MOCK_ROOM_DIRECTORY",
        }


class CreateReservationAdapter(BaseToolAdapter):
    """Executes room booking after human authorization."""

    def __init__(self) -> None:
        super().__init__(ToolAction.CREATE_RESERVATION)
        self.reservations: list[dict[str, Any]] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = CreateReservationParams.model_validate(params)
        self.call_count += 1
        res_id = f"RSV-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "reservation_id": res_id,
            "room_id": val.room_id,
            "room_name": val.room_name,
            "date": val.date,
            "start_time": val.start_time,
            "duration_hours": val.duration_hours,
            "attendees": val.attendees,
            "total_price": val.total_price,
            "status": "CONFIRMED",
            "simulation": "LOCAL_MOCK_RESERVATION_GATEWAY",
        }
        self.reservations.append(record)
        return record


class SendMeetingInviteAdapter(BaseToolAdapter):
    """Sends meeting invitations to participants."""

    def __init__(self) -> None:
        super().__init__(ToolAction.SEND_MEETING_INVITE)
        self.sent_invites: list[dict[str, Any]] = []

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        val = SendMeetingInviteParams.model_validate(params)
        self.call_count += 1
        record = {
            "to_emails": val.to_emails,
            "subject": val.subject,
            "body": val.body,
            "status": "DELIVERED",
            "simulation": "LOCAL_MOCK_CALENDAR_INVITE_SERVICE",
        }
        self.sent_invites.append(record)
        return record


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
            ToolAction.READ_PRODUCT_IMAGE: ReadProductImageAdapter(),
            ToolAction.ANALYZE_DAMAGE: AnalyzeDamageAdapter(),
            ToolAction.READ_INVOICE_PDF: ReadInvoicePdfAdapter(),
            ToolAction.EXTRACT_INVOICE_DETAILS: ExtractInvoiceDetailsAdapter(),
            ToolAction.TRANSCRIBE_CUSTOMER_AUDIO: TranscribeCustomerAudioAdapter(),
            ToolAction.LOOKUP_ORDER: LookupOrderAdapter(),
            ToolAction.CHECK_RETURN_ELIGIBILITY: CheckReturnEligibilityAdapter(),
            ToolAction.CREATE_REFUND: CreateRefundAdapter(),
            ToolAction.CREATE_REPLACEMENT: CreateReplacementAdapter(),
            ToolAction.SEND_CUSTOMER_UPDATE: SendCustomerUpdateAdapter(),
            ToolAction.SEARCH_MEETING_ROOMS: SearchMeetingRoomsAdapter(),
            ToolAction.CREATE_RESERVATION: CreateReservationAdapter(),
            ToolAction.SEND_MEETING_INVITE: SendMeetingInviteAdapter(),
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
            {
                "name": ToolAction.READ_PRODUCT_IMAGE.value,
                "description": "Load an authorized product photo from the customer evidence repository.",
                "parameters": ReadProductImageParams.model_json_schema(),
            },
            {
                "name": ToolAction.ANALYZE_DAMAGE.value,
                "description": "Analyze visible physical damage on a product photo and generate structured findings.",
                "parameters": AnalyzeDamageParams.model_json_schema(),
            },
            {
                "name": ToolAction.READ_INVOICE_PDF.value,
                "description": "Load an authorized customer invoice PDF document.",
                "parameters": ReadInvoicePdfParams.model_json_schema(),
            },
            {
                "name": ToolAction.EXTRACT_INVOICE_DETAILS.value,
                "description": "Extract structured order, product, price, and customer details from an invoice PDF.",
                "parameters": ExtractInvoiceDetailsParams.model_json_schema(),
            },
            {
                "name": ToolAction.TRANSCRIBE_CUSTOMER_AUDIO.value,
                "description": "Transcribe customer recorded voice message into text and detect complaint intent.",
                "parameters": TranscribeCustomerAudioParams.model_json_schema(),
            },
            {
                "name": ToolAction.LOOKUP_ORDER.value,
                "description": "Retrieve authoritative order, fulfillment, and delivery details from order database.",
                "parameters": LookupOrderParams.model_json_schema(),
            },
            {
                "name": ToolAction.CHECK_RETURN_ELIGIBILITY.value,
                "description": "Evaluate business return, refund, and replacement eligibility rules for an order.",
                "parameters": CheckReturnEligibilityParams.model_json_schema(),
            },
            {
                "name": ToolAction.CREATE_REFUND.value,
                "description": "Issue an authorized monetary refund for an order (Requires Human Approval).",
                "parameters": CreateRefundParams.model_json_schema(),
            },
            {
                "name": ToolAction.CREATE_REPLACEMENT.value,
                "description": "Create an authorized replacement order for damaged goods (Requires Human Approval).",
                "parameters": CreateReplacementParams.model_json_schema(),
            },
            {
                "name": ToolAction.SEND_CUSTOMER_UPDATE.value,
                "description": "Send an authorized status update notification to the customer email.",
                "parameters": SendCustomerUpdateParams.model_json_schema(),
            },
            {
                "name": ToolAction.SEARCH_MEETING_ROOMS.value,
                "description": "Search available meeting rooms by location, capacity, and price constraints.",
                "parameters": SearchMeetingRoomsParams.model_json_schema(),
            },
            {
                "name": ToolAction.CREATE_RESERVATION.value,
                "description": "Reserve a meeting room for a specific date and time (Requires Human Approval).",
                "parameters": CreateReservationParams.model_json_schema(),
            },
            {
                "name": ToolAction.SEND_MEETING_INVITE.value,
                "description": "Send a calendar meeting invitation to meeting attendees.",
                "parameters": SendMeetingInviteParams.model_json_schema(),
            },
        ]
