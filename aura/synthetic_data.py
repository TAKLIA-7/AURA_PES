"""AURA Synthetic Customer Data Generator and Mock Stores.

Generates realistic multimodal assets:
  - photo-5521.jpg: Damaged blender photo (Pillow image with crack overlay)
  - invoice-8834.pdf: Formatted PDF invoice for Order ORD-9921
  - voice-2210.mp3: Customer voice recording asset
  - Synthetic Orders & Products Database
"""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw


SYNTHETIC_DIR = Path("data/synthetic")


# ── Synthetic Orders Database ────────────────────────────────────────

SYNTHETIC_ORDERS: dict[str, dict[str, Any]] = {
    "ORD-9921": {
        "order_id": "ORD-9921",
        "customer_id": "CUST-4412",
        "customer_name": "Alex Rivera",
        "customer_email": "alex.rivera@example.com",
        "product_id": "PRD-BLENDER-9000",
        "product_name": "Vortex Blender Pro 9000",
        "amount": 129.99,
        "currency": "USD",
        "order_date": "2026-10-15",
        "delivery_date": "2026-10-18",
        "status": "DELIVERED",
        "carrier": "FedEx",
        "tracking_number": "TRK-881928310",
        "serial_number": "VB9000-8841-A",
        "shipping_address": "742 Evergreen Terrace, Springfield, OR 97477",
    },
    "ORD-1002": {
        "order_id": "ORD-1002",
        "customer_id": "CUST-9901",
        "customer_name": "Sarah Connor",
        "customer_email": "sarah.connor@example.com",
        "product_id": "PRD-COFFEE-200",
        "product_name": "Espresso Master 200",
        "amount": 249.50,
        "currency": "USD",
        "order_date": "2026-08-01",
        "delivery_date": "2026-08-04",
        "status": "DELIVERED",
        "carrier": "UPS",
        "tracking_number": "TRK-11223344",
        "serial_number": "EM200-1102-X",
        "shipping_address": "100 Tech Blvd, Austin, TX 78701",
    },
}


def ensure_synthetic_assets(output_dir: Path | str = SYNTHETIC_DIR) -> dict[str, Path]:
    """Ensure all synthetic assets exist on disk for image/PDF/audio operations."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    assets: dict[str, Path] = {}

    # 1. Generate photo-5521.jpg (Damaged blender photo)
    image_path = out / "photo-5521.jpg"
    if not image_path.exists():
        img = Image.new("RGB", (600, 600), color=(240, 240, 245))
        draw = ImageDraw.Draw(img)

        # Draw blender base
        draw.rectangle([200, 350, 400, 520], fill=(50, 50, 60), outline=(20, 20, 30), width=4)
        # Draw control dial
        draw.ellipse([275, 410, 325, 460], fill=(200, 50, 50), outline=(100, 20, 20), width=2)
        # Draw glass jar
        draw.polygon([(220, 150), (380, 150), (360, 350), (240, 350)], fill=(200, 220, 240), outline=(100, 140, 180), width=3)
        # Draw severe fracture / crack lines across jar
        crack_coords = [(300, 160), (310, 200), (290, 240), (320, 290), (280, 340)]
        draw.line(crack_coords, fill=(220, 30, 30), width=4)
        draw.line([(310, 200), (340, 220), (360, 230)], fill=(220, 30, 30), width=3)
        # Text label
        draw.text((30, 30), "CUSTOMER PHOTO EVIDENCE: photo-5521.jpg", fill=(10, 10, 10))
        draw.text((30, 50), "ITEM: Vortex Blender Pro 9000 (Jar Fracture)", fill=(180, 20, 20))

        img.save(image_path, "JPEG", quality=90)
    assets["image"] = image_path

    # 2. Generate invoice-8834.pdf (Pure Python standard PDF-1.4 generation)
    pdf_path = out / "invoice-8834.pdf"
    if not pdf_path.exists():
        pdf_bytes = _create_minimal_invoice_pdf(
            invoice_num="INV-8834",
            order_id="ORD-9921",
            customer="Alex Rivera",
            email="alex.rivera@example.com",
            item="Vortex Blender Pro 9000",
            total="129.99",
            date="2026-10-15",
        )
        pdf_path.write_bytes(pdf_bytes)
    assets["invoice"] = pdf_path

    # 3. Generate voice-2210.mp3 (Synthetic audio asset with MP3 ID3 header)
    audio_path = out / "voice-2210.mp3"
    if not audio_path.exists():
        # Minimal valid ID3v2 container with synthetic silence/metadata frames
        header = b"ID3\x04\x00\x00\x00\x00\x00\x23"
        tag = b"TIT2\x00\x00\x00\x15\x00\x00\x03Customer Complaint Audio"
        payload = (b"\xff\xfb\x90\x44" + b"\x00" * 380) * 10
        audio_path.write_bytes(header + tag + payload)
    assets["audio"] = audio_path

    return assets


def _create_minimal_invoice_pdf(
    invoice_num: str,
    order_id: str,
    customer: str,
    email: str,
    item: str,
    total: str,
    date: str,
) -> bytes:
    """Construct a clean, valid PDF 1.4 invoice file in pure Python."""
    stream_content = (
        "BT\n"
        "/F1 18 Tf\n"
        "50 750 Td\n"
        f"(INVOICE {invoice_num}) Tj\n"
        "/F1 12 Tf\n"
        "0 -30 Td\n"
        f"(Order ID: {order_id}) Tj\n"
        "0 -20 Td\n"
        f"(Date: {date}) Tj\n"
        "0 -20 Td\n"
        f"(Customer: {customer} <{email}>) Tj\n"
        "0 -30 Td\n"
        "(---------------------------------------------------------) Tj\n"
        "0 -20 Td\n"
        f"(Item: {item}   Qty: 1   Price: ${total}) Tj\n"
        "0 -20 Td\n"
        "(---------------------------------------------------------) Tj\n"
        "0 -20 Td\n"
        f"(TOTAL CHARGED: ${total} USD) Tj\n"
        "0 -30 Td\n"
        "(Payment Method: Visa ending in 4091) Tj\n"
        "ET\n"
    ).encode("ascii")

    stream_len = len(stream_content)

    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    obj3 = (
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    )
    obj4 = (
        f"4 0 obj\n<< /Length {stream_len} >>\nstream\n".encode("ascii")
        + stream_content
        + b"\nendstream\nendobj\n"
    )
    obj5 = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"

    header = b"%PDF-1.4\n"
    offsets = [0]
    body = bytearray(header)

    for o in (obj1, obj2, obj3, obj4, obj5):
        offsets.append(len(body))
        body.extend(o)

    xref_offset = len(body)
    xref = f"xref\n0 6\n0000000000 65535 f \n".encode("ascii")
    for off in offsets[1:]:
        xref += f"{off:010d} 00000 n \n".encode("ascii")

    trailer = (
        f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )

    return bytes(body + xref + trailer)

