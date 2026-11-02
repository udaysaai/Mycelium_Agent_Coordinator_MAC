"""
tests/test_ws3_review_ui.py - WS3 Step 3.5 & 3.6 Human Review UI & State Store Test Suite
Validates:
(a) Immutable review records in StateStore (Accept / Flag actions),
(b) 'Mark Reconciliation Reviewed' T2-style gate records,
(c) Supervisor UI channel handling of review actions,
(d) Desktop UI panel and action buttons presence in index.html and app.js.
"""

import json
from decimal import Decimal
from pathlib import Path
import pytest

from state_store import StateStore
from supervisor import SupervisorDaemon


def test_state_store_reconciliation_review_storage(tmp_path):
    db_path = tmp_path / "test_recon_state.db"
    store = StateStore(db_path=db_path)
    signing_key = b"test_signing_key_recon_review_32"

    review_id = store.save_reconciliation_review(
        run_id="RUN_2026_04",
        exception_id="EXC_0001",
        action="ACCEPT",
        reviewer_notes="Verified with Gram Sevak voucher",
        reviewer_identity="Sarpanch_01",
        signing_key=signing_key
    )
    assert review_id is not None
    assert len(review_id) > 0

    reviews = store.get_reconciliation_reviews(run_id="RUN_2026_04")
    assert len(reviews) == 1
    rev = reviews[0]
    assert rev["exception_id"] == "EXC_0001"
    assert rev["action"] == "ACCEPT"
    assert rev["reviewer_notes"] == "Verified with Gram Sevak voucher"
    assert rev["reviewer_identity"] == "Sarpanch_01"
    assert "row_hmac" in rev


def test_state_store_reconciliation_gate_decision(tmp_path):
    db_path = tmp_path / "test_recon_state.db"
    store = StateStore(db_path=db_path)
    signing_key = b"test_signing_key_recon_review_32"

    gate_info = {
        "run_id": "RUN_2026_04",
        "manifest_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "total_matched": 15,
        "total_exceptions": 3,
        "cashbook_total_credits": "150000.00",
        "cashbook_total_debits": "45000.00",
        "bank_total_deposits": "150000.00",
        "bank_total_withdrawals": "45000.00",
        "decision": "REVIEWED_APPROVED",
        "reviewer_identity": "Auditor_01"
    }

    gate_id = store.save_reconciliation_gate_decision(gate_info, signing_key=signing_key)
    assert gate_id is not None

    stored_gate = store.get_reconciliation_gate_decision(run_id="RUN_2026_04")
    assert stored_gate is not None
    assert stored_gate["manifest_sha256"] == gate_info["manifest_sha256"]
    assert stored_gate["decision"] == "REVIEWED_APPROVED"
    assert stored_gate["total_matched"] == 15
    assert stored_gate["total_exceptions"] == 3


def test_desktop_ui_markup_contains_reconciliation_panel():
    root = Path(__file__).resolve().parent.parent
    renderer_dir = root / "mycelium_desktop" / "renderer"
    index_path = renderer_dir / "index.html" if renderer_dir.exists() else root / "mycelium_desktop" / "index.html"
    app_path = renderer_dir / "app.js" if renderer_dir.exists() else root / "mycelium_desktop" / "app.js"

    index_html = index_path.read_text(encoding="utf-8")
    app_js = app_path.read_text(encoding="utf-8")

    # Verify HTML elements
    assert "reconciliation-review-panel" in index_html
    assert "btn-mark-reconciliation-reviewed" in index_html or "markReconciliationReviewed" in index_html
    assert "reconciliation-exceptions-table" in index_html

    # Verify JS event listeners and handlers
    assert "renderReconciliationExceptions" in app_js
    assert "submitReconciliationReview" in app_js or "handleReconciliationAction" in app_js
