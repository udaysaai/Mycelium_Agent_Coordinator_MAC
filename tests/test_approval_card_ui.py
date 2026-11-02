"""
test_approval_card_ui.py - Verification of Human-On-The-Loop Approval Card & UI Renderer

Verifies:
1. Full untruncated command display in approval payload inspection.
2. Target path and tier classification preservation.
3. Short call hash computation and display.
4. Warning badges for control chars, newlines, confusables, and long strings.
5. Default focus on Reject button in the UI renderer implementation.
"""

import json
from pathlib import Path
import pytest

from approval_card import inspect_approval_payload

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_approval_card_payload_preserves_untruncated_command_and_target():
    """Verify that exact literal text and target paths are never truncated."""
    long_command = "cat /etc/passwd && " + ("x" * 2500)
    target_file = "/workspace_sandbox/output_data.bin"

    card = inspect_approval_payload(
        tool_name="write_workspace_file",
        payload={"file_path": target_file, "content": long_command},
        tier="T2",
        call_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        target_path=target_file
    )

    # 1. Full untruncated content preserved
    assert long_command in card["exact_command"]
    assert len(card["exact_command"]) > 2500

    # 2. Target path and tier
    assert card["target"] == target_file
    assert card["tier"] == "T2"

    # 3. Short call hash (first 12 chars)
    assert card["short_hash"] == "9f86d081884c"
    assert card["call_hash"] == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    # 4. Long payload warning badge flagged
    assert card["flags"]["is_very_long"] is True
    assert any("long" in msg.lower() or "size" in msg.lower() for msg in card["warning_messages"])


def test_approval_card_payload_detects_all_anomaly_badges():
    """Verify detection of newlines, control characters, and confusable/homoglyph characters."""
    evil_command = "echo hello\n\rrm -rf /\x00\x1b[31m \u200b\u0440\u202e"

    card = inspect_approval_payload(
        tool_name="execute_shell_command",
        payload={"command": evil_command},
        tier="T2",
        call_hash="abcdef0123456789"
    )

    assert card["flags"]["has_newlines"] is True
    assert card["flags"]["has_control_chars"] is True
    assert card["flags"]["has_non_ascii_or_confusables"] is True

    # Badges for all 3 categories must be present
    messages = " ".join(card["warning_messages"]).lower()
    assert "newline" in messages
    assert "control" in messages
    assert "homoglyph" in messages or "non-ascii" in messages


def test_ui_renderer_defaults_keyboard_focus_on_reject():
    """
    Verify that the Electron renderer logic in app.js and index.html:
    (a) Defines the reject button and approval modal elements.
    (b) Sets default keyboard focus on the Reject button when triggered.
    (c) Displays untruncated command text and short call hash.
    (d) Renders warning chip badges for all flagged anomalies.
    """
    app_js_path = ROOT_DIR / "mycelium_desktop" / "renderer" / "app.js"
    index_html_path = ROOT_DIR / "mycelium_desktop" / "renderer" / "index.html"

    assert app_js_path.is_file(), "mycelium_desktop/renderer/app.js not found"
    assert index_html_path.is_file(), "mycelium_desktop/renderer/index.html not found"

    app_js = app_js_path.read_text(encoding="utf-8")
    index_html = index_html_path.read_text(encoding="utf-8")

    # (a) Modal buttons defined in HTML
    assert 'id="hol-reject-btn"' in index_html, "hol-reject-btn element missing in index.html"
    assert 'id="hol-approve-btn"' in index_html, "hol-approve-btn element missing in index.html"
    assert 'id="modal-payload-code"' in index_html, "modal-payload-code element missing in index.html"
    assert 'id="modal-call-hash"' in index_html, "modal-call-hash element missing in index.html"
    assert 'id="hol-anomaly-chips"' in index_html, "hol-anomaly-chips element missing in index.html"

    # (b) Default keyboard focus on Reject button in app.js
    assert "el.holRejectBtn.focus()" in app_js, "Default focus on Reject button not implemented in app.js"

    # (c) Full untruncated command text rendered
    assert "el.modalPayloadCode.textContent = payloadStr" in app_js, "Payload text binding missing in app.js"
    assert "data.exactCommand" in app_js, "exactCommand un-truncated binding missing in app.js"

    # (d) Anomaly warning chips for all four categories
    assert "has_newlines" in app_js, "Newline badge check missing in app.js"
    assert "has_control_chars" in app_js, "Control char badge check missing in app.js"
    assert "has_non_ascii_or_confusables" in app_js, "Confusable badge check missing in app.js"
    assert "is_very_long" in app_js, "Length badge check missing in app.js"
