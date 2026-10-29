"""
test_phase06_wiring.py - Phase 0.6 Production Wiring & Boundary Tests
Covers Part 2:
  - F1: Production mode refusal of in-process coordinator
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
import pytest


def test_production_mode_refuses_inprocess_coordinator(monkeypatch):
    """
    In production mode (MAC_UNSAFE_INPROCESS_FOR_TESTS not set),
    MyceliumCoordinator must refuse in-process initialization to enforce
    the supervisor/worker process boundary.
    """
    from coordinator import MyceliumCoordinator
    from local_daemon import LocalExecDaemon

    monkeypatch.delenv("MAC_UNSAFE_INPROCESS_FOR_TESTS", raising=False)
    daemon = LocalExecDaemon(workspace_root=Path("."))

    with pytest.raises(RuntimeError) as exc_info:
        MyceliumCoordinator(local_daemon=daemon)

    assert "in-process" in str(exc_info.value).lower()
    assert "mac_unsafe_inprocess_for_tests" in str(exc_info.value).lower()


def test_inprocess_flag_allows_testing_with_loud_warning(monkeypatch, capsys):
    """
    When MAC_UNSAFE_INPROCESS_FOR_TESTS=1 is explicitly set,
    in-process initialization is permitted for backward-compatible test suites,
    but emits a prominent security warning.
    """
    from coordinator import MyceliumCoordinator
    from local_daemon import LocalExecDaemon

    monkeypatch.setenv("MAC_UNSAFE_INPROCESS_FOR_TESTS", "1")
    daemon = LocalExecDaemon(workspace_root=Path("."))

    coord = MyceliumCoordinator(local_daemon=daemon)
    try:
        captured = capsys.readouterr()
        assert "warning" in captured.err.lower() or "unsafe" in captured.err.lower()
    finally:
        coord.state_store.close()


def pipe_send_recv(pipe_path: str, msg: dict) -> dict:
    import json
    import time
    import win32api
    import win32file
    import win32pipe
    import pywintypes

    start = time.time()
    h = None
    while time.time() - start < 5.0:
        try:
            h = win32file.CreateFile(
                pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            break
        except pywintypes.error as e:
            if e.winerror == 231:  # ERROR_PIPE_BUSY
                try:
                    win32pipe.WaitNamedPipe(pipe_path, 1000)
                except Exception:
                    time.sleep(0.05)
            else:
                raise
    if h is None:
        raise TimeoutError(f"Could not connect to named pipe {pipe_path} within 5s")
    try:
        win32file.WriteFile(h, (json.dumps(msg) + "\n").encode("utf-8"))
        win32file.FlushFileBuffers(h)
        err, data = win32file.ReadFile(h, 65536)
        line = data.decode("utf-8").strip()
        if "\n" in line:
            line = line.split("\n")[0]
        return json.loads(line)
    finally:
        win32api.CloseHandle(h)


def test_named_pipe_supervisor_support(tmp_path):
    """
    Supervisor must support Windows Named Pipes with random per-session names
    and explicit user DACLs, serving worker and UI channels separately.
    """
    from supervisor import SupervisorDaemon
    daemon = SupervisorDaemon(workspace_root=tmp_path, use_named_pipes=True)
    try:
        daemon.start()
        assert hasattr(daemon, "worker_pipe_path")
        assert hasattr(daemon, "ui_pipe_path")
        assert daemon.worker_pipe_path.startswith(r"\\.\pipe\mac_worker_")
        assert daemon.ui_pipe_path.startswith(r"\\.\pipe\mac_ui_")
        assert daemon.worker_pipe_path != daemon.ui_pipe_path

        # Test UI pipe authorization
        ui_resp = pipe_send_recv(daemon.ui_pipe_path, {
            "secret": daemon.ui_secret,
            "type": "LIST_PENDING"
        })
        assert ui_resp.get("status") == "OK"

        # Test UI pipe rejects worker secret
        ui_fail = pipe_send_recv(daemon.ui_pipe_path, {
            "secret": daemon.worker_secret,
            "type": "LIST_PENDING"
        })
        assert ui_fail.get("status") == "ERROR"

        # Test Worker pipe rejects APPROVE_ACTION
        worker_resp = pipe_send_recv(daemon.worker_pipe_path, {
            "type": "APPROVE_ACTION",
            "quarantine_id": "fake-qid"
        })
        assert worker_resp.get("status") in ("REJECTED", "ERROR")
    finally:
        daemon.stop()


# ============================================================================
# F3: Approval Card Integrity & Confusable / Anomaly Flags (Part 2.5)
# ============================================================================

def test_approval_card_exact_content_never_truncated_and_flags_long():
    """
    Approval card must display the full literal text without truncation,
    and flag very long strings (> 1000 chars) with length warnings.
    """
    from approval_card import inspect_approval_payload

    long_cmd = "echo " + ("A" * 5000)
    card = inspect_approval_payload(
        tool_name="execute_shell_command",
        payload={"command": long_cmd},
        tier="T2",
        call_hash="a1b2c3d4e5f67890"
    )

    # Must preserve full command without truncation
    assert card["exact_command"] == long_cmd
    assert len(card["exact_command"]) == 5005
    assert card["flags"]["is_very_long"] is True
    assert card["tier"] == "T2"
    assert card["short_hash"] == "a1b2c3d4e5f6"
    assert any("long" in w.lower() for w in card["warning_messages"])


def test_approval_card_flags_newlines_and_control_characters():
    """
    Approval card must detect and visibly flag embedded newlines,
    null bytes, and ANSI control characters.
    """
    from approval_card import inspect_approval_payload

    tricky_cmd = "git status\necho evil\x00\x1b[31mPWNED\x1b[0m\r\n"
    card = inspect_approval_payload(
        tool_name="execute_shell_command",
        payload={"command": tricky_cmd},
        tier="T2",
        call_hash="fedcba9876543210"
    )

    assert card["exact_command"] == tricky_cmd
    assert card["flags"]["has_newlines"] is True
    assert card["flags"]["has_control_chars"] is True
    assert any("newline" in w.lower() for w in card["warning_messages"])
    assert any("control" in w.lower() for w in card["warning_messages"])


def test_approval_card_flags_confusables_and_non_ascii():
    """
    Approval card must flag homoglyphs/confusables (e.g. Cyrillic lookalikes),
    zero-width spaces, and directional overrides.
    """
    from approval_card import inspect_approval_payload

    # 'р' (U+0440 cyrillic) looks like 'p', zero-width space U+200B, RTL override U+202E
    confusable_cmd = "рython\u200b -c \"print('hello')\"\u202e"
    card = inspect_approval_payload(
        tool_name="execute_shell_command",
        payload={"command": confusable_cmd},
        tier="T2",
        call_hash="1122334455667788"
    )

    assert card["exact_command"] == confusable_cmd
    assert card["flags"]["has_non_ascii_or_confusables"] is True
    assert any("non-ascii" in w.lower() or "confusable" in w.lower() for w in card["warning_messages"])


# ============================================================================
# F7: Real Stack End-to-End Execution (Part 2.4)
# ============================================================================

def test_real_stack_e2e_supervisor_ui_approval(tmp_path):
    """
    Drive the real stack as the Electron app would:
      1. Supervisor starts with named pipes and ephemeral key.
      2. Worker connects to worker pipe, authenticates.
      3. Worker proposes a T2 shell command.
      4. Action is quarantined in SQLite state store.
      5. UI channel queries pending quarantines, checks payload integrity flags.
      6. Operator approves action via UI channel.
      7. Worker executes approved action using one-shot token.
      8. Receipt is verified and persisted in DB.
    """
    from supervisor import SupervisorDaemon
    from approval_card import inspect_approval_payload
    from protocol import HOLApprovalStatus

    daemon = SupervisorDaemon(workspace_root=tmp_path, use_named_pipes=True)
    try:
        daemon.start()

        # Step 1: Worker connects to worker pipe
        auth_resp = pipe_send_recv(daemon.worker_pipe_path, {
            "type": "AUTH",
            "secret": daemon.worker_secret
        })
        assert auth_resp.get("status") == "AUTHENTICATED"

        # Step 2: Worker proposes T2 shell action
        cmd = "echo REAL_STACK_VERIFIED"
        prop_resp = pipe_send_recv(daemon.worker_pipe_path, {
            "type": "PROPOSE_ACTION",
            "secret": daemon.worker_secret,
            "intent": "execute diagnostic command in real stack",
            "tool_name": "execute_shell_command",
            "payload": {"command": cmd}
        })
        assert prop_resp.get("status") == "QUARANTINED"
        qid = prop_resp.get("quarantine_id")
        call_hash = prop_resp.get("call_hash")

        # Step 3: UI channel lists pending quarantines
        pending_resp = pipe_send_recv(daemon.ui_pipe_path, {
            "secret": daemon.ui_secret,
            "type": "LIST_PENDING"
        })
        assert pending_resp.get("status") == "OK"
        pending_list = pending_resp.get("pending", [])
        assert any(q["quarantine_id"] == qid for q in pending_list)

        # Step 4: UI channel inspects approval card schema & flags
        card = inspect_approval_payload(
            tool_name="execute_shell_command",
            payload={"command": cmd},
            tier="T2",
            call_hash=call_hash
        )
        assert card["exact_command"] == cmd
        assert card["short_hash"] == call_hash[:12]
        assert card["flags"]["has_newlines"] is False
        assert card["flags"]["has_control_chars"] is False

        # Step 5: UI channel approves action
        approve_resp = pipe_send_recv(daemon.ui_pipe_path, {
            "secret": daemon.ui_secret,
            "type": "APPROVE_ACTION",
            "quarantine_id": qid,
            "operator_notes": "Operator authorized via secure UI channel"
        })
        assert approve_resp.get("status") == "APPROVED"
        token = approve_resp.get("one_shot_token")
        assert token is not None

        # Step 6: Worker executes approved action with token
        exec_resp = pipe_send_recv(daemon.worker_pipe_path, {
            "type": "EXECUTE_APPROVED",
            "secret": daemon.worker_secret,
            "quarantine_id": qid,
            "one_shot_token": token,
            "payload": {"command": cmd}
        })
        assert exec_resp.get("status") == "COMPLETED"
        assert exec_resp.get("success") is True
        assert exec_resp.get("exit_code") == 0
        assert "receipt" in exec_resp
        assert exec_resp["receipt"]["verified"] is True

        # Step 7: State store verification
        q_record = daemon.state_store.get_quarantine(qid)
        assert q_record["status"] == HOLApprovalStatus.APPROVED.value
        assert q_record["one_shot_token"] == "CONSUMED"
    finally:
        daemon.stop()



