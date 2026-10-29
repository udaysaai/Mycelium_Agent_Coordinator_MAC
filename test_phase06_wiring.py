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
    import win32api
    import win32file
    h = win32file.CreateFile(
        pipe_path,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None,
        win32file.OPEN_EXISTING,
        0, None
    )
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

