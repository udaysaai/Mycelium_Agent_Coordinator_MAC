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
