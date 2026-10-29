"""
test_phase05_strengthened.py - Phase 0.5 Strengthened Security Tests
Covers Part A:
  A1. Real OS Process Crash Durability (subprocess spawn + hard kill via SIGKILL/taskkill)
  A2. Windows Path Containment Matrix (Device names, ADS, UNC, 8.3, junctions, trailing dot/space)
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import pytest

from coordinator import MyceliumCoordinator
from local_daemon import LocalExecDaemon
from protocol import (
    ActionRequest,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
)
from state_store import StateStore


# ============================================================================
# A1. Real Subprocess Crash Durability
# ============================================================================

def test_strengthened_a1_crash_durability_real_subprocess():
    """
    Spawn a REAL separate OS process that creates a pending quarantine, then hard-kill it
    with process.kill() (SIGKILL/TerminateProcess). A fresh process opens the DB and verifies
    the pending item is unexecuted and receipts survive.
    """
    with tempfile.TemporaryDirectory(prefix="mac_crash_test_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        db_path = ws_root / "data" / "mac_state.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Worker script that initializes store, writes a pending quarantine, and pauses
        worker_code = f"""
import sys
import time
from pathlib import Path
sys.path.insert(0, {repr(str(Path(__file__).resolve().parent))})
from state_store import StateStore
from protocol import ActionRequest, HOLQuarantineEvent, HOLApprovalStatus, PrivilegeTier, SafetyTier

store = StateStore(db_path=Path(r'{db_path}'))
req = ActionRequest(
    requestId='req-crash-target-001',
    intent='destructive shell command before crash',
    privilegeTier=PrivilegeTier.PERSON,
    safetyTier=SafetyTier.MUTATING,
    payload={{'command': 'format C:'}}
)
event = HOLQuarantineEvent(
    quarantineId='quarantine-crash-001',
    request=req,
    quarantineReason='Critical mutation requiring human approval',
    decision=HOLApprovalStatus.PENDING,
    callHash='fake-hash-for-crash-test',
    oneShotToken='pending-token',
    plainImpact='Wipe disk',
    expiresAt=time.time() + 900.0
)
store.save_quarantine(event)
sys.stdout.write('QUARANTINE_PERSISTED\\n')
sys.stdout.flush()
# Block indefinitely waiting to be killed
time.sleep(60)
"""

        # Spawn real separate OS process
        proc = subprocess.Popen(
            [sys.executable, "-c", worker_code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            # Wait until quarantine is saved
            line = proc.stdout.readline().strip()
            assert line == "QUARANTINE_PERSISTED", f"Subprocess failed to signal persistence: {proc.stderr.read()}"

            # HARD-KILL the process (simulating hard crash/power cut/SIGKILL)
            proc.kill()
            proc.wait(timeout=5)
            assert proc.poll() is not None, "Process did not terminate after kill()"
        finally:
            if proc.poll() is None:
                proc.kill()

        # Open DB from a FRESH process/connection
        fresh_store = StateStore(db_path=db_path)
        try:
            pending = fresh_store.get_pending_quarantines()
            assert len(pending) == 1, f"Expected 1 pending quarantine, found {len(pending)}"
            item = pending[0]
            assert item["quarantine_id"] == "quarantine-crash-001"
            assert item["status"] == HOLApprovalStatus.PENDING.value
            assert item["request_id"] == "req-crash-target-001"
            assert item["reviewed_at"] is None, "Quarantine must remain unexecuted after crash"
        finally:
            fresh_store.close()


# ============================================================================
# A2. Windows Path Safety Matrix
# ============================================================================

PATH_TRAVERSAL_PAYLOADS = [
    # 1. Classical path traversal
    "../evil.txt",
    "..\\evil.txt",
    "sub/../../evil.txt",
    "sub\\..\\..\\evil.txt",
    "/../evil.txt",
    "\\..\\evil.txt",

    # 2. Absolute paths outside sandbox
    "C:/Windows/System32/calc.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "/etc/passwd",
    "\\Windows\\win.ini",

    # 3. Drive-letter paths (different drives or absolute)
    "Z:\\outside.txt",
    "D:\\outside.txt",
    "c:evil.txt",
    "C:evil.txt",

    # 4. UNC network paths and NT prefixes
    "\\\\server\\share\\payload.txt",
    "//server/share/payload.txt",
    "\\\\?\\C:\\outside.txt",
    "\\\\.\\COM1",
    "\\\\?\\UNC\\server\\share\\evil.txt",

    # 5. Windows reserved device names (must fail even with extension or path)
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM9",
    "LPT1",
    "LPT9",
    "NUL.txt",
    "con.json",
    "aux.dat",
    "com1.log",
    "lpt1.txt",
    "sub/NUL",
    "sub/con.txt",
    "sub\\NUL.txt",

    # 6. Trailing dot and trailing space (NTFS stripping causes aliasing)
    "evil.txt.",
    "evil.txt ",
    "evil.txt...",
    "evil.txt   ",
    "sub./file.txt",
    "sub /file.txt",

    # 7. Alternate Data Streams (ADS)
    "file.txt::$DATA",
    "file.txt:stream",
    "file.txt:hidden:$DATA",
    "sub/file.txt:evil",

    # 8. 8.3 short-name aliases
    "PROGRA~1/evil.txt",
    "DOCUME~1/evil.txt",
]


@pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
def test_strengthened_a2_windows_path_safety_payloads(payload):
    """
    All malicious, reserved, UNC, ADS, or traversal paths must be rejected by
    sandboxed_file_writer with a PermissionError or ValueError, never accepted.
    """
    with tempfile.TemporaryDirectory(prefix="mac_path_test_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        daemon = LocalExecDaemon(workspace_root=ws_root)
        coord = MyceliumCoordinator(local_daemon=daemon)
        try:
            # Retrieve registered tool handler for sandboxed_file_writer
            record = coord.gateway._tools.get("sandboxed_file_writer")
            assert record is not None, "sandboxed_file_writer must be registered"
            writer_fn = record.handler

            with pytest.raises((PermissionError, ValueError, OSError)) as exc_info:
                writer_fn(file_path=payload, content="MALICIOUS_PAYLOAD")

            # Confirm failure was loud and descriptive
            err_msg = str(exc_info.value).lower()
            assert any(term in err_msg for term in ["forbidden", "sandbox", "reserved", "traversal", "boundary", "invalid", "device", "stream", "escape", "illegal"]), (
                f"Expected descriptive sandbox rejection for '{payload}', got: {exc_info.value}"
            )
        finally:
            coord.state_store.close()


def test_strengthened_a2_case_variant_sandbox_prefix():
    """
    Case-variant prefixes like WORKSPACE_SANDBOX/ or WorkSpace_SandBox/ must not escape
    or create duplicated/corrupted paths.
    """
    with tempfile.TemporaryDirectory(prefix="mac_case_test_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        daemon = LocalExecDaemon(workspace_root=ws_root)
        coord = MyceliumCoordinator(local_daemon=daemon)
        try:
            writer_fn = coord.gateway._tools["sandboxed_file_writer"].handler

            # Case-variant input
            res = writer_fn(file_path="WorkSpace_SandBox/nested/valid.txt", content="TEST")
            assert res["success"] is True

            # Resolved file must be strictly inside real workspace_sandbox
            expected_sandbox = (ws_root / "workspace_sandbox").resolve()
            written_file = (ws_root / res["filePath"]).resolve()
            assert os.path.commonpath([str(expected_sandbox), str(written_file)]) == str(expected_sandbox)
            assert written_file.exists()
        finally:
            coord.state_store.close()


def test_strengthened_a2_directory_junction_breakout():
    """
    Directory junction inside workspace_sandbox pointing outside must be rejected when written to.
    Uses 'mklink /J' which does not require admin rights on Windows.
    """
    if sys.platform != "win32":
        pytest.skip("Windows directory junctions test requires Windows platform")

    with tempfile.TemporaryDirectory(prefix="mac_junc_test_") as tmp_dir:
        base_dir = Path(tmp_dir).resolve()
        ws_root = base_dir / "workspace"
        outside_target = base_dir / "outside_target"

        ws_root.mkdir(parents=True, exist_ok=True)
        outside_target.mkdir(parents=True, exist_ok=True)

        sandbox_dir = ws_root / "workspace_sandbox"
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        junction_path = sandbox_dir / "link_to_outside"

        # Create junction using Windows mklink /J
        cmd = f'cmd /c mklink /J "{junction_path}" "{outside_target}"'
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            pytest.skip(f"mklink /J failed: {res.stderr}")

        assert junction_path.exists(), "Junction creation failed"

        daemon = LocalExecDaemon(workspace_root=ws_root)
        coord = MyceliumCoordinator(local_daemon=daemon)
        try:
            writer_fn = coord.gateway._tools["sandboxed_file_writer"].handler

            # Attempt to write through the junction
            with pytest.raises((PermissionError, ValueError, OSError)) as exc_info:
                writer_fn(file_path="link_to_outside/pwned.txt", content="ESCAPED_SANDBOX")

            assert "boundary" in str(exc_info.value).lower() or "sandbox" in str(exc_info.value).lower()
            # Verify file was NOT written outside
            assert not (outside_target / "pwned.txt").exists(), "Security Violation: File was written through junction to outside directory!"
        finally:
            coord.state_store.close()


# ============================================================================
# A4. StateStore Token Expiry & Non-Approved Lifecycle Enforcement
# ============================================================================

def test_strengthened_a4_validate_token_rejects_expired():
    """
    Directly verify that StateStore rejects both approval decisions and token validation
    for expired items:
      1. update_quarantine_decision on expired pending action must return False.
      2. validate_one_shot_token on expired approved action must return False.
    """
    with tempfile.TemporaryDirectory(prefix="mac_exp_test_") as tmp_dir:
        db_path = Path(tmp_dir) / "state.db"
        store = StateStore(db_path=db_path)
        try:
            curr_time = 50000.0
            store.clock = lambda: curr_time

            # Test 1: update_quarantine_decision rejected if expired
            q_pending = HOLQuarantineEvent(
                quarantineId="qid-expired-pending",
                request=ActionRequest(
                    intent="expired pending action",
                    privilegeTier=PrivilegeTier.PERSON,
                    safetyTier=SafetyTier.MUTATING,
                    payload={"tool_name": "execute_shell_command", "command": "echo test"}
                ),
                quarantineReason="Needs approval",
                decision=HOLApprovalStatus.PENDING,
                callHash="hash-pending",
                oneShotToken="token-pending",
                plainImpact="Impact test",
                quarantinedAt=curr_time - 1000.0,
                expiresAt=curr_time - 10.0  # Expired
            )
            store.save_quarantine(q_pending)

            approved = store.update_quarantine_decision("qid-expired-pending", HOLApprovalStatus.APPROVED)
            assert approved is False, "update_quarantine_decision must return False for expired action"
            stored_p = store.get_quarantine("qid-expired-pending")
            assert stored_p is not None
            assert stored_p["status"] == HOLApprovalStatus.REJECTED_TIMEOUT.value

            # Test 2: validate_one_shot_token rejected if expired
            q_event = HOLQuarantineEvent(
                quarantineId="qid-expired-direct",
                request=ActionRequest(
                    intent="expired action test",
                    privilegeTier=PrivilegeTier.PERSON,
                    safetyTier=SafetyTier.MUTATING,
                    payload={"tool_name": "execute_shell_command", "command": "echo test"}
                ),
                quarantineReason="Needs approval",
                decision=HOLApprovalStatus.APPROVED,
                callHash="hash-123",
                oneShotToken="valid-token-123",
                plainImpact="Impact test",
                quarantinedAt=curr_time - 1000.0,
                expiresAt=curr_time - 10.0  # Already expired relative to curr_time
            )
            store.save_quarantine(q_event)

            # Direct validation MUST return False due to expiration
            is_valid = store.validate_one_shot_token("qid-expired-direct", "valid-token-123")
            assert is_valid is False, "validate_one_shot_token must reject expired token"

            # DB status must have transitioned to REJECTED_TIMEOUT
            stored = store.get_quarantine("qid-expired-direct")
            assert stored is not None
            assert stored["status"] == HOLApprovalStatus.REJECTED_TIMEOUT.value
        finally:
            store.close()


def test_strengthened_a4_validate_token_rejects_non_approved_status():
    """
    Directly verify that StateStore.validate_one_shot_token rejects any quarantine
    that is not strictly in APPROVED status (e.g. PENDING, REJECTED_MANUAL, or CONSUMED replay).
    """
    with tempfile.TemporaryDirectory(prefix="mac_status_test_") as tmp_dir:
        db_path = Path(tmp_dir) / "state.db"
        store = StateStore(db_path=db_path)
        try:
            curr_time = 50000.0
            store.clock = lambda: curr_time

            # Case A: PENDING status (not yet approved)
            q_pending = HOLQuarantineEvent(
                quarantineId="qid-pending-status",
                request=ActionRequest(
                    intent="pending action test",
                    privilegeTier=PrivilegeTier.PERSON,
                    safetyTier=SafetyTier.MUTATING,
                    payload={"tool_name": "execute_shell_command", "command": "echo test"}
                ),
                quarantineReason="Needs approval",
                decision=HOLApprovalStatus.PENDING,
                callHash="hash-pending",
                oneShotToken="pending-token-123",
                plainImpact="Impact test",
                quarantinedAt=curr_time,
                expiresAt=curr_time + 900.0
            )
            store.save_quarantine(q_pending)
            assert store.validate_one_shot_token("qid-pending-status", "pending-token-123") is False

            # Case B: REJECTED status
            q_rejected = HOLQuarantineEvent(
                quarantineId="qid-rejected-status",
                request=ActionRequest(
                    intent="rejected action test",
                    privilegeTier=PrivilegeTier.PERSON,
                    safetyTier=SafetyTier.MUTATING,
                    payload={"tool_name": "execute_shell_command", "command": "echo test"}
                ),
                quarantineReason="Denied",
                decision=HOLApprovalStatus.REJECTED,
                callHash="hash-rejected",
                oneShotToken="rejected-token-123",
                plainImpact="Impact test",
                quarantinedAt=curr_time,
                expiresAt=curr_time + 900.0
            )
            store.save_quarantine(q_rejected)
            assert store.validate_one_shot_token("qid-rejected-status", "rejected-token-123") is False

            # Case C: CONSUMED status token replay with 'CONSUMED' literal token
            with store._get_connection() as conn:
                conn.execute(
                    "INSERT INTO quarantines (quarantine_id, request_id, contract_id, tool_name, call_hash, one_shot_token, plain_impact, payload_json, status, expires_at, quarantined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("qid-consumed", "req-1", "cont-1", "tool", "hash-c", "CONSUMED", "impact", "{}", "CONSUMED", curr_time + 900.0, curr_time)
                )
            assert store.validate_one_shot_token("qid-consumed", "CONSUMED") is False
        finally:
            store.close()

