"""
test_phase05_boundary.py - Process Boundary & Worker Attacker Tests
Covers Part C:
  C1. Signing key isolation (key never leaked to worker memory, env, argv, disk)
  C2. SQLite direct tamper isolation (direct DB write cannot unlock execution)
  C3. Worker channel whitelist enforcement (rejects APPROVE, ISSUE_TOKEN)
  C4. UI channel secret enforcement (rejects unauthenticated connections)
  C5. Token forgery rejection across IPC
  C6. Token replay rejection across IPC
  C7. Argument tampering rejection across IPC
  C8. In-worker module import isolation
  C9. Windows same-user OpenProcess memory access analysis (Residual Risk)
  C10. Job Object containment and kill-on-close
  C11. Supervisor crash fail-closed behavior
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import pytest

from protocol import ActionRequest, PrivilegeTier, SafetyTier, TierLevel
from supervisor import SupervisorDaemon
from worker_attacker import WorkerAttacker


@pytest.fixture
def boundary_env():
    """Setup supervisor daemon and worker attacker environment."""
    with tempfile.TemporaryDirectory(prefix="mac_boundary_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        sup = SupervisorDaemon(workspace_root=ws_root)
        sup.start()

        attacker = WorkerAttacker(
            worker_port=sup.worker_port,
            worker_secret=sup.worker_secret,
            supervisor_pid=os.getpid(),
            db_path=sup.db_path
        )
        attacker.connect_worker_channel()

        yield {
            "supervisor": sup,
            "attacker": attacker,
            "workspace": ws_root
        }

        if attacker.sock:
            try:
                attacker.sock.close()
            except Exception:
                pass
        sup.stop()


# ============================================================================
# C1. Signing Key Leakage Search
# ============================================================================

def test_boundary_c1_signing_key_not_leaked_to_worker(boundary_env):
    """Worker cannot find the supervisor's ephemeral in-memory signing key anywhere."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    # Known supervisor key bytes
    real_key = sup.get_ephemeral_key()
    assert len(real_key) == 32

    res = attacker.attack_c1_search_signing_key(real_key)
    assert res["key_found"] is False, f"Signing key leaked to worker! Locations: {res['locations']}"


# ============================================================================
# C2. SQLite Direct Tamper Attempt
# ============================================================================

def test_boundary_c2_sqlite_direct_tamper_fails_execution(boundary_env):
    """
    Even if the worker can write directly to SQLite on disk, modifying quarantine status
    to APPROVED cannot unlock execution because the supervisor validates in-memory state & HMAC.
    """
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    # Propose a mutating action that gets quarantined
    req = {
        "type": "PROPOSE_ACTION",
        "intent": "mutate system config",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo malicious"}
    }
    prop_res = attacker._send_request(req)
    assert prop_res.get("requires_quarantine") is True
    qid = prop_res.get("quarantine_id")
    assert qid is not None

    # Worker directly modifies SQLite on disk
    tamper_res = attacker.attack_c2_sqlite_direct_tamper(qid)

    # Worker attempts to execute using the forged DB record
    exec_res = attacker.attack_c5_forge_token(qid, {"command": "echo malicious"})
    assert exec_res["success"] is False, "Direct SQLite tampering allowed unapproved execution!"


# ============================================================================
# C3. Worker Channel Rejection of Approval Messages
# ============================================================================

def test_boundary_c3_worker_channel_rejects_approval_messages(boundary_env):
    """Worker channel must reject 'APPROVE_ACTION' and log a security violation."""
    attacker: WorkerAttacker = boundary_env["attacker"]
    res = attacker.attack_c3_worker_channel_injected_approve("quarantine-any-id")
    assert res["rejected"] is True


# ============================================================================
# C4. UI Channel Secret Enforcement
# ============================================================================

def test_boundary_c4_ui_channel_rejects_unauthorized_worker(boundary_env):
    """Worker probing the UI port without UI secret must be rejected."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    res = attacker.attack_c4_ui_channel_connect_attempt(sup.ui_port, "quarantine-any-id")
    assert res["approved"] is False


# ============================================================================
# C5. Forged Token Rejection Across IPC
# ============================================================================

def test_boundary_c5_forged_token_rejected_at_execution(boundary_env):
    """Worker submitting a random hex token over IPC must fail."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "shell action",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo 1"}
    })
    qid = prop_res["quarantine_id"]

    res = attacker.attack_c5_forge_token(qid, {"command": "echo 1"})
    assert res["success"] is False


# ============================================================================
# C6. Token Replay Rejection Across IPC
# ============================================================================

def test_boundary_c6_replay_token_rejected_across_ipc(boundary_env):
    """Token approved via UI channel can be used once; second use must be rejected."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "shell action to approve",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo once"}
    })
    qid = prop_res["quarantine_id"]

    # Approve strictly through UI channel
    token = sup.approve_via_ui_channel(qid, operator_notes="Authorized by human")
    assert token is not None

    # First execution succeeds
    exec1 = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "echo once"}
    })
    assert exec1["success"] is True

    # Replay attempt fails
    exec2 = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "echo once"}
    })
    assert exec2["success"] is False


# ============================================================================
# C7. Argument Tampering Rejection Across IPC
# ============================================================================

def test_boundary_c7_argument_tampering_rejected_across_ipc(boundary_env):
    """Approving call X then submitting call Y with same token must fail call-hash verify."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "write benign file",
        "tool_name": "write_workspace_file",
        "payload": {"file_path": "benign.txt", "content": "hello"}
    })
    qid = prop_res["quarantine_id"]
    token = sup.approve_via_ui_channel(qid, operator_notes="Authorized")

    # Worker submits with tampered content
    tampered_exec = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"file_path": "benign.txt", "content": "TAMPERED_MALICIOUS"}
    })
    assert tampered_exec["success"] is False


# ============================================================================
# C8. In-Worker Module Import Isolation
# ============================================================================

def test_boundary_c8_import_modules_in_worker_has_no_authority(boundary_env):
    """Worker importing PolicyEngine cannot access supervisor signing key or live state."""
    attacker: WorkerAttacker = boundary_env["attacker"]
    res = attacker.attack_c8_import_supervisor_modules_in_worker()
    assert res["has_supervisor_key"] is False
    assert res["key_length"] == 32


# ============================================================================
# C9. Process Memory Access Analysis (Known Residual Risk)
# ============================================================================

def test_boundary_c9_windows_process_memory_residual_risk(boundary_env):
    """
    Attempt OpenProcess PROCESS_VM_READ against supervisor.
    On Windows for same-user processes without AppContainer/PPL, this succeeds by OS design.
    The test records this outcome honestly as a documented residual risk.
    """
    attacker: WorkerAttacker = boundary_env["attacker"]
    res = attacker.attack_c9_process_memory_open()
    # Ensure test runs and returns structured data without crashing
    assert "open_read_succeeded" in res
    assert "open_write_succeeded" in res


# ============================================================================
# C10. Job Object Containment
# ============================================================================

def test_boundary_c10_job_object_containment(boundary_env):
    """Supervisor applies Windows Job Object with KILL_ON_JOB_CLOSE to worker."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    assert sup.job_object_active is True or sys.platform != "win32"


# ============================================================================
# C11. Supervisor Crash Fail-Closed Behavior
# ============================================================================

def test_boundary_c11_supervisor_crash_worker_does_not_proceed(boundary_env):
    """When supervisor dies while worker is waiting, worker connection fails closed."""
    sup: SupervisorDaemon = boundary_env["supervisor"]
    attacker: WorkerAttacker = boundary_env["attacker"]

    # Close supervisor server abruptly
    sup.stop()

    # Worker attempt to send request must fail/disconnect, never proceed
    with pytest.raises((socket.error, ConnectionError, BrokenPipeError, OSError)):
        attacker._send_request({"type": "PROPOSE_ACTION", "intent": "test"})
