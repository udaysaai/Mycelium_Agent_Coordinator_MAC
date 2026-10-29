"""
test_phase06_boundary_mutations.py - IPC Boundary Path Mutation Killer Tests
Covers Part 3:
  Ensures MUT_07, MUT_08, MUT_09, MUT_10, MUT_12, MUT_13, MUT_14, MUT_15, MUT_16, MUT_17
  are deterministically killed on the IPC boundary test pass (without relying on in-process tests).
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import pytest

from protocol import ActionRequest, HOLApprovalStatus, PrivilegeTier, SafetyTier
from supervisor import SupervisorDaemon
from worker_attacker import WorkerAttacker


@pytest.fixture
def supervisor_ipc_env():
    """Setup supervisor and worker attacker with injectable clock."""
    simulated_time = [100000.0]

    def mock_clock() -> float:
        return simulated_time[0]

    with tempfile.TemporaryDirectory(prefix="mac_boundary_mut_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        sup = SupervisorDaemon(workspace_root=ws_root, clock=mock_clock, use_named_pipes=True)
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
            "workspace": ws_root,
            "clock": simulated_time,
            "mock_clock_fn": mock_clock
        }

        if attacker.sock:
            try:
                attacker.sock.close()
            except Exception:
                pass
        sup.stop()


def test_ipc_kill_mut07_forged_hmac_on_approved_action(supervisor_ipc_env):
    """
    Kills MUT_07_SKIP_HMAC_VERIFY on IPC path:
    Worker checks token validity over IPC; forged HMAC token must fail verification.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]

    # 1. Propose action
    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "shell echo",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo mut07"}
    })
    qid = prop_res["quarantine_id"]

    # 2. UI approval issues token
    valid_token = sup.approve_via_ui_channel(qid)
    assert valid_token is not None

    # 3. Worker queries verification of a forged token over IPC
    forged_token = "mac_hmac_" + ("deadbeef" * 8)
    res = attacker._send_request({
        "type": "VERIFY_TOKEN",
        "quarantine_id": qid,
        "token": forged_token
    })

    assert res.get("valid") is False, "Forged HMAC token passed verification over IPC!"


def test_ipc_kill_mut08_argument_tampering_recompute_call_hash(supervisor_ipc_env):
    """
    Kills MUT_08_SKIP_CALL_HASH_RECOMPUTE on IPC path:
    Action for command X is approved, but worker executes with tampered command Y.
    Supervisor must recompute call hash from actual call and reject with exit_code 403.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "safe write",
        "tool_name": "write_workspace_file",
        "payload": {"file_path": "test_mut08.txt", "content": "original content"}
    })
    qid = prop_res["quarantine_id"]
    token = sup.approve_via_ui_channel(qid)
    assert token is not None

    # Worker executes with tampered content
    res = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"file_path": "test_mut08.txt", "content": "TAMPERED_CONTENT"}
    })

    assert res.get("success") is False, "Argument tampering was not detected on IPC path!"
    assert res.get("exit_code") == 403


def test_ipc_kill_mut09_expired_token_rejected_over_ipc(supervisor_ipc_env):
    """
    Kills MUT_09_SKIP_EXPIRY_CHECK on IPC path:
    Token past expiry must be rejected with default-deny (exit_code 403).
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]
    clock_box = supervisor_ipc_env["clock"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "shell echo",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo mut09"}
    })
    qid = prop_res["quarantine_id"]
    token = sup.approve_via_ui_channel(qid)
    assert token is not None

    # Advance clock past 900s expiration
    clock_box[0] += 901.0

    res = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "echo mut09"}
    })

    assert res.get("success") is False, "Expired token execution succeeded over IPC!"
    assert res.get("exit_code") == 403


def test_ipc_kill_mut10_consumed_state_replay_rejected_over_ipc(supervisor_ipc_env):
    """
    Kills MUT_10_SKIP_CONSUMED_CHECK on IPC path:
    One-shot token can be executed once; replay of consumed token must fail.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "shell echo",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo mut10"}
    })
    qid = prop_res["quarantine_id"]
    token = sup.approve_via_ui_channel(qid)
    assert token is not None

    # First execution succeeds
    exec1 = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "echo mut10"}
    })
    assert exec1.get("success") is True, f"First execution failed: {exec1}"

    # Replay attempt must fail
    exec2 = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "echo mut10"}
    })
    assert exec2.get("success") is False, "Replay of consumed token succeeded on IPC path!"
    assert exec2.get("exit_code") == 403


def test_ipc_kill_mut12_worker_channel_rejects_approval(supervisor_ipc_env):
    """
    Kills MUT_12_WORKER_ACCEPT_APPROVE on IPC path:
    Worker channel must strictly reject APPROVE_ACTION messages with 403.
    """
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]
    resp = attacker._send_request({
        "type": "APPROVE_ACTION",
        "quarantine_id": "any-qid",
        "operator_notes": "hacked"
    })
    assert resp.get("status") in ("REJECTED", "ERROR")
    assert resp.get("success") is False
    assert resp.get("exit_code") == 403


def test_ipc_kill_mut13_worker_message_whitelist_bypassed(supervisor_ipc_env):
    """
    Kills MUT_13_WORKER_MSG_WHITELIST on IPC path:
    Unwhitelisted message types must be rejected by the supervisor message loop.
    """
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]
    resp = attacker._send_request({
        "type": "UNREGISTERED_WORKER_COMMAND",
        "secret": attacker.worker_secret
    })
    assert resp.get("status") == "ERROR"
    assert "Unknown message type" in resp.get("message", "")


def test_ipc_kill_mut14_ui_secret_not_verified_on_approval(supervisor_ipc_env):
    """
    Kills MUT_14_UI_SECRET_CHECK on IPC path:
    Connecting to UI channel with invalid/missing secret must be rejected.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]

    res = attacker.attack_c4_ui_channel_connect_attempt(sup.ui_port, "qid-mut14")
    assert res.get("approved") is False, "UI channel accepted approval without valid UI secret!"


def test_ipc_kill_mut15_sandbox_path_containment_in_supervisor(supervisor_ipc_env):
    """
    Kills MUT_15_PATH_CONTAINMENT on IPC path:
    Junction breakout inside workspace_sandbox pointing outside must be rejected.
    """
    if sys.platform != "win32":
        pytest.skip("Directory junction test requires Windows platform")

    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]
    ws_root = supervisor_ipc_env["workspace"]

    outside_dir = ws_root.parent / "outside_junc_mut15"
    outside_dir.mkdir(parents=True, exist_ok=True)
    (outside_dir / "escaped.txt").unlink(missing_ok=True)
    junc_path = ws_root / "workspace_sandbox" / "junc_link"

    cmd = f'cmd /c mklink /J "{junc_path}" "{outside_dir}"'
    subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if not junc_path.exists():
        pytest.skip("mklink /J failed or permission denied")

    resp = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "write through junction",
        "tool_name": "sandboxed_file_writer",
        "payload": {"file_path": "junc_link/escaped.txt", "content": "breach"}
    })

    assert resp.get("success") is False, "Directory junction breakout succeeded over IPC!"
    assert not (outside_dir / "escaped.txt").exists(), "File was written outside sandbox via junction!"


def test_ipc_kill_mut16_state_integrity_check_before_execution(supervisor_ipc_env):
    """
    Kills MUT_16_STATE_INTEGRITY on IPC path:
    Direct SQLite modification of operator notes before execution must be detected
    by supervisor state integrity verification and aborted with 403.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "shell echo",
        "tool_name": "execute_shell_command",
        "payload": {"command": "echo mut16"}
    })
    qid = prop_res["quarantine_id"]
    token = sup.approve_via_ui_channel(qid)
    assert token is not None

    # Attacker directly alters SQLite state file (modifies operator notes)
    conn = sqlite3.connect(str(sup.db_path))
    try:
        conn.execute("UPDATE quarantines SET operator_notes = 'TAMPERED_OPERATOR_NOTES' WHERE quarantine_id = ?", (qid,))
        conn.commit()
    finally:
        conn.close()

    # Worker attempts execution
    res = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "echo mut16"}
    })

    assert res.get("success") is False, "Execution proceeded despite corrupted database state!"
    assert res.get("exit_code") == 403


def test_ipc_kill_mut17_shell_command_outside_allowlist(supervisor_ipc_env):
    """
    Kills MUT_17_SHELL_ALLOWLIST on IPC path:
    Shell commands outside the supervisor allowlist (e.g. powershell -enc) must be rejected with 403.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]

    prop_res = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "run unwhitelisted powershell command",
        "tool_name": "execute_shell_command",
        "payload": {"command": "powershell -enc dGVzdA=="}
    })
    qid = prop_res["quarantine_id"]
    token = sup.approve_via_ui_channel(qid)
    assert token is not None

    # Execute approved request
    res = attacker._send_request({
        "type": "EXECUTE_APPROVED",
        "quarantine_id": qid,
        "one_shot_token": token,
        "payload": {"command": "powershell -enc dGVzdA=="}
    })

    assert res.get("success") is False, "Unwhitelisted shell command succeeded on IPC path!"
    assert res.get("exit_code") == 403


def test_ipc_kill_mut11_unknown_tool_defaults_to_t2(supervisor_ipc_env):
    """
    Kills MUT_11_UNKNOWN_TOOL_AS_T0 on IPC path:
    Unregistered capabilities must be quarantined as T2.
    """
    attacker: WorkerAttacker = supervisor_ipc_env["attacker"]
    resp = attacker._send_request({
        "type": "PROPOSE_ACTION",
        "intent": "run unregistered capability",
        "tool_name": "unregistered_mesh_tool_xyz",
        "payload": {"param": "val"}
    })
    assert resp.get("requires_quarantine") is True, "Unknown capability bypassed T2 quarantine!"
    assert resp.get("status") == "QUARANTINED"


def test_ipc_kill_mut01_and_mut03_verifier_tampered_hash(supervisor_ipc_env):
    """
    Kills MUT_01_ALWAYS_PASS and MUT_03_SKIP_HASH_COMPARE on boundary path:
    Verifier must reject hash mismatches.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    diff_file = sup.workspace_root / "diff.txt"
    diff_file.write_text("Hello World!", encoding="utf-8")
    receipt = sup.verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "diff.txt", "content": "Hello Vorld!"},
        raw_output=True,
        request_id="req-mut01-03"
    )
    assert receipt.verified is False, "Verifier accepted mismatched hash!"


def test_ipc_kill_mut02_verifier_missing_file(supervisor_ipc_env):
    """
    Kills MUT_02_SKIP_EXISTENCE on boundary path:
    Verifier must reject nonexistent files.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    receipt = sup.verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "nonexistent_file_xyz.txt", "content": "data"},
        raw_output=True,
        request_id="req-mut02"
    )
    assert receipt.verified is False, "Verifier accepted nonexistent file!"


def test_ipc_kill_mut04_verifier_size_check(supervisor_ipc_env):
    """
    Kills MUT_04_SKIP_SIZE_CHECK on boundary path:
    Verifier must reject files under min_bytes threshold.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    target = sup.workspace_root / "small.txt"
    target.write_text("123", encoding="utf-8")
    from protocol import TaskContract, TierLevel
    contract = TaskContract(
        contractId="c-size",
        goal="test size",
        constraints={},
        successPredicate={"min_bytes": 100},
        tierCeiling=TierLevel.T1
    )
    receipt = sup.verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "small.txt", "content": "123"},
        raw_output=True,
        request_id="req-mut04",
        contract=contract
    )
    assert receipt.verified is False, "Verifier accepted file below min_bytes threshold!"


def test_ipc_kill_mut05_verifier_shell_exit_code(supervisor_ipc_env):
    """
    Kills MUT_05_SKIP_SHELL_EXIT_CHECK on boundary path:
    Verifier must reject non-zero exit codes.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    receipt = sup.verifier.verify_action(
        tool_name="execute_shell_command",
        payload={"command": "exit 1"},
        raw_output={"exitCode": 1, "stdout": "", "stderr": "error"},
        request_id="req-mut05"
    )
    assert receipt.verified is False, "Verifier marked nonzero exit code as verified!"


def test_ipc_kill_mut06_verifier_binary_crlf_leak(supervisor_ipc_env):
    """
    Kills MUT_06_BINARY_CRLF_LEAK on boundary path:
    Verifier must not normalize CRLF on binary payloads.
    """
    sup: SupervisorDaemon = supervisor_ipc_env["supervisor"]
    bin_file = sup.workspace_root / "payload.bin"
    bin_file.write_bytes(b"DATA\r\nMORE")
    receipt = sup.verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "payload.bin", "content": "DATA\nMORE"},
        raw_output=True,
        request_id="req-mut06",
        is_binary=True
    )
    assert receipt.verified is False
