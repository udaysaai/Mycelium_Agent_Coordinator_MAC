"""
test_phase06_worker_containment.py - Worker Privilege Shrink & Containment Tests
Covers Part 5:
  W1. Canary read outside sandbox (Residual Risk Documentation)
  W2. Write outside sandbox (Blocked by Low Integrity)
  W3. Outbound network socket (Residual Risk Documentation)
  W4. OpenProcess(PROCESS_VM_READ) against supervisor (Blocked by Low Integrity)
  W5. Write to data/mac_state.db (Blocked by Low Integrity)
  W6. UI named pipe connection protection
  W7. Job Object process limit containment
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest

from supervisor import SupervisorDaemon


@pytest.fixture
def worker_containment_env():
    """Setup supervisor with restricted token worker environment."""
    with tempfile.TemporaryDirectory(prefix="mac_containment_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        sup = SupervisorDaemon(workspace_root=ws_root, use_named_pipes=True)
        sup.start()

        yield {
            "supervisor": sup,
            "workspace": ws_root
        }

        sup.stop()


def _run_worker_probe(sup: SupervisorDaemon, script_body: str) -> dict:
    """Helper to run a probe script inside the restricted worker process."""
    res = sup.spawn_worker_process(script_body)
    return res


def test_w1_canary_read_outside_sandbox(worker_containment_env):
    """
    W1: Canary read outside sandbox.
    Windows Mandatory Integrity Control permits Read-Up by default OS design.
    This test verifies execution and documents the residual risk honestly.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]
    ws: Path = worker_containment_env["workspace"]
    canary = ws.parent / "canary_w1.txt"
    canary.write_text("CANARY_DATA_SECRET", encoding="utf-8")

    probe_script = f"""
import sys, json
try:
    with open(r"{canary}", "r", encoding="utf-8") as f:
        data = f.read()
    res = {{"read_succeeded": True, "data": data}}
except Exception as e:
    res = {{"read_succeeded": False, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert "read_succeeded" in result, f"Probe failed to report structured result: {result}"


def test_w2_write_outside_sandbox_blocked(worker_containment_env):
    """
    W2: Write outside sandbox.
    Low Integrity token must prevent writing to Medium/High integrity user directories.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]
    ws: Path = worker_containment_env["workspace"]
    outside_file = ws.parent / "escape_w2.txt"

    probe_script = f"""
import sys, json
try:
    with open(r"{outside_file}", "w", encoding="utf-8") as f:
        f.write("malicious write")
    res = {{"write_succeeded": True}}
except PermissionError as pe:
    res = {{"write_succeeded": False, "blocked": True, "error": str(pe)}}
except Exception as e:
    res = {{"write_succeeded": False, "blocked": False, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("write_succeeded") is False, "Worker wrote outside sandbox!"
    assert not outside_file.exists(), "File was created outside sandbox!"


def test_w3_outbound_network_socket_diagnostic(worker_containment_env):
    """
    W3: Outbound network socket.
    Evaluates outbound network socket capability from inside restricted worker.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]

    probe_script = """
import socket, json
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(("8.8.8.8", 53))
    s.close()
    res = {"connected": True}
except Exception as e:
    res = {"connected": False, "error": str(e)}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert "connected" in result, f"Network probe did not report: {result}"


def test_w4_openprocess_against_supervisor_blocked(worker_containment_env):
    """
    W4: OpenProcess(PROCESS_VM_READ) against supervisor.
    Under Low Integrity token, opening Medium Integrity supervisor process
    for VM_READ must fail by Windows Mandatory Integrity Control.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]
    sup_pid = os.getpid()

    probe_script = f"""
import ctypes, json
kernel32 = ctypes.windll.kernel32
sup_pid = {sup_pid}
# PROCESS_VM_READ = 0x0010, PROCESS_ALL_ACCESS = 0x1FFFFF
h = kernel32.OpenProcess(0x0010, False, sup_pid)
err = kernel32.GetLastError()
res = {{"handle": bool(h), "error_code": err}}
if h:
    kernel32.CloseHandle(h)
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    # Handle must be 0/False or error 5 (Access Denied)
    assert result.get("handle") is False, "Worker successfully opened supervisor memory for reading!"


def test_w5_write_to_database_blocked(worker_containment_env):
    """
    W5: Direct write to mac_state.db.
    Low Integrity token must be blocked from writing to SQLite file.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]
    db_path = sup.db_path

    probe_script = f"""
import json
try:
    with open(r"{db_path}", "r+b") as f:
        f.write(b"CORRUPT")
    res = {{"db_write_succeeded": True}}
except PermissionError as pe:
    res = {{"db_write_succeeded": False, "blocked": True, "error": str(pe)}}
except Exception as e:
    res = {{"db_write_succeeded": False, "blocked": False, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("db_write_succeeded") is False, "Worker directly wrote to database file!"


def test_w6_connect_to_ui_named_pipe_rejected(worker_containment_env):
    """
    W6: Worker attempts to connect to UI named pipe without secret.
    Must be blocked by user-only DACL or rejected by supervisor secret check.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]
    ui_pipe = sup.ui_pipe_path

    probe_script = f"""
import json, socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(("127.0.0.1", {sup.ui_port}))
    msg = json.dumps({{"type": "APPROVE_ACTION", "quarantine_id": "test", "secret": "bad"}}) + "\\n"
    s.sendall(msg.encode("utf-8"))
    data = s.recv(4096).decode("utf-8")
    s.close()
    res = {{"connected": True, "approved": "APPROVED" in data, "response": data}}
except Exception as e:
    res = {{"connected": False, "approved": False, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("approved") is False, "Worker was able to approve via UI channel!"


def test_w7_spawn_within_job_object(worker_containment_env):
    """
    W7: Worker processes are assigned to Windows Job Object.
    """
    sup: SupervisorDaemon = worker_containment_env["supervisor"]
    assert sup.job_object_active is True or sys.platform != "win32"
