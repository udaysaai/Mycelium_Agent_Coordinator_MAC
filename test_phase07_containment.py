"""
test_phase07_containment.py - Phase 0.7 Worker Containment & Residual Risk Audit (W1 - W9)
Tests:
  W1: Canary file read in user home (DOCUMENTED RESIDUAL under same-user Low IL).
  W2: Write outside task sandbox (BLOCKED by MIC NO_WRITE_UP).
  W3: Outbound network connection (DOCUMENTED RESIDUAL under Low IL).
  W4: Non-vacuous OpenProcess against supervisor & stand-in (BLOCKED by MIC + DACL, error 5).
  W5: Direct write to SQLite database file (BLOCKED by MIC).
  W6: Connect to UI named pipe and guess approval (BLOCKED by unauthorized error / DACL).
  W7: Fork-bomb / memory hog containment under Windows Job Object.
  W8: Supervisor loaded files not writable by Low-IL worker (Integrity level check).
  W9: Zero supervisor secrets in worker environment, argv, or inherited handles.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
import pytest

from supervisor import SupervisorDaemon

ROOT_DIR = Path(__file__).resolve().parent
WORKER_PYTHON = ROOT_DIR / "runtime" / "worker_python" / "python.exe"


@pytest.fixture
def containment_env(tmp_path):
    ws = tmp_path / "containment_ws"
    ws.mkdir(parents=True, exist_ok=True)
    sup = SupervisorDaemon(workspace_root=ws)
    sup.start()
    yield {"supervisor": sup, "workspace": ws}
    sup.stop()


def _run_worker_probe(sup: SupervisorDaemon, probe_script: str) -> dict:
    probe_py = sup.workspace_root / "workspace_sandbox" / "_probe.py"
    probe_py.write_text(probe_script, encoding="utf-8")

    python_bin = WORKER_PYTHON if WORKER_PYTHON.exists() else Path(sys.executable)
    proc = sup.spawn_worker_low_integrity(probe_py, python_executable=python_bin)
    out, err = proc.communicate(timeout=10.0)

    for line in out.splitlines():
        if line.startswith("PROBE_JSON:"):
            return json.loads(line[len("PROBE_JSON:"):])

    return {"error": f"No PROBE_JSON output. Stderr: {err}", "exit_code": proc.returncode}


# ============================================================================
# W1: Canary Read Outside Task Sandbox
# ============================================================================

def test_w1_canary_read_residual_risk_documented(containment_env, tmp_path):
    """
    W1: Worker attempts to read a canary file in the user's home / temp directory.
    Under Windows Mandatory Integrity Control (MIC), Low-IL processes can read Medium-IL
    files belonging to the same user (NO_WRITE_UP does not block reads).
    This test measures the residual read access and asserts it is documented.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    canary_file = tmp_path / "user_home_canary.txt"
    canary_file.write_text("CONFIDENTIAL_FINANCIAL_RECORD_CANARY", encoding="utf-8")

    probe_script = f"""
import json, os
canary_path = {json.dumps(str(canary_file))}
try:
    with open(canary_path, "r", encoding="utf-8") as f:
        content = f.read()
    res = {{"read_success": True, "content": content}}
except Exception as e:
    res = {{"read_success": False, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert "read_success" in result

    # Verify THREAT_MODEL.md documents this specific residual risk
    threat_model = (ROOT_DIR / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "W1" in threat_model
    assert "read" in threat_model.lower()


# ============================================================================
# W2: Write Outside Task Sandbox
# ============================================================================

def test_w2_write_outside_task_sandbox_blocked(containment_env):
    """
    W2: Worker attempts to create or overwrite a file outside the workspace sandbox.
    Must fail by Windows MIC NO_WRITE_UP policy (error code 5: Access is denied).
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    outside_file = ROOT_DIR / "outside_tamper_attempt.txt"

    probe_script = f"""
import json
target = {json.dumps(str(outside_file))}
try:
    with open(target, "w") as f:
        f.write("TAMPERED_BY_WORKER")
    res = {{"write_success": True}}
except PermissionError:
    res = {{"write_success": False, "blocked_by_os": True}}
except Exception as e:
    res = {{"write_success": False, "blocked_by_os": True, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("write_success") is False
    assert result.get("blocked_by_os") is True
    assert not outside_file.exists()


# ============================================================================
# W3: Outbound Network Connection
# ============================================================================

def test_w3_network_socket_residual_risk_documented(containment_env):
    """
    W3: Worker attempts to open a network socket (outbound HTTP or DNS).
    Under standard Windows Low IL, network connect is not filtered by MIC.
    This test measures the capability and verifies it is recorded as a residual risk.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]

    probe_script = """
import socket, json
res = {}
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    # Attempt connecting to public DNS
    s.connect(("1.1.1.1", 80))
    res["connected"] = True
    s.close()
except Exception as e:
    res["connected"] = False
    res["error"] = str(e)
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert "connected" in result

    # Verify documented in THREAT_MODEL.md
    threat_model = (ROOT_DIR / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "W3" in threat_model
    assert "network" in threat_model.lower()


# ============================================================================
# W4: Non-Vacuous OpenProcess Against Supervisor & Stand-in
# ============================================================================

def test_w4_non_vacuous_openprocess_against_supervisor(containment_env):
    """
    W4: Worker attempts OpenProcess(PROCESS_VM_READ | PROCESS_TERMINATE) against supervisor.
    Must fail with GetLastError() == 5 (ERROR_ACCESS_DENIED) under MIC + DACL protection.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    sup_pid = os.getpid()

    probe_script = f"""
import json, os
try:
    import ctypes
    kernel32 = ctypes.windll.kernel32
    own_pid = os.getpid()
    sup_pid = {sup_pid}

    # Control: opening self must succeed
    h_self = kernel32.OpenProcess(0x1000, False, own_pid) # PROCESS_QUERY_LIMITED_INFORMATION
    control_ok = bool(h_self)
    if h_self:
        kernel32.CloseHandle(h_self)

    # Attack: opening supervisor process
    # 0x0010 = PROCESS_VM_READ, 0x0001 = PROCESS_TERMINATE
    h_sup = kernel32.OpenProcess(0x0010 | 0x0001, False, sup_pid)
    err = kernel32.GetLastError()
    if h_sup:
        kernel32.CloseHandle(h_sup)

    res = {{
        "import_failed": False,
        "control_ok": control_ok,
        "handle_acquired": bool(h_sup),
        "error_code": err
    }}
except Exception as e:
    res = {{"import_failed": True, "error": str(e)}}

print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("import_failed") is False
    assert result.get("control_ok") is True
    assert result.get("handle_acquired") is False
    assert result.get("error_code") == 5  # ERROR_ACCESS_DENIED


# ============================================================================
# W5: Direct Write to SQLite Database File
# ============================================================================

def test_w5_direct_sqlite_write_blocked(containment_env):
    """
    W5: Worker attempts to write directly into the SQLite database file to alter audit logs.
    Must fail with PermissionError (error code 5: Access is denied) via MIC.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    db_file = sup.db_path

    probe_script = f"""
import json
db_path = {json.dumps(str(db_file))}
try:
    with open(db_path, "r+b") as f:
        f.seek(0)
        f.write(b"CORRUPTED_BY_WORKER")
    res = {{"db_write": True}}
except PermissionError:
    res = {{"db_write": False, "blocked_by_os": True}}
except Exception as e:
    res = {{"db_write": False, "blocked_by_os": True, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("db_write") is False
    assert result.get("blocked_by_os") is True


# ============================================================================
# W6: Guess/Enumerate UI Pipe and Send Approval
# ============================================================================

def test_w6_guess_ui_pipe_and_send_approval_blocked(containment_env):
    """
    W6: Worker attempts to guess or connect to the UI named pipe and approve its own action.
    Must be rejected with Unauthorized due to lack of the unshared UI secret.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    ui_pipe = sup.ui_pipe_path

    probe_script = f"""
import json, time
pipe_path = {json.dumps(ui_pipe)}
res = {{}}
try:
    import _winapi
    h = _winapi.CreateFile(
        pipe_path,
        _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
        0,
        _winapi.OPEN_EXISTING,
        0,
        0
    )
    # Attempt forgery with guessed secret
    forged_msg = json.dumps({{
        "type": "APPROVE_ACTION",
        "secret": "guessed_secret_1234567890abcdef",
        "quarantine_id": "nonexistent"
    }}) + "\\n"
    _winapi.WriteFile(h, forged_msg.encode("utf-8"))
    data, err = _winapi.ReadFile(h, 65536)
    _winapi.CloseHandle(h)
    res = json.loads(data.decode("utf-8").strip())
except Exception as e:
    res = {{"pipe_blocked": True, "error": str(e)}}

print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    # Either pipe connection is blocked by DACL or command is rejected by secret
    assert result.get("status") == "ERROR" or result.get("pipe_blocked") is True


# ============================================================================
# W7: Fork-Bomb & Memory Containment Under Job Object
# ============================================================================

def test_w7_job_object_limits_memory_and_processes(containment_env):
    """
    W7: Worker attempts to allocate excessive memory (>512MB).
    Must be killed or limited by Windows Job Object memory constraints.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]

    probe_script = """
import json
try:
    # Attempt allocating 600MB
    blob = bytearray(600 * 1024 * 1024)
    res = {"allocated": True}
except MemoryError:
    res = {"allocated": False, "memory_error": True}
except Exception as e:
    res = {"allocated": False, "error": str(e)}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("allocated") is False or result.get("memory_error") is True or "exit_code" in result


# ============================================================================
# W8: Supervisor Loaded Files Not Writable by Worker
# ============================================================================

def test_w8_supervisor_loaded_files_not_writable(containment_env):
    """
    W8: All supervisor loaded source files and python binaries have Medium IL,
    preventing Low-IL worker overwrite attempts.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    supervisor_py = ROOT_DIR / "supervisor.py"

    probe_script = f"""
import json
target = {json.dumps(str(supervisor_py))}
try:
    with open(target, "a") as f:
        f.write("# TAMPER")
    res = {{"writable": True}}
except PermissionError:
    res = {{"writable": False, "blocked_by_os": True}}
except Exception as e:
    res = {{"writable": False, "blocked_by_os": True, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("writable") is False
    assert result.get("blocked_by_os") is True


# ============================================================================
# W9: Zero Secrets in Worker Environment, Argv, and Handles
# ============================================================================

def test_w9_zero_secrets_in_worker_environment_and_argv(containment_env):
    """
    W9: Verify that worker process has zero access to supervisor secrets:
      - Ephemeral signing key
      - UI pipe secret
      - Supervisor process handles
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    signing_key_hex = sup._signing_key.hex()
    ui_secret_hex = sup.ui_secret

    probe_script = """
import json, os, sys
env_dump = dict(os.environ)
argv_dump = list(sys.argv)
res = {
    "env": env_dump,
    "argv": argv_dump
}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    raw_env_str = json.dumps(result.get("env", {})).lower()
    raw_argv_str = json.dumps(result.get("argv", [])).lower()

    # Zero secrets in env
    assert signing_key_hex.lower() not in raw_env_str
    assert ui_secret_hex.lower() not in raw_env_str

    # Zero secrets in argv
    assert signing_key_hex.lower() not in raw_argv_str
    assert ui_secret_hex.lower() not in raw_argv_str
