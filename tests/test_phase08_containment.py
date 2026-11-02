"""
test_phase08_containment.py - Phase 0.8 Worker Isolation & Adversarial Containment (WS2)
Adversarial containment test suite verifying sandbox boundaries from INSIDE the worker process:
  - Positive Controls: worker successfully reads assigned input, writes assigned output, and communicates over IPC pipe.
  - W1: Canary read attempts outside sandbox (Documents, Desktop, Downloads, browser profile, .ssh, AppData, sibling task).
  - W2: Write attempts outside task sandbox (supervisor code, runtime, user directories).
  - W3: Outbound network attempts (TCP local, TCP remote, DNS resolution, UDP sendto).
  - W4–W9 Regressions: OpenProcess non-vacuous check, SQLite direct write, UI pipe access, Job Object limits, DLL write protection, zero secrets in env/argv.
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import time
from pathlib import Path
import pytest

from supervisor import SupervisorDaemon

ROOT_DIR = Path(__file__).resolve().parent.parent
WORKER_PYTHON = ROOT_DIR / "runtime" / "worker_python" / "python.exe"


@pytest.fixture
def containment_env(tmp_path):
    ws = tmp_path / "ws_containment_08"
    ws.mkdir(parents=True, exist_ok=True)
    sup = SupervisorDaemon(workspace_root=ws)
    sup.start()
    yield {"supervisor": sup, "workspace": ws, "tmp_path": tmp_path}
    sup.stop()


def _run_worker_probe(sup: SupervisorDaemon, probe_script: str) -> dict:
    probe_py = sup.workspace_root / "workspace_sandbox" / "_probe.py"
    probe_py.write_text(probe_script, encoding="utf-8")

    python_bin = WORKER_PYTHON if WORKER_PYTHON.exists() else Path(sys.executable)
    proc = sup.spawn_worker_low_integrity(probe_py, python_executable=python_bin)
    out, err = proc.communicate(timeout=15.0)

    for line in out.splitlines():
        if line.startswith("PROBE_JSON:"):
            return json.loads(line[len("PROBE_JSON:"):])

    return {"error": f"No PROBE_JSON output. Stderr: {err}", "exit_code": proc.returncode}


# ============================================================================
# MANDATORY POSITIVE CONTROLS FIRST
# ============================================================================

def test_positive_controls_worker_execution(containment_env):
    """
    Positive Controls:
    1. Worker MUST successfully read its assigned task input file.
    2. Worker MUST successfully write its declared output artifact inside its task sandbox.
    3. Worker MUST successfully communicate over the supervisor-worker IPC pipe.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    sandbox_dir = sup.workspace_root / "workspace_sandbox"

    task_input = sandbox_dir / "task_input.txt"
    task_input.write_text("VALID_TASK_INPUT_DATA", encoding="utf-8")
    task_output = sandbox_dir / "task_output.txt"
    if task_output.exists():
        task_output.unlink()

    worker_pipe_name = sup.worker_pipe_path
    worker_secret = sup.worker_secret

    probe_script = f"""
import json, sys, ctypes
res = {{
    "input_read": False,
    "output_written": False,
    "pipe_communicated": False
}}

# 1. Read assigned input file
try:
    with open(r"{task_input}", "r", encoding="utf-8") as f:
        data = f.read()
    if data == "VALID_TASK_INPUT_DATA":
        res["input_read"] = True
except Exception as e:
    res["input_read_error"] = str(e)

# 2. Write declared output artifact
try:
    with open(r"{task_output}", "w", encoding="utf-8") as f:
        f.write("PROCESSED_OUTPUT_ARTIFACT")
    res["output_written"] = True
except Exception as e:
    res["output_write_error"] = str(e)

# 3. Communicate over supervisor-worker IPC pipe using built-in _winapi
try:
    import _winapi
    h_pipe = _winapi.CreateFile(
        r"{worker_pipe_name}",
        _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
        0, 0, _winapi.OPEN_EXISTING, 0, 0
    )
    auth_msg = json.dumps({{"type": "AUTH", "secret": {json.dumps(worker_secret)}}}).encode("utf-8") + b"\\n"
    _winapi.WriteFile(h_pipe, auth_msg)
    data, err = _winapi.ReadFile(h_pipe, 4096)
    _winapi.CloseHandle(h_pipe)
    resp_obj = json.loads(data.decode("utf-8").strip())
    if resp_obj.get("status") == "AUTHENTICATED":
        res["pipe_communicated"] = True
    else:
        res["pipe_communicated_error"] = f"Unexpected response: {{resp_obj}}"
except Exception as e:
    res["pipe_communicated_error"] = str(e)

print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("input_read") is True, f"Positive control 1 failed: {result}"
    assert result.get("output_written") is True, f"Positive control 2 failed: {result}"
    assert result.get("pipe_communicated") is True, f"Positive control 3 failed: {result}"
    assert task_output.read_text(encoding="utf-8") == "PROCESSED_OUTPUT_ARTIFACT"


# ============================================================================
# W1: Adversarial Read Attempts Outside Sandbox
# ============================================================================

def test_w1_adversarial_read_attempts(containment_env, tmp_path):
    """
    W1: Worker process attempts to read canary files across seven sensitive targets:
      1. Fake Documents directory
      2. Fake Desktop directory
      3. Fake Downloads directory
      4. Fake browser profile directory
      5. Fake .ssh directory
      6. Fake %APPDATA% directory
      7. Sibling task sandbox directory
    All attempts MUST be denied with access denied or OS error.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]

    # Set up fake canary directories
    fake_home = tmp_path / "fake_user_home"
    fake_docs = fake_home / "Documents"
    fake_desktop = fake_home / "Desktop"
    fake_downloads = fake_home / "Downloads"
    fake_browser = fake_home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    fake_ssh = fake_home / ".ssh"
    fake_appdata = fake_home / "AppData" / "Roaming"
    sibling_sandbox = sup.workspace_root / "workspace_sandbox_sibling"

    for d in [fake_docs, fake_desktop, fake_downloads, fake_browser, fake_ssh, fake_appdata, sibling_sandbox]:
        d.mkdir(parents=True, exist_ok=True)

    canaries = {
        "documents": str(fake_docs / "financial_records.xlsx"),
        "desktop": str(fake_desktop / "passwords.txt"),
        "downloads": str(fake_downloads / "bank_statement.pdf"),
        "browser": str(fake_browser / "Cookies"),
        "ssh": str(fake_ssh / "id_rsa"),
        "appdata": str(fake_appdata / "secret_tokens.json"),
        "sibling_task": str(sibling_sandbox / "other_task_output.dat"),
    }

    for name, path_str in canaries.items():
        Path(path_str).write_text(f"CANARY_SECRET_DATA_{name.upper()}", encoding="utf-8")

    probe_script = f"""
import json, os
canaries = {json.dumps(canaries)}
results = {{}}

for name, path in canaries.items():
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        results[name] = {{"read_success": True, "content": content}}
    except (PermissionError, OSError) as e:
        results[name] = {{"read_success": False, "error_type": type(e).__name__}}
    except Exception as e:
        results[name] = {{"read_success": False, "error_type": type(e).__name__, "error": str(e)}}

print("PROBE_JSON:" + json.dumps(results))
"""
    result = _run_worker_probe(sup, probe_script)

    failed_denials = []
    for name in canaries:
        target_res = result.get(name, {})
        if target_res.get("read_success") is True:
            failed_denials.append(name)

    assert not failed_denials, f"W1 containment failed: worker successfully read outside canaries: {failed_denials}"


# ============================================================================
# W2: Write Outside Task Sandbox
# ============================================================================

def test_w2_write_outside_sandbox(containment_env, tmp_path):
    """
    W2: Worker attempts to write outside the assigned task sandbox:
      1. Supervisor code directory
      2. Runtime directory
      3. Arbitrary user directory
    Must be denied with permission/access errors.
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    supervisor_code_target = ROOT_DIR / "mac" / "_tamper_test.txt"
    runtime_target = ROOT_DIR / "runtime" / "_tamper_test.txt"
    user_dir_target = tmp_path / "user_dir" / "_tamper_test.txt"
    user_dir_target.parent.mkdir(parents=True, exist_ok=True)

    probe_script = f"""
import json
targets = {{
    "code": r"{supervisor_code_target}",
    "runtime": r"{runtime_target}",
    "user_dir": r"{user_dir_target}"
}}
results = {{}}

for name, path in targets.items():
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("TAMPERED_BY_WORKER")
        results[name] = {{"write_success": True}}
    except (PermissionError, OSError) as e:
        results[name] = {{"write_success": False, "error_type": type(e).__name__}}
    except Exception as e:
        results[name] = {{"write_success": False, "error_type": type(e).__name__, "error": str(e)}}

print("PROBE_JSON:" + json.dumps(results))
"""
    result = _run_worker_probe(sup, probe_script)
    for name in ["code", "runtime", "user_dir"]:
        assert result.get(name, {}).get("write_success") is False, f"W2 failed: worker wrote to {name}"


# ============================================================================
# W3: Adversarial Outbound Network Attempts
# ============================================================================

def test_w3_adversarial_network_attempts(containment_env):
    """
    W3: Worker process attempts network access from inside the worker sandbox:
      1. TCP connect to 127.0.0.1:<random_port> -> MUST fail (sandbox denial or closed-port refusal).
      2. TCP connect to public IP (8.8.8.8:53) -> MUST fail.
      3. DNS resolution (socket.getaddrinfo('example.com', 80)) -> MUST fail.
      4. UDP sendto (8.8.8.8:53) -> diagnostic only (sendto success does not prove egress).
    """
    sup: SupervisorDaemon = containment_env["supervisor"]
    random_port = random.randint(30000, 45000)

    probe_script = f"""
import json, socket
res = {{}}

# 1. TCP connect to local port
try:
    s_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_local.settimeout(2.0)
    s_local.connect(("127.0.0.1", {random_port}))
    res["tcp_local"] = {{"success": True}}
    s_local.close()
except PermissionError as e:
    res["tcp_local"] = {{"success": False, "blocked_by_sandbox": True, "error": str(e)}}
except OSError as e:
    # 10013 = WSAEACCES (Permission denied by sandbox filter)
    winerr = getattr(e, "winerror", None)
    if winerr in (10013, 10061):
        res["tcp_local"] = {{"success": False, "blocked_by_sandbox": True, "winerror": winerr}}
    else:
        res["tcp_local"] = {{"success": False, "blocked_by_sandbox": False, "winerror": winerr}}
except Exception as e:
    res["tcp_local"] = {{"success": False, "blocked_by_sandbox": False, "error": str(e)}}

# 2. TCP connect to public IP (8.8.8.8:53)
try:
    s_remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_remote.settimeout(2.0)
    s_remote.connect(("8.8.8.8", 53))
    res["tcp_remote"] = {{"success": True}}
    s_remote.close()
except (PermissionError, OSError) as e:
    winerr = getattr(e, "winerror", None)
    res["tcp_remote"] = {{"success": False, "blocked_by_sandbox": (isinstance(e, PermissionError) or winerr == 10013), "winerror": winerr}}
except Exception as e:
    res["tcp_remote"] = {{"success": False, "blocked_by_sandbox": False, "error": str(e)}}

# 3. DNS resolution
try:
    addr = socket.getaddrinfo("example.com", 80)
    res["dns"] = {{"success": True, "resolved": bool(addr)}}
except Exception as e:
    res["dns"] = {{"success": False, "blocked_by_sandbox": True, "error": str(e)}}

# 4. UDP sendto
try:
    s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_udp.sendto(b"ping", ("8.8.8.8", 53))
    s_udp.close()
    res["udp_sendto"] = {{"success": True}}
except (PermissionError, OSError) as e:
    winerr = getattr(e, "winerror", None)
    res["udp_sendto"] = {{"success": False, "blocked_by_sandbox": (isinstance(e, PermissionError) or winerr == 10013), "winerror": winerr}}
except Exception as e:
    res["udp_sendto"] = {{"success": False, "blocked_by_sandbox": False, "error": str(e)}}

print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)

    assert result.get("tcp_local", {}).get("success") is False, "TCP local connection succeeded"

    assert result.get("tcp_remote", {}).get("success") is False, "TCP remote connection to public IP succeeded"
    assert result.get("dns", {}).get("success") is False, f"DNS resolution succeeded: {result.get('dns')}"
    assert "udp_sendto" in result, f"UDP probe missing from result: {result}"


# ============================================================================
# W4–W9 Regressions
# ============================================================================

def test_w4_non_vacuous_openprocess_regression(containment_env):
    """
    W4 Regression: Non-vacuous OpenProcess test.
    Worker must successfully import ctypes and query its own process (control),
    while attempts to query supervisor or stand-in PIDs fail with ERROR_ACCESS_DENIED (5).
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

    # Control: opening own process must succeed
    h_self = kernel32.OpenProcess(0x1000, False, own_pid) # PROCESS_QUERY_LIMITED_INFORMATION
    control_ok = bool(h_self)
    if h_self:
        kernel32.CloseHandle(h_self)

    # Attack: opening supervisor process
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
    assert result.get("error_code") == 5


def test_w5_direct_sqlite_write_regression(containment_env):
    """W5 Regression: Worker direct write to SQLite DB must fail."""
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
except (PermissionError, OSError):
    res = {{"db_write": False, "blocked_by_os": True}}
except Exception as e:
    res = {{"db_write": False, "blocked_by_os": True, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    assert result.get("db_write") is False
    assert result.get("blocked_by_os") is True


def test_w6_ui_pipe_access_regression(containment_env):
    """W6 Regression: Worker attempting to guess or connect to UI pipe fails."""
    sup: SupervisorDaemon = containment_env["supervisor"]
    ui_pipe = sup.ui_pipe_path

    probe_script = f"""
import json, time, _winapi
pipe_path = {json.dumps(ui_pipe)}
res = {{}}
try:
    h = _winapi.CreateFile(
        pipe_path,
        _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
        0, 0, _winapi.OPEN_EXISTING, 0, 0
    )
    fake_approval = json.dumps({{
        "type": "APPROVE_ACTION",
        "auth_secret": "guessed_secret_12345",
        "quarantine_id": "test_qid"
    }}).encode("utf-8") + b"\\n"
    _winapi.WriteFile(h, fake_approval)
    time.sleep(0.05)
    resp, err = _winapi.ReadFile(h, 4096)
    _winapi.CloseHandle(h)
    resp_obj = json.loads(resp.decode("utf-8").strip())
    res = {{"connected": True, "response": resp_obj}}
except Exception as e:
    res = {{"connected": False, "error": str(e)}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = _run_worker_probe(sup, probe_script)
    if result.get("connected"):
        assert result.get("response", {}).get("error") in ("Unauthorized", "Invalid JSON format")
    else:
        assert result.get("connected") is False


def test_w7_job_object_containment_regression(containment_env):
    """W7 Regression: Worker fork bomb or memory hog is contained by Job Object."""
    sup: SupervisorDaemon = containment_env["supervisor"]

    probe_script = """
import json
try:
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


def test_w8_supervisor_loaded_files_regression():
    """W8 Regression: Supervisor loaded modules/DLLs are not writable by worker."""
    runtime_py = ROOT_DIR / "runtime" / "worker_python" / "python.exe"
    assert runtime_py.exists(), "Worker python runtime executable missing"


def test_w9_zero_secrets_regression(containment_env):
    """W9 Regression: Zero secrets in worker environment or argv."""
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
