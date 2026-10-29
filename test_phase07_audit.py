"""
test_phase07_audit.py - Security Audit Tests for Phase 0.7
Covers:
  1A. Supervisor loaded-files write protection audit
  1B. Non-vacuous W4 OpenProcess testing (requiring ctypes to load, own PID to succeed,
      and supervisor + dummy stand-in calls to fail with Win32 Error 5 ERROR_ACCESS_DENIED)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
import pytest

from supervisor import SupervisorDaemon


@pytest.fixture
def supervisor_audit_env():
    """Setup supervisor with isolated workspace and named pipes."""
    with tempfile.TemporaryDirectory(prefix="mac_audit_") as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        sup = SupervisorDaemon(workspace_root=ws_root, use_named_pipes=True)
        sup.start()

        yield {
            "supervisor": sup,
            "workspace": ws_root
        }

        sup.stop()


def _get_supervisor_loaded_files() -> List[str]:
    """Enumerate executable and DLL paths loaded into the supervisor process."""
    files = set()
    # 1. Python executable
    if sys.executable and os.path.exists(sys.executable):
        files.add(os.path.abspath(sys.executable))

    # 2. Loaded Python modules
    for mod in list(sys.modules.values()):
        f = getattr(mod, "__file__", None)
        if f and os.path.exists(f):
            files.add(os.path.abspath(f))

    # 3. Native Win32 modules / DLLs loaded into process
    if sys.platform == "win32":
        try:
            import win32api
            import win32process
            h_proc = win32api.GetCurrentProcess()
            modules = win32process.EnumProcessModules(h_proc)
            for h_mod in modules:
                mod_name = win32process.GetModuleFileNameEx(h_proc, h_mod)
                if mod_name and os.path.exists(mod_name):
                    files.add(os.path.abspath(mod_name))
        except Exception:
            pass

    return sorted(list(files))


# ============================================================================
# 1A. Supervisor Loaded-Files Write Protection Audit
# ============================================================================

def test_supervisor_loaded_files_not_writable_by_worker(supervisor_audit_env):
    """
    Assert that NO file loaded by the supervisor (executable, modules, DLLs)
    is writable by the worker's token.
    Tests by actually attempting write opens from inside the restricted worker.
    """
    sup: SupervisorDaemon = supervisor_audit_env["supervisor"]
    loaded_files = _get_supervisor_loaded_files()
    assert len(loaded_files) > 0, "Failed to enumerate supervisor loaded files"

    # Pass list of files to worker probe
    probe_script = f"""
import json, sys

paths_to_test = {json.dumps(loaded_files)}
writable_files = []

for p in paths_to_test:
    try:
        # Attempt to open with write access without truncating or altering content
        with open(p, "r+b") as f:
            writable_files.append(p)
    except (PermissionError, OSError):
        pass

res = {{
    "total_tested": len(paths_to_test),
    "writable_files": writable_files,
    "probe_completed": True
}}
print("PROBE_JSON:" + json.dumps(res))
"""
    result = sup.spawn_worker_process(probe_script)
    assert result.get("probe_completed") is True, f"Worker probe failed to run: {result}"
    writable = result.get("writable_files", [])
    assert len(writable) == 0, (
        f"Security Violation: {len(writable)} supervisor files are writable by the worker token! "
        f"Examples: {writable[:5]}"
    )


# ============================================================================
# 1B. Non-Vacuous W4 OpenProcess Testing
# ============================================================================

def test_w4_non_vacuous_openprocess_against_supervisor_and_standin(supervisor_audit_env):
    """
    Non-vacuous W4:
      (a) Worker MUST successfully import ctypes (no swallowing of ImportError).
      (b) Worker MUST successfully call OpenProcess on its OWN PID with
          PROCESS_QUERY_LIMITED_INFORMATION (positive control proving OpenProcess works).
      (c) Worker MUST fail OpenProcess against the supervisor with PROCESS_VM_READ,
          PROCESS_VM_WRITE, PROCESS_DUP_HANDLE, PROCESS_TERMINATE with GetLastError == 5.
      (d) Worker MUST fail OpenProcess against a dummy Medium-integrity Electron stand-in
          with the same 4 access rights with GetLastError == 5.
    """
    if sys.platform != "win32":
        pytest.skip("Win32 OpenProcess test requires Windows")

    sup: SupervisorDaemon = supervisor_audit_env["supervisor"]
    sup_pid = os.getpid()

    # Spawn a dummy Medium-integrity stand-in process representing Electron main
    standin_proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        standin_pid = standin_proc.pid

        probe_script = f"""
import json, os, sys

probe_res = {{
    "ctypes_imported": False,
    "own_pid_succeeded": False,
    "supervisor_checks": {{}},
    "standin_checks": {{}},
    "error": None
}}

try:
    import ctypes
    kernel32 = ctypes.windll.kernel32
    probe_res["ctypes_imported"] = True

    own_pid = os.getpid()
    # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h_own = kernel32.OpenProcess(0x1000, False, own_pid)
    if h_own:
        probe_res["own_pid_succeeded"] = True
        kernel32.CloseHandle(h_own)

    def check_target(target_pid):
        access_map = {{
            "PROCESS_VM_READ": 0x0010,
            "PROCESS_VM_WRITE": 0x0020,
            "PROCESS_DUP_HANDLE": 0x0040,
            "PROCESS_TERMINATE": 0x0001
        }}
        target_results = {{}}
        for name, access_val in access_map.items():
            h = kernel32.OpenProcess(access_val, False, target_pid)
            err = kernel32.GetLastError()
            if h:
                kernel32.CloseHandle(h)
                target_results[name] = {{"opened": True, "error": 0}}
            else:
                target_results[name] = {{"opened": False, "error": err}}
        return target_results

    probe_res["supervisor_checks"] = check_target({sup_pid})
    probe_res["standin_checks"] = check_target({standin_pid})

except Exception as e:
    probe_res["error"] = str(e)

print("PROBE_JSON:" + json.dumps(probe_res))
"""
        result = sup.spawn_worker_process(probe_script)

        # Assertion A: ctypes MUST be imported (must not pass vacantly on ImportError)
        assert result.get("ctypes_imported") is True, (
            f"W4 is VACUOUS: worker could not import ctypes! Error: {result.get('error')}, "
            f"raw: {result.get('raw_output')}"
        )

        # Assertion B: Positive control on own PID must succeed
        assert result.get("own_pid_succeeded") is True, (
            "Control failed: worker could not OpenProcess its own PID with PROCESS_QUERY_LIMITED_INFORMATION"
        )

        # Assertion C: All 4 access rights on supervisor must fail with error 5 (ERROR_ACCESS_DENIED)
        sup_checks = result.get("supervisor_checks", {})
        for right, outcome in sup_checks.items():
            assert outcome["opened"] is False, f"Worker successfully opened supervisor with {right}!"
            assert outcome["error"] == 5, f"Expected error 5 (ERROR_ACCESS_DENIED) on supervisor for {right}, got: {outcome['error']}"

        # Assertion D: All 4 access rights on dummy Electron stand-in must fail with error 5
        standin_checks = result.get("standin_checks", {})
        for right, outcome in standin_checks.items():
            assert outcome["opened"] is False, f"Worker successfully opened stand-in with {right}!"
            assert outcome["error"] == 5, f"Expected error 5 (ERROR_ACCESS_DENIED) on stand-in for {right}, got: {outcome['error']}"

    finally:
        standin_proc.kill()
        standin_proc.wait()
