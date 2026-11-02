#!/usr/bin/env python3
"""
scripts/capability_probe.py - Windows System Security Capability Probe (Phase 0.8 / WS2)
Probes:
- OS edition, build, elevation/admin state
- AppContainer API availability (CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName)
- PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES support
- Low Privilege AppContainer (LPAC) support
- CPython execution inside AppContainer with package ACLs
- WSL2 availability and status
- Windows Sandbox availability
- Windows Defender Application Guard / Hyper-V container presence

Emits structured JSON to stdout and evidence/capability_probe.json.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def probe_appcontainer_capabilities() -> dict:
    res = {
        "has_create_appcontainer_profile": False,
        "has_derive_appcontainer_sid": False,
        "has_derive_restricted_appcontainer_sid": False,
        "has_delete_appcontainer_profile": False,
        "has_proc_thread_attribute_security_capabilities": False,
        "profile_creation_succeeded": False,
        "profile_error": None,
        "appcontainer_sid": None,
        "can_launch_appcontainer_process": False,
        "launch_error": None,
        "cpython_execution_status": None,
        "cpython_exit_code": None,
        "notes": []
    }

    try:
        userenv = ctypes.windll.userenv
        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32
    except Exception as e:
        res["profile_error"] = f"Failed to load userenv/kernel32/advapi32: {e}"
        return res

    res["has_create_appcontainer_profile"] = hasattr(userenv, "CreateAppContainerProfile")
    res["has_derive_appcontainer_sid"] = hasattr(userenv, "DeriveAppContainerSidFromAppContainerName")
    res["has_derive_restricted_appcontainer_sid"] = hasattr(userenv, "DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName")
    res["has_delete_appcontainer_profile"] = hasattr(userenv, "DeleteAppContainerProfile")

    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20009
    size = ctypes.c_size_t(0)
    init_res = kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    res["has_proc_thread_attribute_security_capabilities"] = (size.value > 0 or init_res != 0)

    container_name = "MAC_WS2_CapabilityProbe_AC"
    display_name = "MAC Probe AppContainer WS2"
    desc = "Probe for Windows AppContainer capability in MAC"

    p_sid = ctypes.c_void_p()
    try:
        hr = userenv.CreateAppContainerProfile(
            ctypes.c_wchar_p(container_name),
            ctypes.c_wchar_p(display_name),
            ctypes.c_wchar_p(desc),
            None,
            0,
            ctypes.byref(p_sid)
        )
        if hr == 0 or (hr & 0xFFFFFFFF) == 0x800700B7:
            res["profile_creation_succeeded"] = True
            if hr != 0:
                userenv.DeriveAppContainerSidFromAppContainerName(
                    ctypes.c_wchar_p(container_name),
                    ctypes.byref(p_sid)
                )
        else:
            res["profile_error"] = f"CreateAppContainerProfile failed with HRESULT 0x{hr & 0xFFFFFFFF:08X}"
    except Exception as e:
        res["profile_error"] = str(e)

    if not res["profile_creation_succeeded"] or not p_sid:
        res["notes"].append("AppContainer profile creation failed or denied.")
        return res

    str_sid = ctypes.c_wchar_p()
    advapi32.ConvertSidToStringSidW(p_sid, ctypes.byref(str_sid))
    sid_str = str_sid.value
    res["appcontainer_sid"] = sid_str

    class SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [
            ("AppContainerSid", ctypes.c_void_p),
            ("Capabilities", ctypes.c_void_p),
            ("CapabilityCount", ctypes.wintypes.DWORD),
            ("Reserved", ctypes.wintypes.DWORD)
        ]

    sec_caps = SECURITY_CAPABILITIES()
    sec_caps.AppContainerSid = p_sid
    sec_caps.Capabilities = None
    sec_caps.CapabilityCount = 0
    sec_caps.Reserved = 0

    attr_list = ctypes.create_string_buffer(size.value)
    if kernel32.InitializeProcThreadAttributeList(attr_list, 1, 0, ctypes.byref(size)):
        if kernel32.UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(sec_caps),
            ctypes.sizeof(sec_caps),
            None,
            None
        ):
            class STARTUPINFOW(ctypes.Structure):
                _fields_ = [
                    ('cb', ctypes.wintypes.DWORD),
                    ('lpReserved', ctypes.wintypes.LPWSTR),
                    ('lpDesktop', ctypes.wintypes.LPWSTR),
                    ('lpTitle', ctypes.wintypes.LPWSTR),
                    ('dwX', ctypes.wintypes.DWORD),
                    ('dwY', ctypes.wintypes.DWORD),
                    ('dwXSize', ctypes.wintypes.DWORD),
                    ('dwYSize', ctypes.wintypes.DWORD),
                    ('dwXCountChars', ctypes.wintypes.DWORD),
                    ('dwYCountChars', ctypes.wintypes.DWORD),
                    ('dwFillAttribute', ctypes.wintypes.DWORD),
                    ('dwFlags', ctypes.wintypes.DWORD),
                    ('wShowWindow', ctypes.wintypes.WORD),
                    ('cbReserved2', ctypes.wintypes.WORD),
                    ('lpReserved2', ctypes.c_void_p),
                    ('hStdInput', ctypes.wintypes.HANDLE),
                    ('hStdOutput', ctypes.wintypes.HANDLE),
                    ('hStdError', ctypes.wintypes.HANDLE),
                ]

            class STARTUPINFOEXW(ctypes.Structure):
                _fields_ = [
                    ("StartupInfo", STARTUPINFOW),
                    ("lpAttributeList", ctypes.c_void_p)
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('hProcess', ctypes.wintypes.HANDLE),
                    ('hThread', ctypes.wintypes.HANDLE),
                    ('dwProcessId', ctypes.wintypes.DWORD),
                    ('dwThreadId', ctypes.wintypes.DWORD),
                ]

            si = STARTUPINFOEXW()
            si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
            si.lpAttributeList = ctypes.cast(attr_list, ctypes.c_void_p)
            pi = PROCESS_INFORMATION()

            # Test execution with repo-local worker runtime
            runtime_dir = Path(__file__).resolve().parent.parent / "runtime" / "worker_python"
            worker_py = runtime_dir / "python.exe"
            if worker_py.exists():
                subprocess.run(["icacls", str(runtime_dir), "/grant", f"*{sid_str}:(OI)(CI)(RX)"], capture_output=True)
                target_exe = worker_py
            else:
                target_exe = Path(sys.executable)

            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            py_cmd = f'"{target_exe}" -c "import sys; sys.exit(0)"'
            success = kernel32.CreateProcessW(
                None,
                ctypes.c_wchar_p(py_cmd),
                None,
                None,
                False,
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi)
            )
            if success:
                res["can_launch_appcontainer_process"] = True
                kernel32.WaitForSingleObject(pi.hProcess, 5000)
                exit_code = ctypes.wintypes.DWORD()
                kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
                res["cpython_exit_code"] = hex(exit_code.value)
                kernel32.CloseHandle(pi.hProcess)
                kernel32.CloseHandle(pi.hThread)

                if exit_code.value == 0:
                    res["cpython_execution_status"] = "SUCCESS"
                elif exit_code.value == 0xC0000135:
                    res["cpython_execution_status"] = "STATUS_DLL_NOT_FOUND (0xc0000135)"
                elif exit_code.value == 0xC0000142:
                    res["cpython_execution_status"] = "STATUS_DLL_INIT_FAILED (0xc0000142)"
                else:
                    res["cpython_execution_status"] = f"EXIT_CODE_{hex(exit_code.value)}"
            else:
                err = kernel32.GetLastError()
                res["launch_error"] = f"CreateProcessW failed with error {err}"

            if worker_py.exists():
                subprocess.run(["icacls", str(runtime_dir), "/remove", f"*{sid_str}"], capture_output=True)

        kernel32.DeleteProcThreadAttributeList(attr_list)

    # Clean up AppContainer profile
    try:
        userenv.DeleteAppContainerProfile(ctypes.c_wchar_p(container_name))
    except Exception:
        pass

    return res


def probe_capabilities() -> dict:
    results = {}
    results["os_platform"] = platform.platform()
    win_ver = sys.getwindowsversion()
    results["windows_version"] = {
        "major": win_ver.major,
        "minor": win_ver.minor,
        "build": win_ver.build,
        "platform": win_ver.platform,
        "service_pack": win_ver.service_pack
    }

    try:
        results["windows_edition"] = getattr(platform, "win32_edition", lambda: "Unknown")()
    except Exception:
        results["windows_edition"] = "Unknown"

    # 1. Admin / Elevation Check
    try:
        results["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        results["is_admin"] = False

    # 2. advapi32 Token APIs
    try:
        advapi32 = ctypes.windll.advapi32
        results["has_create_restricted_token"] = hasattr(advapi32, "CreateRestrictedToken")
        results["has_set_token_information"] = hasattr(advapi32, "SetTokenInformation")
    except Exception:
        results["has_create_restricted_token"] = False
        results["has_set_token_information"] = False

    # 3. AppContainer & LPAC Capabilities Probe
    results["appcontainer_probe"] = probe_appcontainer_capabilities()

    # 4. WSL2 Check
    try:
        res = subprocess.run(["wsl.exe", "--status"], capture_output=True, timeout=5)
        results["wsl_available"] = (res.returncode == 0)
        try:
            results["wsl_status"] = res.stdout.decode("utf-16le", errors="ignore").strip().replace("\r\n", " ")[:120]
        except Exception:
            results["wsl_status"] = res.stdout.decode("utf-8", errors="ignore").strip()[:120]
    except Exception as e:
        results["wsl_available"] = False
        results["wsl_status"] = str(e)

    # 5. Windows Sandbox Check
    try:
        res = subprocess.run(["where.exe", "WindowsSandbox.exe"], capture_output=True, text=True, timeout=5)
        results["windows_sandbox_executable"] = (res.returncode == 0)
    except Exception:
        results["windows_sandbox_executable"] = False

    # 6. Hyper-V / Host Compute Service Check
    results["hyperv_container_support"] = {
        "vmcompute_exe_present": os.path.exists(r"C:\Windows\System32\vmcompute.exe"),
        "hcs_dll_present": os.path.exists(r"C:\Windows\System32\hcs.dll"),
        "wdagtool_exe_present": os.path.exists(r"C:\Windows\System32\wdagtool.exe")
    }

    return results


if __name__ == "__main__":
    caps = probe_capabilities()
    raw_json = json.dumps(caps, indent=2)
    print(raw_json)

    # Write to evidence directory
    evidence_dir = Path(__file__).resolve().parent.parent / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    probe_file = evidence_dir / "capability_probe.json"
    probe_file.write_text(raw_json, encoding="utf-8")
    print(f"\nWrote probe results to {probe_file}")
