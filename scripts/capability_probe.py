#!/usr/bin/env python3
"""
scripts/capability_probe.py - Windows System Security Capability Probe (Phase 0.7)
Probes OS edition, elevation/admin state, AppContainer profile creation,
AppContainer process launch, CPython DLL loading inside AppContainer,
Restricted Token / Low Integrity APIs, WSL2, and Windows Sandbox.
Outputs structured JSON to stdout and evidence/capability_probe.json.
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


def probe_appcontainer_execution() -> dict:
    res = {
        "can_call_create_appcontainer_profile": False,
        "profile_error": None,
        "can_launch_appcontainer_process": False,
        "launch_error": None,
        "cpython_dll_load_status": None,
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

    container_name = "MAC_SecurityProbe_AppContainer"
    display_name = "MAC Probe AppContainer"
    desc = "Probe for Windows AppContainer capability in non-elevated Python"

    p_sid = ctypes.c_void_p()
    # HRESULT CreateAppContainerProfile
    # E_ACCESSDENIED = 0x80070005, S_OK = 0, HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700b7
    try:
        hr = userenv.CreateAppContainerProfile(
            ctypes.c_wchar_p(container_name),
            ctypes.c_wchar_p(display_name),
            ctypes.c_wchar_p(desc),
            None,
            0,
            ctypes.byref(p_sid)
        )
        # 0x800700b7 = already exists
        if hr == 0 or (hr & 0xFFFFFFFF) == 0x800700B7:
            res["can_call_create_appcontainer_profile"] = True
            if hr != 0:
                userenv.DeriveAppContainerSidFromAppContainerName(
                    ctypes.c_wchar_p(container_name),
                    ctypes.byref(p_sid)
                )
        else:
            res["profile_error"] = f"CreateAppContainerProfile failed with HRESULT 0x{hr & 0xFFFFFFFF:08X}"
    except Exception as e:
        res["profile_error"] = str(e)

    if not res["can_call_create_appcontainer_profile"] or not p_sid:
        res["notes"].append("AppContainer profile creation failed or denied.")
        return res

    # Convert SID to string for record
    str_sid = ctypes.c_wchar_p()
    advapi32.ConvertSidToStringSidW(p_sid, ctypes.byref(str_sid))
    res["appcontainer_sid"] = str_sid.value

    # Test launching a basic process with SECURITY_CAPABILITIES
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

    # Probe PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES (0x20009)
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20009
    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))

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
            # Attempt to launch cmd.exe /c exit 0 or python.exe
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

            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            # Test launching python.exe -c "import sys; sys.exit(0)"
            py_cmd = f'"{sys.executable}" -c "import sys; sys.exit(0)"'
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

                # Standard CPython fails with 0xc0000142 (STATUS_DLL_INIT_FAILED)
                # because standard python312.dll and Windows runtime lack package ACLs
                if exit_code.value == 0xC0000142:
                    res["cpython_dll_load_status"] = "STATUS_DLL_INIT_FAILED (0xc0000142) - CPython DLL lacks package permissions"
                elif exit_code.value == 0:
                    res["cpython_dll_load_status"] = "SUCCESS"
                else:
                    res["cpython_dll_load_status"] = f"EXIT_CODE_{hex(exit_code.value)}"
            else:
                err = kernel32.GetLastError()
                res["launch_error"] = f"CreateProcessW failed with error {err}"
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

    # 1. Admin / Elevation Check
    try:
        results["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        results["is_admin"] = False

    # 2. AppContainer API Check (userenv.dll / kernel32.dll)
    try:
        userenv = ctypes.windll.userenv
        results["has_create_appcontainer_profile"] = hasattr(userenv, "CreateAppContainerProfile")
    except Exception:
        results["has_create_appcontainer_profile"] = False

    # 3. Restricted Token & Low Integrity APIs (advapi32.dll)
    try:
        advapi32 = ctypes.windll.advapi32
        results["has_create_restricted_token"] = hasattr(advapi32, "CreateRestrictedToken")
        results["has_set_token_information"] = hasattr(advapi32, "SetTokenInformation")
    except Exception:
        results["has_create_restricted_token"] = False
        results["has_set_token_information"] = False

    # 4. AppContainer Execution Probe
    results["appcontainer_probe"] = probe_appcontainer_execution()

    # 5. WSL2 Check
    try:
        res = subprocess.run(["wsl.exe", "--status"], capture_output=True, text=True, timeout=5)
        results["wsl_available"] = (res.returncode == 0)
        results["wsl_status"] = res.stdout.strip().replace("\r\n", " ")[:120]
    except Exception as e:
        results["wsl_available"] = False
        results["wsl_status"] = str(e)

    # 6. Windows Sandbox Check
    try:
        res = subprocess.run(["where.exe", "WindowsSandbox.exe"], capture_output=True, text=True, timeout=5)
        results["windows_sandbox_executable"] = (res.returncode == 0)
    except Exception:
        results["windows_sandbox_executable"] = False

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
