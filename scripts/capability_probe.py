#!/usr/bin/env python3
"""
scripts/capability_probe.py - Windows System Security Capability Probe
Probes OS edition, elevation/admin state, AppContainer, Low Integrity / Restricted Token APIs,
WSL2, and Windows Sandbox.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys


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

    # 4. WSL2 Check
    try:
        res = subprocess.run(["wsl.exe", "--status"], capture_output=True, text=True, timeout=5)
        results["wsl_available"] = (res.returncode == 0)
        results["wsl_status"] = res.stdout.strip().replace("\r\n", " ")[:120]
    except Exception as e:
        results["wsl_available"] = False
        results["wsl_status"] = str(e)

    # 5. Windows Sandbox Check
    try:
        res = subprocess.run(["where.exe", "WindowsSandbox.exe"], capture_output=True, text=True, timeout=5)
        results["windows_sandbox_executable"] = (res.returncode == 0)
    except Exception:
        results["windows_sandbox_executable"] = False

    return results


if __name__ == "__main__":
    caps = probe_capabilities()
    import json
    print(json.dumps(caps, indent=2))
