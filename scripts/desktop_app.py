"""
US Neural - Mycelium Desktop Application Launcher
Module: desktop_app.py
Description: Python entrypoint launching the Electron Desktop Application
             connected to the Mycelium Agent Coordinator (MAC) & HOL Guard.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DESKTOP_DIR = BASE_DIR / "mycelium_desktop"
if not DESKTOP_DIR.exists():
    # Fallback to sibling directory
    DESKTOP_DIR = (BASE_DIR.parent / "mycelium_desktop").resolve()


def launch_desktop():
    print("=" * 70)
    print("  US NEURAL - MYCELIUM AGENT COORDINATOR (MAC) DESKTOP APPLICATION")
    print("  Zero-Trust Split-Execution Engine & Native HOL Guard UI")
    print("=" * 70)
    print(f"[*] Workspace Root       : {BASE_DIR}")
    print(f"[*] Desktop App Directory: {DESKTOP_DIR}")

    # Check node / npm
    npm_path = shutil.which("npm.cmd") or shutil.which("npm")
    npx_path = shutil.which("npx.cmd") or shutil.which("npx")
    
    if not npm_path:
        print("[!] Error: Node.js / npm not found in system PATH.")
        sys.exit(1)

    # Launch electron via npm start
    print("[*] Launching Electron Native Desktop Window via npm start...")
    try:
        subprocess.run(
            [npm_path, "start"],
            cwd=str(DESKTOP_DIR),
            shell=sys.platform.startswith("win"),
            check=False
        )
        print("[✔] Desktop Application session ended cleanly.")
    except KeyboardInterrupt:
        print("\n[*] Shutting down Desktop Application...")
    except Exception as exc:
        print(f"[!] Launch error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    launch_desktop()
