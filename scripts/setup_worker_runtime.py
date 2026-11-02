"""
scripts/setup_worker_runtime.py - Provisions repo-local worker runtime for containment testing.

Ensures runtime/worker_python/python.exe exists with all required base DLLs and standard libraries,
and applies the required Windows ACLs:
- ALL APPLICATION PACKAGES (S-1-15-2-1): (OI)(CI)(RX)
- Low Mandatory Level (S-1-16-4096): (OI)(CI)(RX)
"""

import os
import pathlib
import shutil
import subprocess
import sys


def setup_worker_runtime() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    runtime_dir = repo_root / "runtime" / "worker_python"
    target_exe = runtime_dir / "python.exe"

    if not target_exe.exists():
        print(f"[1/3] Provisioning worker runtime at {runtime_dir}...")
        runtime_dir.mkdir(parents=True, exist_ok=True)
        base = pathlib.Path(sys.base_prefix)

        # Copy executable and DLL files from base Python installation
        for item in base.glob("*"):
            if item.name.lower() in ("doc", "tcl", "tools", "include"):
                continue
            dest = runtime_dir / item.name
            if item.is_file():
                shutil.copy2(item, dest)
            elif item.is_dir():
                if not dest.exists():
                    shutil.copytree(
                        item,
                        dest,
                        ignore=shutil.ignore_patterns("test", "__pycache__", "site-packages")
                    )

        # Write pyvenv.cfg so Python discovers its Lib directory
        cfg_path = runtime_dir / "pyvenv.cfg"
        if not cfg_path.exists():
            cfg_path.write_text(
                f"home = .\ninclude-system-site-packages = false\nversion = {sys.version.split()[0]}\nexecutable = python.exe\n",
                encoding="utf-8"
            )
        print(f"Worker runtime provisioned. target_exe exists: {target_exe.exists()}")
    else:
        print(f"Worker runtime already present at {target_exe}")

    # Set Windows ACLs if on win32
    if sys.platform == "win32":
        print("[2/3] Setting AppContainer and Low-IL permissions...")
        subprocess.run(
            ["icacls", str(runtime_dir), "/grant", "*S-1-15-2-1:(OI)(CI)(RX)"],
            capture_output=True, text=True
        )
        subprocess.run(
            ["icacls", str(runtime_dir), "/grant", "*S-1-16-4096:(OI)(CI)(RX)"],
            capture_output=True, text=True
        )

    # Smoke test the provisioned executable
    print("[3/3] Verifying worker python execution...")
    res = subprocess.run(
        [str(target_exe), "-c", "import json, os, sys; print('WORKER_PYTHON_OK:', sys.version.split()[0])"],
        capture_output=True,
        text=True
    )
    if res.returncode != 0:
        print(f"Error executing worker python: {res.stderr}")
        sys.exit(res.returncode)
    print(f"Verified: {res.stdout.strip()}")


if __name__ == "__main__":
    setup_worker_runtime()
