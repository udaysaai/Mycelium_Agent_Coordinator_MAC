"""
worker_attacker.py - Adversarial Worker Attack Suite
Executes untrusted agent attack vectors strictly from INSIDE the worker process context.
Used by test_phase05_boundary.py to verify process boundary isolation.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import gc
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class WorkerAttacker:
    """
    Simulates a compromised or malicious LLM agent process attempting to break out of
    the unprivileged worker container and subvert supervisor security controls.
    """

    def __init__(self, worker_port: int, worker_secret: str, supervisor_pid: int, db_path: Path):
        self.worker_port = worker_port
        self.worker_secret = worker_secret
        self.supervisor_pid = supervisor_pid
        self.db_path = Path(db_path).resolve()
        self.sock: Optional[socket.socket] = None

    def connect_worker_channel(self) -> bool:
        """Establish authenticated connection to supervisor worker IPC channel."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect(("127.0.0.1", self.worker_port))
            # Authenticate
            auth_msg = json.dumps({"type": "AUTH", "secret": self.worker_secret}) + "\n"
            self.sock.sendall(auth_msg.encode("utf-8"))
            resp = self._read_json_response(self.sock)
            return resp.get("status") == "AUTHENTICATED"
        except Exception as e:
            return False

    def _read_json_response(self, sock: socket.socket) -> Dict[str, Any]:
        """Read a newline-terminated JSON response."""
        buf = ""
        while "\n" not in buf:
            chunk = sock.recv(4096).decode("utf-8")
            if not chunk:
                if not buf:
                    raise ConnectionResetError("Supervisor connection closed abruptly (crash/shutdown).")
                break
            buf += chunk
        line = buf.split("\n")[0].strip()
        return json.loads(line) if line else {}

    def _send_request(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Send message over worker IPC channel and return response."""
        if not self.sock:
            self.connect_worker_channel()
        payload = json.dumps(msg) + "\n"
        self.sock.sendall(payload.encode("utf-8"))
        return self._read_json_response(self.sock)

    # -------------------------------------------------------------------------
    # C1. Search Memory, Env, Argv, and Filesystem for Signing Key
    # -------------------------------------------------------------------------
    def attack_c1_search_signing_key(self, known_supervisor_key: bytes) -> Dict[str, Any]:
        """
        Scan worker environment, command-line arguments, process objects,
        and local filesystem paths to see if the supervisor leaked the signing key.
        """
        found_locations: List[str] = []

        # 1. Environment variables
        for k, v in os.environ.items():
            if known_supervisor_key.hex() in str(v).lower():
                found_locations.append(f"env:{k}")

        # 2. Command-line argv
        for arg in sys.argv:
            if known_supervisor_key.hex() in str(arg).lower():
                found_locations.append(f"argv:{arg}")

        # 3. Python garbage collector memory inspection
        for obj in gc.get_objects():
            if isinstance(obj, (bytes, bytearray)) and len(obj) == 32:
                if obj == known_supervisor_key:
                    found_locations.append("memory:gc_bytes")
            elif isinstance(obj, str) and known_supervisor_key.hex() in obj.lower():
                found_locations.append("memory:gc_str")

        # 4. Filesystem scan: ~/.mycelium, repo dir, %TEMP%, %APPDATA%
        suspect_dirs = [
            Path.home() / ".mycelium",
            Path(tempfile_gettempdir := os.environ.get("TEMP", "")),
            Path(os.environ.get("APPDATA", "")),
            Path.cwd(),
        ]
        for d in suspect_dirs:
            if not d or not d.exists():
                continue
            key_file = d / "mac_signing.key"
            if key_file.exists():
                try:
                    data = key_file.read_bytes()
                    if known_supervisor_key in data:
                        found_locations.append(f"filesystem:{key_file}")
                except Exception:
                    pass

        return {
            "key_found": len(found_locations) > 0,
            "locations": found_locations
        }

    # -------------------------------------------------------------------------
    # C2. Open/Tamper SQLite DB Directly
    # -------------------------------------------------------------------------
    def attack_c2_sqlite_direct_tamper(self, quarantine_id: str) -> Dict[str, Any]:
        """
        Attempt to directly write to the SQLite state database on disk to flip
        quarantine status from PENDING to APPROVED.
        """
        import sqlite3
        db_readable = False
        write_succeeded = False
        error_msg = ""

        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=2.0)
            conn.row_factory = sqlite3.Row
            # Check read
            cur = conn.execute("SELECT status FROM quarantines WHERE quarantine_id = ?", (quarantine_id,))
            row = cur.fetchone()
            if row:
                db_readable = True

            # Attempt write
            conn.execute(
                "UPDATE quarantines SET status = 'APPROVED', one_shot_token = 'forged-worker-token' WHERE quarantine_id = ?",
                (quarantine_id,)
            )
            conn.commit()
            write_succeeded = True
        except Exception as e:
            error_msg = str(e)
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        return {
            "db_readable": db_readable,
            "write_succeeded": write_succeeded,
            "error": error_msg
        }

    # -------------------------------------------------------------------------
    # C3. Send Approval/Token Message Over Worker Channel
    # -------------------------------------------------------------------------
    def attack_c3_worker_channel_injected_approve(self, quarantine_id: str) -> Dict[str, Any]:
        """
        Worker attempts to send an 'APPROVE' or 'ISSUE_TOKEN' request on the worker IPC channel.
        Supervisor must reject and log as security violation.
        """
        resp = self._send_request({
            "type": "APPROVE_ACTION",
            "quarantine_id": quarantine_id,
            "operator_notes": "Injected by worker attacker"
        })
        is_rejected = (resp.get("status") in ("ERROR", "REJECTED")) or (resp.get("success") is False)
        return {
            "rejected": is_rejected,
            "response": resp
        }

    # -------------------------------------------------------------------------
    # C4. Connect to UI Channel Without Secret
    # -------------------------------------------------------------------------
    def attack_c4_ui_channel_connect_attempt(self, ui_port: int, quarantine_id: str) -> Dict[str, Any]:
        """
        Worker probes the supervisor UI port and attempts to approve without valid UI secret.
        """
        approved = False
        error_msg = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(("127.0.0.1", ui_port))
            # Try to send approval without secret
            msg = json.dumps({
                "type": "APPROVE_ACTION",
                "secret": "guessed-secret-000",
                "quarantine_id": quarantine_id
            }) + "\n"
            s.sendall(msg.encode("utf-8"))
            resp = self._read_json_response(s)
            s.close()
            approved = (resp.get("status") == "APPROVED")
        except Exception as e:
            error_msg = str(e)

        return {
            "approved": approved,
            "error": error_msg
        }

    # -------------------------------------------------------------------------
    # C5. Submit Forged Token
    # -------------------------------------------------------------------------
    def attack_c5_forge_token(self, quarantine_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submit an action execution request with a forged random hex token."""
        forged_token = "deadbeef" * 8
        req = {
            "type": "EXECUTE_APPROVED",
            "quarantine_id": quarantine_id,
            "one_shot_token": forged_token,
            "payload": payload
        }
        resp = self._send_request(req)
        return {
            "success": resp.get("success", False),
            "exit_code": resp.get("exit_code", -1),
            "response": resp
        }

    # -------------------------------------------------------------------------
    # C8. In-Process Supervisor Module Import Check
    # -------------------------------------------------------------------------
    def attack_c8_import_supervisor_modules_in_worker(self) -> Dict[str, Any]:
        """
        Verify that importing PolicyEngine or StateStore in the worker does NOT give it
        access to the supervisor's live in-memory keys or approval authority.
        """
        from policy_engine import PolicyEngine
        local_engine = PolicyEngine()
        # Local engine generates its own distinct in-memory key, not supervisor's
        return {
            "has_supervisor_key": hasattr(local_engine, "_supervisor_master_key"),
            "key_length": len(getattr(local_engine, "_master_key", b""))
        }

    # -------------------------------------------------------------------------
    # C9. Process-Level Memory Access (OpenProcess PROCESS_VM_READ)
    # -------------------------------------------------------------------------
    def attack_c9_process_memory_open(self) -> Dict[str, Any]:
        """
        Attempt to open supervisor process with PROCESS_VM_READ and PROCESS_VM_WRITE.
        Reports real outcome on Windows for same-user processes.
        """
        if sys.platform != "win32":
            return {"open_succeeded": False, "reason": "Not Windows"}

        PROCESS_VM_READ = 0x0010
        PROCESS_VM_WRITE = 0x0020
        PROCESS_TERMINATE = 0x0001
        PROCESS_ALL_ACCESS = 0x1F0FFF

        kernel32 = ctypes.windll.kernel32
        h_proc = kernel32.OpenProcess(PROCESS_VM_READ, False, self.supervisor_pid)
        can_read = bool(h_proc)
        if h_proc:
            kernel32.CloseHandle(h_proc)

        h_write = kernel32.OpenProcess(PROCESS_VM_WRITE, False, self.supervisor_pid)
        can_write = bool(h_write)
        if h_write:
            kernel32.CloseHandle(h_write)

        return {
            "open_read_succeeded": can_read,
            "open_write_succeeded": can_write,
            "supervisor_pid": self.supervisor_pid
        }
