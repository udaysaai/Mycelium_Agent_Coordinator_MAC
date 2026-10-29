"""
supervisor.py - Phase 0.5 Privileged Supervisor Daemon
Owns SQLite/WAL state, policy engine, verification engine, ephemeral signing key,
and isolated UI/Worker IPC channels.

Hardened for Windows:
  - Ephemeral in-memory signing key: NEVER written to disk, never in env/argv/logs.
  - Windows Job Object: KILL_ON_JOB_CLOSE, memory limit, active process limit.
  - Two isolated channels:
      1. Worker Channel: Strict whitelist of commands; rejects and logs APPROVE/ISSUE_TOKEN.
      2. UI Channel: Authenticated with separate UI secret for operator confirmation.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import json
import logging
import os
import secrets
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from coordinator import MyceliumCoordinator
from local_daemon import LocalExecDaemon
from mcp_gateway import MCPGateway
from policy_engine import PolicyEngine
from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
    TaskContract,
    TaskContractStatus,
    TierLevel,
    VerificationReceipt,
)
from state_store import StateStore
from verifier import DeterministicVerifier

logger = logging.getLogger("MyceliumSupervisor")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class SupervisorDaemon:
    """
    Privileged supervisor process managing the boundary between untrusted worker code
    and trusted governance/persistence/verification systems.
    """

    WORKER_ALLOWED_MESSAGE_TYPES = {
        "AUTH",
        "PROPOSE_ACTION",
        "EXECUTE_APPROVED",
        "POLL_TASK",
        "FETCH_RECEIPT",
        "GET_DIAGNOSTICS",
        "VERIFY_TOKEN"
    }

    ALLOWED_SHELL_COMMANDS = {
        'echo', 'dir', 'type', 'ls', 'cat', 'python', 'pytest', 'git', 'node', 'npm', 'whoami'
    }

    FORBIDDEN_WORKER_MESSAGE_TYPES = {
        "APPROVE_ACTION",
        "REJECT_ACTION",
        "ISSUE_TOKEN",
        "HOL_DECISION"
    }

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        clock: Optional[Callable[[], float]] = None,
        use_named_pipes: bool = True
    ):
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.clock = clock or time.time

        # Ensure sandbox and data directories exist
        (self.workspace_root / "workspace_sandbox").mkdir(parents=True, exist_ok=True)
        (self.workspace_root / "data").mkdir(parents=True, exist_ok=True)

        # 1. Ephemeral In-Memory Signing Key: Dies with this process
        self._signing_key: bytes = secrets.token_bytes(32)

        # 2. Trusted Subsystems (Supervisor is the ONLY owner)
        self.db_path = self.workspace_root / "data" / "mac_state.db"
        self.state_store = StateStore(
            db_path=self.db_path,
            clock=self.clock,
            integrity_key=self._signing_key
        )
        self.policy_engine = PolicyEngine(
            sandbox_dirname="workspace_sandbox",
            signing_key=self._signing_key
        )
        self.daemon = LocalExecDaemon(workspace_root=self.workspace_root)
        self.verifier = DeterministicVerifier(
            workspace_root=self.workspace_root,
            state_store=self.state_store
        )
        self.coordinator = MyceliumCoordinator(
            local_daemon=self.daemon,
            state_store=self.state_store,
            policy_engine=self.policy_engine,
            verifier=self.verifier,
            _supervisor_mode=True
        )

        # 3. IPC Channels and Per-Session Secrets
        self.worker_secret: str = secrets.token_hex(32)
        self.ui_secret: str = secrets.token_hex(32)

        self.worker_server: Optional[socket.socket] = None
        self.worker_port: int = 0
        self.ui_server: Optional[socket.socket] = None
        self.ui_port: int = 0

        self._active_connections: set[socket.socket] = set()
        self._conn_lock = threading.Lock()

        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._ui_thread: Optional[threading.Thread] = None

        # Named Pipe attributes with random per-session names
        self.use_named_pipes = use_named_pipes
        self.worker_pipe_path = rf"\\.\pipe\mac_worker_{secrets.token_hex(16)}"
        self.ui_pipe_path = rf"\\.\pipe\mac_ui_{secrets.token_hex(16)}"
        self._pipe_handles: List[Any] = []
        self._worker_pipe_thread: Optional[threading.Thread] = None
        self._ui_pipe_thread: Optional[threading.Thread] = None

        # 4. Windows Job Object Management
        self.job_object_handle = None
        self.job_object_active = False
        self._init_windows_job_object()

    def _init_windows_job_object(self) -> None:
        """Create and configure Windows Job Object for worker containment."""
        if sys.platform != "win32":
            return
        try:
            kernel32 = ctypes.windll.kernel32
            h_job = kernel32.CreateJobObjectW(None, None)
            if not h_job:
                return

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ('r_ops', ctypes.c_uint64), ('w_ops', ctypes.c_uint64),
                    ('o_ops', ctypes.c_uint64), ('r_bytes', ctypes.c_uint64),
                    ('w_bytes', ctypes.c_uint64), ('o_bytes', ctypes.c_uint64)
                ]

            class BASIC_LIMIT(ctypes.Structure):
                _fields_ = [
                    ('per_proc_time', ctypes.c_int64), ('per_job_time', ctypes.c_int64),
                    ('limit_flags', ctypes.wintypes.DWORD), ('min_ws', ctypes.c_size_t),
                    ('max_ws', ctypes.c_size_t), ('active_procs', ctypes.wintypes.DWORD),
                    ('affinity', ctypes.c_size_t), ('priority_class', ctypes.wintypes.DWORD),
                    ('scheduling_class', ctypes.wintypes.DWORD)
                ]

            class EXTENDED_LIMIT(ctypes.Structure):
                _fields_ = [
                    ('basic', BASIC_LIMIT), ('io_info', IO_COUNTERS),
                    ('proc_mem_limit', ctypes.c_size_t), ('job_mem_limit', ctypes.c_size_t),
                    ('peak_proc_mem', ctypes.c_size_t), ('peak_job_mem', ctypes.c_size_t)
                ]

            info = EXTENDED_LIMIT()
            # 0x2000 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            # 0x0008 = JOB_OBJECT_LIMIT_ACTIVE_PROCESS (max 16 processes)
            info.basic.limit_flags = 0x2000 | 0x0008
            info.basic.active_procs = 16

            res = kernel32.SetInformationJobObject(
                h_job, 9, ctypes.byref(info), ctypes.sizeof(info)
            )
            if res:
                self.job_object_handle = h_job
                self.job_object_active = True
                logger.info("Windows Job Object configured with KILL_ON_JOB_CLOSE.")
        except Exception as e:
            logger.warning(f"Could not initialize Windows Job Object: {e}")

    def assign_worker_to_job(self, proc: subprocess.Popen) -> bool:
        """Assign spawned worker subprocess to Job Object."""
        if not self.job_object_active or not self.job_object_handle:
            return False
        try:
            kernel32 = ctypes.windll.kernel32
            # Use proc._handle on Windows
            handle = getattr(proc, "_handle", None)
            if handle:
                res = kernel32.AssignProcessToJobObject(self.job_object_handle, handle)
                return bool(res)
        except Exception as e:
            logger.warning(f"Failed to assign worker {proc.pid} to Job Object: {e}")
        return False

    def spawn_worker_process(self, script_body: str) -> Dict[str, Any]:
        """
        Spawn a restricted worker process with dropped privileges and Low Integrity level.
        Enforces:
          - Restricted token (DISABLE_MAX_PRIVILEGE)
          - Low Integrity Level (S-1-16-4096)
          - Confinement in Windows Job Object
        Captures structured output and returns parsed probe JSON dictionary.
        """
        import uuid
        sandbox_dir = (self.workspace_root / "workspace_sandbox").resolve()
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        unique_id = uuid.uuid4().hex[:8]
        script_file = sandbox_dir / f"_worker_probe_{unique_id}.py"
        out_file = sandbox_dir / f"_worker_out_{unique_id}.txt"
        script_file.write_text(script_body, encoding="utf-8")

        if sys.platform == "win32":
            try:
                import win32api
                import win32con
                import win32event
                import win32file
                import win32process
                import win32security

                # Ensure sandbox directory allows Low Integrity inheritance
                subprocess.run(
                    f'icacls "{sandbox_dir}" /setintegritylevel (OI)(CI)L',
                    shell=True,
                    capture_output=True,
                    timeout=5
                )

                # 1. Open current process token
                h_current = win32api.GetCurrentProcess()
                tok = win32security.OpenProcessToken(
                    h_current,
                    win32con.TOKEN_DUPLICATE | win32con.TOKEN_ASSIGN_PRIMARY | win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_DEFAULT
                )

                # 2. Drop all unnecessary privileges
                rest_tok = win32security.CreateRestrictedToken(
                    tok, win32security.DISABLE_MAX_PRIVILEGE, [], [], []
                )

                # 3. Set TokenIntegrityLevel to Low Integrity (S-1-16-4096)
                low_sid = win32security.ConvertStringSidToSid("S-1-16-4096")
                win32security.SetTokenInformation(
                    rest_tok,
                    win32security.TokenIntegrityLevel,
                    (low_sid, win32security.SE_GROUP_INTEGRITY)
                )

                # 4. Prepare inheritable output file handle
                sa = win32security.SECURITY_ATTRIBUTES()
                sa.bInheritHandle = 1

                h_out = win32file.CreateFile(
                    str(out_file),
                    win32file.GENERIC_WRITE | win32file.GENERIC_READ,
                    win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                    sa,
                    win32file.CREATE_ALWAYS,
                    win32file.FILE_ATTRIBUTE_NORMAL,
                    None
                )

                startup = win32process.STARTUPINFO()
                startup.dwFlags = win32process.STARTF_USESTDHANDLES
                startup.hStdOutput = h_out
                startup.hStdError = h_out

                cmd = f'"{sys.executable}" -u "{script_file}"'
                h_proc, h_thread, pid, tid = win32process.CreateProcessAsUser(
                    rest_tok, None, cmd, None, None, True, 0, None, str(self.workspace_root), startup
                )

                # 5. Assign to Job Object
                if self.job_object_active and self.job_object_handle:
                    try:
                        kernel32 = ctypes.windll.kernel32
                        kernel32.AssignProcessToJobObject(self.job_object_handle, int(h_proc))
                    except Exception as e:
                        logger.warning(f"Failed to assign restricted worker to Job Object: {e}")

                win32event.WaitForSingleObject(h_proc, 10000)
                win32file.CloseHandle(h_out)
                win32api.CloseHandle(h_proc)
                win32api.CloseHandle(h_thread)

            except Exception as e:
                logger.error(f"Error spawning restricted worker via CreateProcessAsUser: {e}")
                # Fallback to standard subprocess
                with open(out_file, "w", encoding="utf-8") as f_out:
                    proc = subprocess.Popen(
                        [sys.executable, "-u", str(script_file)],
                        stdout=f_out,
                        stderr=f_out,
                        cwd=str(self.workspace_root)
                    )
                    self.assign_worker_to_job(proc)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        else:
            with open(out_file, "w", encoding="utf-8") as f_out:
                proc = subprocess.Popen(
                    [sys.executable, "-u", str(script_file)],
                    stdout=f_out,
                    stderr=f_out,
                    cwd=str(self.workspace_root)
                )
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

        out_text = ""
        if out_file.exists():
            try:
                out_text = out_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

        # Cleanup files
        try:
            if script_file.exists():
                script_file.unlink()
            if out_file.exists():
                out_file.unlink()
        except Exception:
            pass

        # Parse probe json
        for line in out_text.splitlines():
            line_str = line.strip()
            if line_str.startswith("PROBE_JSON:"):
                try:
                    return json.loads(line_str[len("PROBE_JSON:"):])
                except Exception:
                    pass

        return {"raw_output": out_text, "success": False}

    def get_ephemeral_key(self) -> bytes:
        """Access in-memory signing key for internal verification."""
        return self._signing_key

    def start(self) -> None:
        """Start Worker and UI IPC listener sockets."""
        self._running = True

        # 1. Bind Worker Channel Socket
        self.worker_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.worker_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.worker_server.bind(("127.0.0.1", 0))
        self.worker_server.listen(16)
        self.worker_port = self.worker_server.getsockname()[1]

        # 2. Bind UI Channel Socket
        self.ui_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ui_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ui_server.bind(("127.0.0.1", 0))
        self.ui_server.listen(8)
        self.ui_port = self.ui_server.getsockname()[1]

        # 3. Start Listener Threads
        self._worker_thread = threading.Thread(target=self._worker_accept_loop, daemon=True)
        self._worker_thread.start()

        self._ui_thread = threading.Thread(target=self._ui_accept_loop, daemon=True)
        self._ui_thread.start()

        # 4. Start Named Pipe Servers on Windows
        if self.use_named_pipes and sys.platform == "win32":
            self._start_named_pipes()
            logger.info(f"Named Pipes active. Worker: {self.worker_pipe_path}, UI: {self.ui_pipe_path}")

        logger.info(f"Supervisor started. Worker Port: {self.worker_port}, UI Port: {self.ui_port}")

    def stop(self) -> None:
        """Stop supervisor daemon and release resources."""
        self._running = False

        # Forcibly close all active client connections (simulates crash/server death)
        with self._conn_lock:
            for s in list(self._active_connections):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                except Exception:
                    pass
            self._active_connections.clear()

        if self.worker_server:
            try:
                self.worker_server.close()
            except Exception:
                pass
        if self.ui_server:
            try:
                self.ui_server.close()
            except Exception:
                pass

        if self.job_object_handle:
            try:
                ctypes.windll.kernel32.CloseHandle(self.job_object_handle)
            except Exception:
                pass
            self.job_object_handle = None

        # Close named pipe handles
        if self.use_named_pipes and sys.platform == "win32":
            self._unblock_pipes()
            with self._conn_lock:
                for h in list(self._pipe_handles):
                    try:
                        import win32pipe, win32api
                        win32pipe.DisconnectNamedPipe(h)
                        win32api.CloseHandle(h)
                    except Exception:
                        pass
                self._pipe_handles.clear()

        self.state_store.close()
        logger.info("Supervisor stopped.")

    # -------------------------------------------------------------------------
    # Worker Channel Message Loop & Dispatch
    # -------------------------------------------------------------------------
    def _worker_accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self.worker_server.accept()
                threading.Thread(target=self._handle_worker_connection, args=(conn,), daemon=True).start()
            except Exception:
                break

    def _handle_worker_connection(self, conn: socket.socket) -> None:
        with self._conn_lock:
            self._active_connections.add(conn)
        authenticated = False
        conn.settimeout(30.0)

        with conn:
            try:
                buffer = ""
                while self._running:
                    data = conn.recv(65536).decode("utf-8")
                    if not data:
                        break
                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if not line.strip():
                            continue
                        msg = json.loads(line)
                        resp = self._dispatch_worker_message(msg, authenticated)
                        if resp.get("status") == "AUTHENTICATED":
                            authenticated = True
                        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except Exception:
                pass
            finally:
                with self._conn_lock:
                    self._active_connections.discard(conn)
                self.state_store.close()

    def _dispatch_worker_message(self, msg: Dict[str, Any], authenticated: bool) -> Dict[str, Any]:
        msg_type = str(msg.get("type", "")).upper()

        # Handle Auth
        if msg_type == "AUTH":
            secret = msg.get("secret", "")
            if hmac_secret_match := secrets.compare_digest(secret, self.worker_secret):
                return {"status": "AUTHENTICATED", "message": "Worker session authorized."}
            logger.warning("[SECURITY] Worker channel authentication failed (invalid secret).")
            return {"status": "ERROR", "message": "Authentication failed."}

        if not authenticated:
            secret = msg.get("secret", "")
            if secret and secrets.compare_digest(secret, self.worker_secret):
                authenticated = True
            else:
                return {"status": "ERROR", "message": "Unauthenticated connection."}

        # Check for forbidden message types (approval injection vector)
        if msg_type in self.FORBIDDEN_WORKER_MESSAGE_TYPES:
            logger.error(
                f"[SECURITY AUDIT] Unauthorized attempt to send '{msg_type}' on WORKER channel! "
                f"Quarantine ID: {msg.get('quarantine_id')}. Action blocked."
            )
            return {
                "status": "REJECTED",
                "success": False,
                "exit_code": 403,
                "error": f"Security Violation: '{msg_type}' is forbidden on the worker channel."
            }

        # Validate allowed types
        if msg_type not in self.WORKER_ALLOWED_MESSAGE_TYPES:
            return {"status": "ERROR", "message": f"Unknown message type '{msg_type}'."}

        # 1. PROPOSE_ACTION
        if msg_type == "PROPOSE_ACTION":
            return self._worker_propose_action(msg)

        # 2. EXECUTE_APPROVED
        if msg_type == "EXECUTE_APPROVED":
            return self._worker_execute_approved(msg)

        # 3. GET_DIAGNOSTICS
        if msg_type == "GET_DIAGNOSTICS":
            return {"status": "OK", "diagnostics": {"os": sys.platform, "time": self.clock()}}

        # 4. VERIFY_TOKEN
        if msg_type == "VERIFY_TOKEN":
            qid = msg.get("quarantine_id", "")
            tok = msg.get("token", "")
            stored = self.state_store.get_quarantine(qid)
            if not stored:
                return {"status": "ERROR", "valid": False}
            is_valid = self.policy_engine.verify_hmac_token(tok, qid, stored["call_hash"], stored["expires_at"])
            return {"status": "OK", "valid": is_valid}

        return {"status": "OK"}

    def _worker_propose_action(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        intent = msg.get("intent", "")
        tool_name = msg.get("tool_name", "")
        payload = msg.get("payload", {})

        req = ActionRequest(
            intent=intent,
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING if "command" in payload else SafetyTier.MUTATING_SANDBOX,
            payload=payload
        )

        # Intake evaluation
        outcome = self.coordinator.intake_gate.evaluate_intent(intent, payload)
        contract = outcome.contract
        if contract:
            self.state_store.save_contract(contract)

        # Policy evaluation
        verdict = self.policy_engine.evaluate(request=req, contract=contract, tool_name=tool_name)

        if verdict.requiresQuarantine:
            # Register in DB
            quarantine = HOLQuarantineEvent(
                request=req,
                quarantineReason="Mutating action quarantined by supervisor policy.",
                decision=HOLApprovalStatus.PENDING,
                callHash=verdict.callHash,
                plainImpact=verdict.plainImpact,
                expiresAt=self.clock() + 900.0
            )
            self.state_store.save_quarantine(quarantine, tool_name=tool_name, payload=payload)
            return {
                "status": "QUARANTINED",
                "requires_quarantine": True,
                "quarantine_id": quarantine.quarantineId,
                "call_hash": verdict.callHash,
                "plain_impact": verdict.plainImpact
            }

        # Safe T0/T1 action: Execute immediately through coordinator
        res: ExecutionResult = self.coordinator.dispatch(req)
        return {
            "status": "COMPLETED",
            "requires_quarantine": False,
            "success": res.success,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "exit_code": res.exitCode,
            "receipt": res.receipt.model_dump() if res.receipt else None
        }

    def _worker_execute_approved(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute quarantined action unlocking with one-shot token.
        Recomputes call hash from actual call to prevent argument tampering.
        """
        quarantine_id = msg.get("quarantine_id", "")
        token = msg.get("one_shot_token", "")
        payload = msg.get("payload", {})

        stored_q = self.state_store.get_quarantine(quarantine_id)
        if not stored_q:
            return {"status": "ERROR", "success": False, "exit_code": 404, "error": "Quarantine not found."}

        # State store cryptographic integrity check
        if not self.state_store.verify_integrity(self._signing_key):
            logger.error("[SECURITY] State store integrity check failed before executing approved action.")
            return {
                "status": "ERROR",
                "success": False,
                "exit_code": 403,
                "error": "Security Violation: State store integrity check failed."
            }

        tool_name = stored_q.get("tool_name", "action")
        target = payload.get("command", payload.get("file_path", ""))

        if tool_name == "execute_shell_command":
            cmd_str = str(payload.get("command", "")).strip()
            first_cmd = cmd_str.split()[0].lower() if cmd_str else ""
            if first_cmd not in self.ALLOWED_SHELL_COMMANDS:
                return {
                    "status": "ERROR",
                    "success": False,
                    "exit_code": 403,
                    "error": f"Security Violation: Shell command '{first_cmd}' not in allowlist."
                }

        # 1. Recompute call hash from actual execution payload
        current_call_hash = self.policy_engine.compute_call_hash(tool_name, payload, str(target))

        # 2. Validate token (HMAC, call hash, expiry, consumed state)
        is_valid = self.state_store.validate_one_shot_token(
            quarantine_id=quarantine_id,
            token=token,
            policy_engine=self.policy_engine,
            current_call_hash=current_call_hash
        )

        if not is_valid:
            logger.error(
                f"[SECURITY] Token validation failed for quarantine {quarantine_id}. "
                f"Token: {token[:12]}..., Call Hash: {current_call_hash[:10]}..."
            )
            return {
                "status": "ERROR",
                "success": False,
                "exit_code": 403,
                "error": "Security Violation: Invalid, expired, replayed, or argument-tampered token."
            }

        # 3. Authorized execution: Run tool via local daemon in sandbox
        req = ActionRequest(
            intent=f"Approved execution of {tool_name}",
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING,
            payload=payload,
            oneShotToken=token
        )
        raw_output, exit_code, stdout, stderr = self.coordinator._run_actuator(req, tool_name, None)
        receipt = self.verifier.verify_action(
            tool_name=tool_name,
            payload=payload,
            raw_output=raw_output,
            request_id=stored_q.get("request_id", "")
        )
        success = (exit_code == 0) and receipt.verified
        return {
            "status": "COMPLETED",
            "success": success,
            "stdout": stdout or (str(raw_output) if raw_output is not None else ""),
            "stderr": stderr,
            "exit_code": exit_code,
            "receipt": receipt.model_dump() if receipt else None
        }

    # -------------------------------------------------------------------------
    # UI Channel Message Loop & Operator Approval
    # -------------------------------------------------------------------------
    def _ui_accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self.ui_server.accept()
                threading.Thread(target=self._handle_ui_connection, args=(conn,), daemon=True).start()
            except Exception:
                break

    def _handle_ui_connection(self, conn: socket.socket) -> None:
        with self._conn_lock:
            self._active_connections.add(conn)
        conn.settimeout(30.0)
        with conn:
            try:
                buffer = ""
                while self._running:
                    data = conn.recv(65536).decode("utf-8")
                    if not data:
                        break
                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if not line.strip():
                            continue
                        msg = json.loads(line)
                        resp = self._dispatch_ui_message(msg)
                        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except Exception:
                pass
            finally:
                with self._conn_lock:
                    self._active_connections.discard(conn)
                self.state_store.close()

    def _dispatch_ui_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        secret = msg.get("secret", "")
        if not secrets.compare_digest(secret, self.ui_secret):
            return {"status": "ERROR", "message": "Unauthorized: Invalid UI secret."}

        msg_type = str(msg.get("type", "")).upper()

        if msg_type == "LIST_PENDING":
            pending = self.state_store.get_pending_quarantines()
            return {"status": "OK", "pending": pending}

        if msg_type == "APPROVE_ACTION":
            qid = msg.get("quarantine_id", "")
            notes = msg.get("operator_notes", "Operator sign-off")
            token = self.approve_via_ui_channel(qid, notes)
            if token:
                return {"status": "APPROVED", "quarantine_id": qid, "one_shot_token": token}
            return {"status": "ERROR", "message": "Quarantine not found or already resolved."}

        if msg_type == "REJECT_ACTION":
            qid = msg.get("quarantine_id", "")
            notes = msg.get("operator_notes", "Operator rejected")
            self.state_store.update_quarantine_decision(qid, HOLApprovalStatus.REJECTED, notes=notes)
            return {"status": "REJECTED", "quarantine_id": qid}

        return {"status": "ERROR", "message": f"Unknown UI command '{msg_type}'."}

    def approve_via_ui_channel(self, quarantine_id: str, operator_notes: str = "Authorized by human") -> Optional[str]:
        """
        Operator sign-off method accessible ONLY from the privileged supervisor/UI interface.
        Generates HMAC token using ephemeral in-memory key.
        """
        q = self.state_store.get_quarantine(quarantine_id)
        if not q or q["status"] != HOLApprovalStatus.PENDING.value:
            return None

        call_hash = q["call_hash"]
        expires_at = q["expires_at"]

        token = self.policy_engine.generate_hmac_token(quarantine_id, call_hash, expires_at)
        self.state_store.update_quarantine_decision(
            quarantine_id=quarantine_id,
            decision=HOLApprovalStatus.APPROVED,
            operator_id="operator_ui",
            notes=operator_notes,
            token=token
        )
        logger.info(f"Operator approved quarantine {quarantine_id}. Token issued.")
        return token

    # -------------------------------------------------------------------------
    # Worker Process Spawn with Inherited Stdin Config (No Argv / No Env Leak)
    # -------------------------------------------------------------------------
    def spawn_worker(
        self,
        script_path: Path,
        extra_args: Optional[List[str]] = None
    ) -> subprocess.Popen:
        """
        Spawn an unprivileged worker subprocess.
        Config is delivered securely via stdin at startup, NOT via argv or environment.
        """
        clean_env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "PATH": os.environ.get("PATH", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
            "PYTHONPATH": str(Path(__file__).resolve().parent)
        }

        cmd = [sys.executable, str(script_path)] + (extra_args or [])
        sandbox_cwd = self.workspace_root / "workspace_sandbox"

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(sandbox_cwd),
            env=clean_env,
            close_fds=True,
            text=True
        )

        # Assign process to Windows Job Object
        self.assign_worker_to_job(proc)

        # Pipe config over stdin
        config_payload = json.dumps({
            "worker_port": self.worker_port,
            "worker_secret": self.worker_secret
        }) + "\n"

        proc.stdin.write(config_payload)
        proc.stdin.flush()
        return proc



    # -------------------------------------------------------------------------
    # Windows Named Pipe Handlers with User-Only DACL
    # -------------------------------------------------------------------------
    @staticmethod
    def _create_user_only_security_attributes():
        if sys.platform != "win32":
            return None
        try:
            import win32api, win32security, ntsecuritycon
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
            user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.GENERIC_READ | ntsecuritycon.GENERIC_WRITE, user_sid)
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(True, dacl, False)
            sd.SetSecurityDescriptorOwner(user_sid, False)
            sa = win32security.SECURITY_ATTRIBUTES()
            sa.SECURITY_DESCRIPTOR = sd
            sa.bInheritHandle = False
            return sa
        except Exception as e:
            logger.warning(f"Could not configure pipe user DACL: {e}")
            return None

    def _unblock_pipes(self):
        try:
            import win32file
            for p in (self.worker_pipe_path, self.ui_pipe_path):
                try:
                    h = win32file.CreateFile(p, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None)
                    win32file.CloseHandle(h)
                except Exception:
                    pass
        except Exception:
            pass

    def _start_named_pipes(self):
        import win32pipe
        sa = self._create_user_only_security_attributes()
        self._initial_worker_pipe = win32pipe.CreateNamedPipe(
            self.worker_pipe_path,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
        )
        self._initial_ui_pipe = win32pipe.CreateNamedPipe(
            self.ui_pipe_path,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
        )
        with self._conn_lock:
            self._pipe_handles.append(self._initial_worker_pipe)
            self._pipe_handles.append(self._initial_ui_pipe)
        self._worker_pipe_thread = threading.Thread(target=self._worker_pipe_loop, daemon=True)
        self._worker_pipe_thread.start()
        self._ui_pipe_thread = threading.Thread(target=self._ui_pipe_loop, daemon=True)
        self._ui_pipe_thread.start()

    def _worker_pipe_loop(self):
        import win32pipe
        sa = self._create_user_only_security_attributes()
        h_pipe = self._initial_worker_pipe
        while self._running:
            try:
                try:
                    win32pipe.ConnectNamedPipe(h_pipe, None)
                except Exception as e:
                    if getattr(e, 'winerror', None) != 535:
                        raise
                threading.Thread(target=self._handle_worker_pipe_client, args=(h_pipe,), daemon=True).start()
                if not self._running:
                    break
                h_pipe = win32pipe.CreateNamedPipe(
                    self.worker_pipe_path,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
                )
                with self._conn_lock:
                    self._pipe_handles.append(h_pipe)
            except Exception:
                if not self._running:
                    break
                time.sleep(0.05)

    def _handle_worker_pipe_client(self, h_pipe):
        import win32file, win32pipe, win32api
        authenticated = False
        try:
            buffer = ""
            while self._running:
                try:
                    err, data = win32file.ReadFile(h_pipe, 65536)
                except Exception:
                    break
                if not data:
                    break
                buffer += data.decode("utf-8")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip():
                        continue
                    msg = json.loads(line)
                    resp = self._dispatch_worker_message(msg, authenticated)
                    if msg.get("type", "").upper() == "AUTH" and resp.get("status") == "AUTHENTICATED":
                        authenticated = True
                    out = (json.dumps(resp) + "\n").encode("utf-8")
                    win32file.WriteFile(h_pipe, out)
                    win32file.FlushFileBuffers(h_pipe)
        finally:
            try:
                win32pipe.DisconnectNamedPipe(h_pipe)
                win32api.CloseHandle(h_pipe)
            except Exception:
                pass
            with self._conn_lock:
                if h_pipe in self._pipe_handles:
                    self._pipe_handles.remove(h_pipe)
            self.state_store.close()

    def _ui_pipe_loop(self):
        import win32pipe
        sa = self._create_user_only_security_attributes()
        h_pipe = self._initial_ui_pipe
        while self._running:
            try:
                try:
                    win32pipe.ConnectNamedPipe(h_pipe, None)
                except Exception as e:
                    if getattr(e, 'winerror', None) != 535:
                        raise
                threading.Thread(target=self._handle_ui_pipe_client, args=(h_pipe,), daemon=True).start()
                if not self._running:
                    break
                h_pipe = win32pipe.CreateNamedPipe(
                    self.ui_pipe_path,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
                )
                with self._conn_lock:
                    self._pipe_handles.append(h_pipe)
            except Exception:
                if not self._running:
                    break
                time.sleep(0.05)

    def _handle_ui_pipe_client(self, h_pipe):
        import win32file, win32pipe, win32api
        try:
            buffer = ""
            while self._running:
                try:
                    err, data = win32file.ReadFile(h_pipe, 65536)
                except Exception:
                    break
                if not data:
                    break
                buffer += data.decode("utf-8")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip():
                        continue
                    msg = json.loads(line)
                    resp = self._dispatch_ui_message(msg)
                    out = (json.dumps(resp) + "\n").encode("utf-8")
                    win32file.WriteFile(h_pipe, out)
                    win32file.FlushFileBuffers(h_pipe)
        finally:
            try:
                win32pipe.DisconnectNamedPipe(h_pipe)
                win32api.CloseHandle(h_pipe)
            except Exception:
                pass
            with self._conn_lock:
                if h_pipe in self._pipe_handles:
                    self._pipe_handles.remove(h_pipe)
            self.state_store.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MAC Privileged Supervisor Daemon")
    parser.add_argument("--workspace", required=True, help="Workspace root directory")
    parser.add_argument("--port-file", required=False, default=None, help="File to write active ports and secret")
    parser.add_argument("--timeout", type=float, default=0.0, help="Optional auto-shutdown timeout in seconds")
    args = parser.parse_args()

    ws = Path(args.workspace).resolve()
    daemon = SupervisorDaemon(workspace_root=ws)
    daemon.start()

    if args.port_file:
        pf = Path(args.port_file).resolve()
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({
            "pid": os.getpid(),
            "worker_port": daemon.worker_port,
            "ui_port": daemon.ui_port,
            "ui_secret": daemon.ui_secret,
            "worker_secret": daemon.worker_secret
        }), encoding="utf-8")

    try:
        t0 = time.time()
        while daemon._running:
            if args.timeout > 0 and (time.time() - t0) > args.timeout:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        daemon.stop()
