"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: local_daemon.py
Description: Production-grade isolated execution daemon responsible for secure OS/Shell
             command execution and sandboxed workspace file I/O with timeout enforcement.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from protocol import ExecutionResult


class WorkspaceSecurityError(PermissionError):
    """Raised when an operation attempts to escape the sandboxed workspace root."""
    pass


class LocalExecDaemon:
    """
    Isolated execution daemon for running shell processes and workspace operations.
    Enforces path containment, execution timeouts, and telemetry tracking.
    """

    def __init__(self, workspace_root: Optional[str | Path] = None):
        """
        Initialize the Local Execution Daemon.

        :param workspace_root: Base directory where file access is restricted.
                               Defaults to current working directory.
        """
        if workspace_root is None:
            self.workspace_root = Path.cwd().resolve()
        else:
            self.workspace_root = Path(workspace_root).resolve()

        # Ensure root directory exists
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self._current_proc: Optional[subprocess.Popen] = None

    def _terminate_process_tree(self, proc: Optional[subprocess.Popen]) -> None:
        """Terminates process and all descendant child processes to prevent zombies."""
        if not proc or proc.poll() is not None:
            return
        try:
            if sys.platform.startswith("win"):
                subprocess.run(
                    f"taskkill /F /T /PID {proc.pid}",
                    shell=True,
                    capture_output=True,
                    timeout=5
                )
            else:
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def abort_active(self) -> bool:
        """Forcibly terminates currently executing subprocess if active."""
        if self._current_proc and self._current_proc.poll() is None:
            self._terminate_process_tree(self._current_proc)
            return True
        return False

    def _resolve_safe_path(self, file_path: str | Path) -> Path:
        """
        Verify that the requested file path resides strictly inside the workspace.
        Prevents directory traversal (e.g. '../../etc/passwd').
        """
        candidate = Path(file_path)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.workspace_root / candidate).resolve()

        try:
            # Check relative containment
            resolved.relative_to(self.workspace_root)
        except ValueError as err:
            raise WorkspaceSecurityError(
                f"Security Sandbox Violation: Path '{file_path}' resolves to '{resolved}' "
                f"which is outside workspace root '{self.workspace_root}'."
            ) from err

        return resolved

    def execute_command(
        self,
        command: str,
        timeout_seconds: float = 25.0,
        request_id: Optional[str] = None
    ) -> ExecutionResult:
        """
        Executes a shell/OS command in an isolated subprocess.
        Enforces 25s timeout limits and process tree termination to prevent zombie hanging.

        :param command: Shell command to execute.
        :param timeout_seconds: Maximum allowed execution time (Default: 25.0s).
        :param request_id: Optional correlation tracking identifier.
        :return: ExecutionResult containing stdout, stderr, exit code, and latency.
        """
        req_id = request_id or str(uuid.uuid4())
        start_time = time.perf_counter()

        if not command or not command.strip():
            return ExecutionResult(
                requestId=req_id,
                success=False,
                stdout="",
                stderr="Execution error: Empty command provided.",
                exitCode=1,
                latencyMs=0.0
            )

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=str(self.workspace_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self._current_proc = proc

            try:
                stdout, stderr = proc.communicate(timeout=timeout_seconds)
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
                return ExecutionResult(
                    requestId=req_id,
                    success=(proc.returncode == 0),
                    stdout=stdout or "",
                    stderr=stderr or "",
                    exitCode=proc.returncode or 0,
                    latencyMs=latency_ms
                )
            except subprocess.TimeoutExpired:
                # Terminate process tree to prevent zombie process
                self._terminate_process_tree(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=2)
                except Exception:
                    stdout, stderr = "", ""
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

                return ExecutionResult(
                    requestId=req_id,
                    success=False,
                    stdout=stdout or "",
                    stderr=f"Execution exceeded maximum allowed timeout ({timeout_seconds}s limit). Process safely terminated.",
                    exitCode=-1,
                    latencyMs=latency_ms
                )
            finally:
                self._current_proc = None

        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            return ExecutionResult(
                requestId=req_id,
                success=False,
                stdout="",
                stderr=f"Subprocess spawn failure: {type(exc).__name__}: {str(exc)}",
                exitCode=127,
                latencyMs=latency_ms
            )

    def read_workspace_file(self, file_path: str) -> str:
        """
        Safely read a file within the workspace boundaries.

        :param file_path: Relative or absolute path inside the workspace.
        :return: String content of the file.
        :raises FileNotFoundError: If file does not exist.
        :raises WorkspaceSecurityError: If path escapes the workspace.
        """
        target = self._resolve_safe_path(file_path)

        if not target.exists():
            raise FileNotFoundError(f"Workspace file not found: '{file_path}' (Resolved: '{target}')")

        if not target.is_file():
            raise IsADirectoryError(f"Target is a directory, not a file: '{file_path}'")

        try:
            return target.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Fallback for binary or encoded data
            raw_bytes = target.read_bytes()
            return raw_bytes.decode("utf-8", errors="replace")

    def write_workspace_file(self, file_path: str, content: str) -> bool:
        """
        Safely write content to a file inside workspace boundaries.
        Creates parent directories automatically if needed.

        :param file_path: Relative or absolute path inside the workspace.
        :param content: UTF-8 string content to write.
        :return: True upon successful write.
        :raises WorkspaceSecurityError: If path escapes the workspace.
        """
        target = self._resolve_safe_path(file_path)

        try:
            # Ensure parent directories exist
            target.parent.mkdir(parents=True, exist_ok=True)

            # Atomic write pattern using temp sibling file
            temp_target = target.with_suffix(f"{target.suffix}.tmp.{uuid.uuid4().hex[:8]}")
            temp_target.write_text(content, encoding="utf-8")
            temp_target.replace(target)
            return True
        except Exception as err:
            # Clean up temp file if failed
            if 'temp_target' in locals() and temp_target.exists():
                try:
                    temp_target.unlink()
                except OSError:
                    pass
            raise IOError(f"Failed writing to workspace file '{file_path}': {err}") from err
