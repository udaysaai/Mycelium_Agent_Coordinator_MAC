"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: coordinator.py
Description: Central Intelligence Traffic Manager & HOL (Human-On-The-Loop) Safety Gate.
             Integrates sub-10ms semantic tool matching, zero-latency bypass for READ_ONLY
             operations, and mandatory quarantine with operator hook for MUTATING actions.
"""

from __future__ import annotations

import os
import platform
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
    ToolMatchResult,
)
from local_daemon import LocalExecDaemon
from mcp_gateway import (
    ExecuteShellCommandParams,
    ListDirectoryParams,
    MCPGateway,
    ReadWorkspaceFileParams,
    SystemDiagnosticsParams,
    WriteWorkspaceFileParams,
)


class MyceliumCoordinator:
    """
    Central Intelligence Coordinator for US Neural Agent Mesh.
    Manages semantic tool routing, HOL safety boundaries, and split execution.
    """

    def __init__(
        self,
        local_daemon: Optional[LocalExecDaemon] = None,
        mcp_gateway: Optional[MCPGateway] = None,
        human_confirmation_hook: Optional[Callable[[HOLQuarantineEvent], bool]] = None
    ):
        """
        Initialize the Mycelium Coordinator.

        :param local_daemon: Execution daemon for shell and workspace operations.
        :param mcp_gateway: Gateway managing tool contracts and semantic vector mesh.
        :param human_confirmation_hook: Callback invoked when an action is quarantined.
        """
        self.daemon = local_daemon or LocalExecDaemon()
        self.gateway = mcp_gateway or MCPGateway()
        self.human_confirmation_hook = human_confirmation_hook or self._default_cli_human_hook

        # Telemetry logs
        self.quarantine_history: List[HOLQuarantineEvent] = []
        self.execution_audit: List[ExecutionResult] = []

        # Bootstrap core tools into MCP Gateway
        self._bootstrap_core_tools()

    def _bootstrap_core_tools(self) -> None:
        """Register fundamental local tools with safety tiers and schemas."""
        # 1. Read Workspace File (READ_ONLY)
        self.gateway.register_tool(
            name="read_workspace_file",
            description="Read textual or configuration content of a file within the workspace safely.",
            safety_tier=SafetyTier.READ_ONLY,
            schema_model=ReadWorkspaceFileParams,
            handler=self.daemon.read_workspace_file,
            tags=["read", "file", "inspect", "cat", "view", "workspace", "config"]
        )

        # 2. Write Workspace File (MUTATING)
        self.gateway.register_tool(
            name="write_workspace_file",
            description="Write, update, or create a file inside the sandboxed workspace directory.",
            safety_tier=SafetyTier.MUTATING,
            schema_model=WriteWorkspaceFileParams,
            handler=self.daemon.write_workspace_file,
            tags=["write", "create", "file", "modify", "save", "workspace", "update"]
        )

        # 3. Execute Shell Command (MUTATING)
        self.gateway.register_tool(
            name="execute_shell_command",
            description="Execute arbitrary OS/Shell commands and system processes.",
            safety_tier=SafetyTier.MUTATING,
            schema_model=ExecuteShellCommandParams,
            handler=lambda command, timeout_seconds=15.0: self.daemon.execute_command(
                command=command,
                timeout_seconds=timeout_seconds
            ),
            tags=["shell", "bash", "cmd", "execute", "run", "process", "terminal", "os"]
        )

        # Pre-cache static platform metadata to prevent Windows registry/WMI lookup latency
        static_platform = {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": os.environ.get("PROCESSOR_IDENTIFIER", platform.machine()),
            "python_version": sys.version.split()[0],
            "cpu_count": os.cpu_count() or 1
        }

        # 4. System Diagnostics (READ_ONLY)
        def _get_system_diagnostics(include_environment: bool = False) -> Dict[str, Any]:
            diag = dict(static_platform)
            diag["timestamp"] = time.time()
            if include_environment:
                sanitized_env = {
                    k: ("***REDACTED***" if any(s in k.lower() for s in ["key", "secret", "token", "pass"]) else v)
                    for k, v in os.environ.items()
                }
                diag["environment"] = sanitized_env
            return diag

        self.gateway.register_tool(
            name="system_diagnostics",
            description="Introspect hardware, OS platform, Python runtime, and host system health.",
            safety_tier=SafetyTier.READ_ONLY,
            schema_model=SystemDiagnosticsParams,
            handler=_get_system_diagnostics,
            tags=["system", "status", "metrics", "health", "diagnostics", "host", "specs", "cpu"]
        )

        # 5. List Workspace Directory (READ_ONLY)
        def _list_directory(directory_path: str = ".") -> List[str]:
            target = self.daemon._resolve_safe_path(directory_path)
            if not target.is_dir():
                raise NotADirectoryError(f"Target '{directory_path}' is not a directory.")
            return [p.name for p in target.iterdir()]

        self.gateway.register_tool(
            name="list_workspace_directory",
            description="List file and directory entries inside workspace directory.",
            safety_tier=SafetyTier.READ_ONLY,
            schema_model=ListDirectoryParams,
            handler=_list_directory,
            tags=["list", "ls", "dir", "directory", "browse", "folder"]
        )

    def set_human_confirmation_hook(self, hook: Callable[[HOLQuarantineEvent], bool]) -> None:
        """Configure a custom human confirmation hook for HOL quarantine evaluation."""
        self.human_confirmation_hook = hook

    @staticmethod
    def _default_cli_human_hook(quarantine: HOLQuarantineEvent) -> bool:
        """Fallback standard terminal prompt for operator approval."""
        req = quarantine.request
        print(f"\n[HOL GUARD QUARANTINE INTERVENTION]")
        print(f"Request ID: {req.requestId}")
        print(f"Intent    : {req.intent}")
        print(f"Privilege : {req.privilegeTier.value}")
        print(f"Safety    : {req.safetyTier.value}")
        print(f"Reason    : {quarantine.quarantineReason}")
        print(f"Payload   : {req.payload}")
        try:
            choice = input("Authorize state-altering execution? (y/N): ").strip().lower()
            return choice in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def route_intent(self, intent: str, top_k: int = 1) -> List[ToolMatchResult]:
        """
        Discover matching tools in sub-10ms via Mycelium Semantic Vector-Mesh.
        """
        return self.gateway.discover_tools(intent, top_k=top_k)

    def dispatch(self, request: ActionRequest) -> ExecutionResult:
        """
        Central execution gatekeeper.
        
        HOL Guard Rules:
        1. If safetyTier is MUTATING -> Quarantine and await human confirmation.
        2. If privilegeTier is BACKGROUND and executing a state-altering command -> Quarantine.
        3. If safetyTier is READ_ONLY -> Immediate bypass with zero latency penalty.
        """
        dispatch_start = time.perf_counter()

        # Step 1: Semantic discovery check if tool not explicitly indicated in payload
        matched_tools = self.route_intent(request.intent, top_k=1)
        best_tool_match = matched_tools[0] if matched_tools else None

        # Check effective safety classification (strictest wins)
        effective_safety = request.safetyTier
        if best_tool_match and best_tool_match.tool.safetyTier == SafetyTier.MUTATING:
            effective_safety = SafetyTier.MUTATING

        # Step 2: Evaluate HOL Guard Criteria
        is_quarantine_required = (
            effective_safety == SafetyTier.MUTATING
            or (request.privilegeTier == PrivilegeTier.BACKGROUND and "command" in request.payload)
        )

        if is_quarantine_required:
            quarantine_reason = (
                f"State-altering MUTATING action under {request.privilegeTier.value} privilege requires "
                f"explicit Human-On-The-Loop authorization."
            )
            quarantine_event = HOLQuarantineEvent(
                request=request,
                quarantineReason=quarantine_reason,
                decision=HOLApprovalStatus.PENDING
            )

            # Invoke Human-On-The-Loop Hook
            approved = self.human_confirmation_hook(quarantine_event)
            quarantine_event.reviewedAt = time.time()

            if not approved:
                quarantine_event.decision = HOLApprovalStatus.REJECTED
                self.quarantine_history.append(quarantine_event)
                latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)

                rejected_result = ExecutionResult(
                    requestId=request.requestId,
                    success=False,
                    stdout="",
                    stderr=f"HOL Guard Blocked: Action '{request.intent}' was quarantined and rejected by operator.",
                    exitCode=403,
                    latencyMs=latency_ms
                )
                self.execution_audit.append(rejected_result)
                return rejected_result

            # Approved by human operator
            quarantine_event.decision = HOLApprovalStatus.APPROVED
            self.quarantine_history.append(quarantine_event)

        # Step 3: Dispatch Execution
        result = self._execute_request(request, best_tool_match)
        total_latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)

        # Update end-to-end latency
        result.latencyMs = total_latency_ms
        self.execution_audit.append(result)
        return result

    def _execute_request(
        self,
        request: ActionRequest,
        best_match: Optional[ToolMatchResult]
    ) -> ExecutionResult:
        """Execute request using either tool handler or direct daemon execution."""
        # Case A: Explicit shell command payload
        if "command" in request.payload:
            cmd = request.payload["command"]
            timeout = request.payload.get("timeout_seconds", 15.0)
            return self.daemon.execute_command(
                command=cmd,
                timeout_seconds=timeout,
                request_id=request.requestId
            )

        # Case B: Tool name explicitly specified in payload
        tool_name = request.payload.get("tool_name")
        tool_args = request.payload.get("arguments", {})

        # If not explicit in payload, check semantic vector match
        if not tool_name and best_match and best_match.similarityScore > 0.15:
            tool_name = best_match.tool.name
            tool_args = request.payload

        if tool_name:
            try:
                raw_out = self.gateway.execute_tool(tool_name, tool_args)
                out_str = str(raw_out) if not isinstance(raw_out, str) else raw_out
                return ExecutionResult(
                    requestId=request.requestId,
                    success=True,
                    stdout=out_str,
                    stderr="",
                    exitCode=0,
                    latencyMs=0.0
                )
            except Exception as err:
                return ExecutionResult(
                    requestId=request.requestId,
                    success=False,
                    stdout="",
                    stderr=f"Tool Execution Error: {type(err).__name__}: {str(err)}",
                    exitCode=1,
                    latencyMs=0.0
                )

        # Case C: Unrouted intent fallback
        return ExecutionResult(
            requestId=request.requestId,
            success=False,
            stdout="",
            stderr=f"No matching tool or execution strategy identified for intent: '{request.intent}'",
            exitCode=404,
            latencyMs=0.0
        )
