"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: coordinator.py
Description: Central Intelligence Traffic Manager & HOL (Human-On-The-Loop) Safety Gate.
             Integrates Conversational Intake Gate, Dynamic Capability Grants (T0/T1/T2),
             Durable SQLite WAL State Storage, and Deterministic Out-of-Band Verifiers.
"""

from __future__ import annotations

import os
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    ToolMatchResult,
    VerificationReceipt,
)
from local_daemon import LocalExecDaemon, WorkspaceSecurityError
from mcp_gateway import (
    ExecuteShellCommandParams,
    ListDirectoryParams,
    MCPGateway,
    ReadWorkspaceFileParams,
    SystemDiagnosticsParams,
    WriteWorkspaceFileParams,
)
from state_store import StateStore
from policy_engine import PolicyEngine, PolicyVerdict
from verifier import DeterministicVerifier
from intake_gate import IntakeGate, IntakeOutcome


class MyceliumCoordinator:
    """
    Central Intelligence Coordinator for US Neural Agent Mesh.
    Manages semantic tool routing, HOL safety boundaries, split execution,
    and out-of-band deterministic verification.
    """

    def __init__(
        self,
        local_daemon: Optional[LocalExecDaemon] = None,
        mcp_gateway: Optional[MCPGateway] = None,
        human_confirmation_hook: Optional[Callable[[HOLQuarantineEvent], bool]] = None,
        state_store: Optional[StateStore] = None,
        key_file_path: Optional[str | Path] = None,
        policy_engine: Optional[PolicyEngine] = None,
        verifier: Optional[DeterministicVerifier] = None
    ):
        """
        Initialize the Mycelium Coordinator.

        :param local_daemon: Execution daemon for shell and workspace operations.
        :param mcp_gateway: Gateway managing tool contracts and semantic vector mesh.
        :param human_confirmation_hook: Callback invoked when an action is quarantined.
        :param state_store: Durable SQLite persistence for contracts, quarantines, and receipts.
        :param key_file_path: External path for HMAC signing key.
        :param policy_engine: PolicyEngine instance.
        :param verifier: DeterministicVerifier instance.
        """
        self.daemon = local_daemon or LocalExecDaemon()
        self.gateway = mcp_gateway or MCPGateway()
        self.human_confirmation_hook = human_confirmation_hook or self._default_cli_human_hook

        # Initialize Durable Governance & Verification Subsystems
        self.state_store = state_store or StateStore(
            db_path=self.daemon.workspace_root / "data" / "mac_state.db"
        )
        self.policy_engine = policy_engine or PolicyEngine(
            sandbox_dirname="workspace_sandbox",
            key_file_path=key_file_path
        )
        self.verifier = verifier or DeterministicVerifier(
            workspace_root=self.daemon.workspace_root,
            state_store=self.state_store
        )
        self.intake_gate = IntakeGate()

        # Telemetry logs
        self.quarantine_history: List[HOLQuarantineEvent] = []
        self.execution_audit: List[ExecutionResult] = []

        # Bootstrap core tools into MCP Gateway
        self._bootstrap_core_tools()

    def _bootstrap_core_tools(self) -> None:
        """Register fundamental local tools with safety tiers and schemas."""
        # 1. Read Workspace File (T0: READ_ONLY)
        self.gateway.register_tool(
            name="read_workspace_file",
            description="Read textual or configuration content of a file within the workspace safely.",
            safety_tier=SafetyTier.READ_ONLY,
            schema_model=ReadWorkspaceFileParams,
            handler=self.daemon.read_workspace_file,
            tags=["read", "file", "inspect", "cat", "view", "workspace", "config"]
        )

        # 2. Write Workspace File (T1 / T2 depending on target path)
        self.gateway.register_tool(
            name="write_workspace_file",
            description="Write, update, or create a file inside the sandboxed workspace directory.",
            safety_tier=SafetyTier.MUTATING,
            schema_model=WriteWorkspaceFileParams,
            handler=self.daemon.write_workspace_file,
            tags=["write", "create", "file", "modify", "save", "workspace", "update"]
        )

        RESERVED_DEVICE_NAMES = {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        }

        # 3. Hardened Sandboxed File Writer with Atomic Sync (T1: MUTATING_SANDBOX)
        def _sandboxed_atomic_writer(file_path: str, content: str) -> Dict[str, Any]:
            sandbox_dir = (self.daemon.workspace_root / "workspace_sandbox").resolve()
            sandbox_dir.mkdir(parents=True, exist_ok=True)

            raw_path_str = str(file_path)
            if not raw_path_str:
                raise ValueError("file_path cannot be empty")

            # 1. Reject Alternate Data Streams (ADS) and Drive Letters
            if ":" in raw_path_str:
                raise PermissionError(f"Alternate data streams and drive letters forbidden in sandbox: '{file_path}'")

            # 2. Reject UNC network paths and NT prefixes
            norm_slashes = raw_path_str.replace("\\", "/")
            if (
                norm_slashes.startswith("//")
                or norm_slashes.startswith("/?")
                or norm_slashes.startswith("/.")
                or raw_path_str.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\"))
            ):
                raise PermissionError(f"UNC, NT, and network device prefixes forbidden in sandbox: '{file_path}'")

            # 3. Reject absolute paths
            if os.path.isabs(raw_path_str) or norm_slashes.startswith("/"):
                raise PermissionError(f"Absolute paths forbidden in sandbox: '{file_path}'")

            # Split path into raw components to validate each token
            raw_parts = [p for p in norm_slashes.split("/") if p != ""]

            for part in raw_parts:
                # 4. Trailing dot or trailing space check (NTFS stripping causes aliasing)
                if part.endswith(".") or part.endswith(" "):
                    raise PermissionError(f"Trailing dot or space in path component forbidden: '{part}'")

                # 5. Path traversal sequence
                if part == "..":
                    raise PermissionError(f"Path traversal sequence '..' forbidden in sandbox: '{file_path}'")

                # 6. 8.3 short-name aliases
                if "~" in part:
                    raise PermissionError(f"8.3 short-name alias forbidden in sandbox: '{part}'")

                # 7. Reserved Windows device names
                base_name = part.split(".")[0].upper()
                if base_name in RESERVED_DEVICE_NAMES:
                    raise PermissionError(f"Windows reserved device name forbidden: '{part}'")

            # Strip case-insensitive "workspace_sandbox/" prefix if present
            clean_rel = norm_slashes.lstrip("/")
            prefix = "workspace_sandbox/"
            if clean_rel.lower().startswith(prefix):
                clean_rel = clean_rel[len(prefix):]

            if not clean_rel or clean_rel == ".":
                raise PermissionError("Target cannot be empty or the sandbox directory itself")

            target = (sandbox_dir / clean_rel)

            # 8. Real path resolution and commonpath containment (blocks junctions & symlink escapes)
            real_sandbox = os.path.realpath(str(sandbox_dir))
            real_target = os.path.realpath(str(target))
            real_parent = os.path.realpath(str(target.parent))

            try:
                cp_target = os.path.commonpath([real_sandbox, real_target])
                cp_parent = os.path.commonpath([real_sandbox, real_parent])
                if cp_target != real_sandbox or cp_parent != real_sandbox:
                    raise PermissionError(f"Sandboxed file writer violated sandbox boundary: '{file_path}'")
            except (ValueError, OSError) as exc:
                raise PermissionError(f"Sandboxed file writer violated sandbox boundary: '{file_path}'") from exc

            target.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write pattern with flush and fsync
            tmp_target = target.with_suffix(f"{target.suffix}.tmp.{uuid.uuid4().hex[:6]}")
            with open(tmp_target, "w", encoding="utf-8", newline="") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            tmp_target.replace(target)
            return {
                "success": True,
                "filePath": str(target.relative_to(self.daemon.workspace_root)).replace("\\", "/"),
                "bytesWritten": len(content.encode("utf-8")),
                "atomic": True
            }

        self.gateway.register_tool(
            name="sandboxed_file_writer",
            description="Atomically write files strictly confined inside the isolated workspace_sandbox directory.",
            safety_tier=SafetyTier.MUTATING_SANDBOX,
            schema_model=WriteWorkspaceFileParams,
            handler=_sandboxed_atomic_writer,
            tags=["sandbox", "write", "atomic", "file", "safe_write"]
        )

        # 4. Execute Shell Command (T2: MUTATING)
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

        # Pre-cache static platform metadata
        static_platform = {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": os.environ.get("PROCESSOR_IDENTIFIER", platform.machine()),
            "python_version": sys.version.split()[0],
            "cpu_count": os.cpu_count() or 1
        }

        # 5. System Diagnostics (T0: READ_ONLY)
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
            tags=["system", "status", "metrics", "health", "diagnostics", "host", "specs", "cpu", "telemetry", "platform", "node"]
        )

        # 6. List Workspace Directory (T0: READ_ONLY)
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
        """Configure custom operator confirmation callback."""
        self.human_confirmation_hook = hook

    @staticmethod
    def _default_cli_human_hook(quarantine: HOLQuarantineEvent) -> bool:
        """Fallback standard terminal prompt for operator approval."""
        req = quarantine.request
        print(f"\n[HOL GUARD QUARANTINE INTERVENTION]")
        print(f"Quarantine ID: {quarantine.quarantineId}")
        print(f"One-Shot Tok : {quarantine.oneShotToken}")
        print(f"Plain Impact : {quarantine.plainImpact}")
        print(f"Intent       : {req.intent}")
        print(f"Safety Tier  : {req.safetyTier.value}")
        print(f"Reason       : {quarantine.quarantineReason}")
        print(f"Payload      : {req.payload}")
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
        Enforces Plane 1 (Intake), Plane 3 (Policy & Quarantine), and Plane 4 (Verifier).
        """
        dispatch_start = time.perf_counter()

        # -------------------------------------------------------------------
        # Step 1: Plane 1 - Conversational Parameter Intake & Plan Gate
        # -------------------------------------------------------------------
        intake_outcome: IntakeOutcome = self.intake_gate.evaluate_intent(
            intent=request.intent,
            payload=request.payload
        )

        if intake_outcome.isConversational:
            latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)
            return ExecutionResult(
                requestId=request.requestId,
                contractId=None,
                success=True,
                stdout=intake_outcome.responseMessage,
                stderr="",
                exitCode=0,
                latencyMs=latency_ms,
                tierLevel=TierLevel.T0
            )

        if not intake_outcome.isReadyForExecution and intake_outcome.missingSlots:
            latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)
            return ExecutionResult(
                requestId=request.requestId,
                contractId=None,
                success=False,
                stdout=intake_outcome.responseMessage,
                stderr="Missing parameter slots required to compile execution contract.",
                exitCode=422,
                latencyMs=latency_ms,
                tierLevel=TierLevel.T0
            )

        contract: Optional[TaskContract] = intake_outcome.contract
        if contract:
            request.contractId = contract.contractId
            self.state_store.save_contract(contract)

        # -------------------------------------------------------------------
        # Step 2: Semantic Tool Discovery
        # -------------------------------------------------------------------
        matched_tools = self.route_intent(request.intent, top_k=1)
        best_tool_match = matched_tools[0] if matched_tools else None

        tool_name = request.payload.get("tool_name")
        if not tool_name and best_tool_match and best_tool_match.similarityScore >= 0.55:
            tool_name = best_tool_match.tool.name
        elif not tool_name and "command" in request.payload:
            tool_name = "execute_shell_command"

        # T0 Fast-Path for idempotent READ_ONLY inspection requests
        is_read_tool = False
        if tool_name in ("system_diagnostics", "read_workspace_file", "list_workspace_directory"):
            is_read_tool = True
        elif best_tool_match and getattr(best_tool_match.tool, "safetyTier", None) == SafetyTier.READ_ONLY:
            is_read_tool = True

        if request.safetyTier == SafetyTier.READ_ONLY and is_read_tool and not request.payload.get("command"):
            raw_output, exit_code, stdout, stderr = self._run_actuator(request, tool_name, best_tool_match)
            effective_tool = tool_name or (best_tool_match.tool.name if best_tool_match else "action")
            receipt = self.verifier.verify_action(
                tool_name=effective_tool,
                payload=request.payload,
                raw_output=raw_output,
                request_id=request.requestId,
                contract=contract,
                persist=False
            )
            total_latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)
            result = ExecutionResult(
                requestId=request.requestId,
                contractId=request.contractId,
                success=(exit_code == 0),
                stdout=stdout or (str(raw_output) if raw_output is not None else ""),
                stderr=stderr,
                exitCode=exit_code,
                latencyMs=total_latency_ms,
                tierLevel=TierLevel.T0,
                receipt=receipt
            )
            self.execution_audit.append(result)
            return result

        # -------------------------------------------------------------------
        # Step 3: Plane 3 - Capability Grant Policy Engine (T0/T1/T2)
        # -------------------------------------------------------------------
        verdict: PolicyVerdict = self.policy_engine.evaluate(
            request=request,
            contract=contract,
            tool_name=tool_name
        )

        # If T2 action requires quarantine
        if verdict.requiresQuarantine:
            has_valid_token = False
            if request.oneShotToken:
                # Execution-time argument tampering & token authenticity check
                actual_target = request.payload.get("command", request.payload.get("file_path", ""))
                current_call_hash = self.policy_engine.compute_call_hash(
                    tool_name=tool_name or "action",
                    payload=request.payload,
                    target=str(actual_target)
                )
                quarantine_id = request.payload.get("quarantineId", "")
                has_valid_token = self.state_store.validate_one_shot_token(
                    quarantine_id=quarantine_id,
                    token=request.oneShotToken,
                    policy_engine=self.policy_engine,
                    current_call_hash=current_call_hash
                )
                if not has_valid_token:
                    latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)
                    rejected_result = ExecutionResult(
                        requestId=request.requestId,
                        contractId=request.contractId,
                        success=False,
                        stdout="",
                        stderr="Security Violation: Invalid, expired, replayed, or argument-tampered authorization token.",
                        exitCode=403,
                        latencyMs=latency_ms,
                        tierLevel=verdict.tierLevel
                    )
                    self.execution_audit.append(rejected_result)
                    return rejected_result
            else:
                # No token provided: Trigger quarantine and await human authorization
                quarantine_id = str(uuid.uuid4())
                token = self.policy_engine.generate_hmac_token(
                    quarantine_id,
                    verdict.callHash,
                    verdict.expiresAt
                )

                quarantine_event = HOLQuarantineEvent(
                    quarantineId=quarantine_id,
                    contractId=request.contractId,
                    request=request,
                    quarantineReason=verdict.reason,
                    decision=HOLApprovalStatus.PENDING,
                    callHash=verdict.callHash,
                    oneShotToken=token,
                    plainImpact=verdict.plainImpact,
                    expiresAt=verdict.expiresAt
                )

                # Persist quarantine into durable SQLite WAL store
                self.state_store.save_quarantine(
                    event=quarantine_event,
                    tool_name=tool_name or "action",
                    payload=request.payload
                )

                if contract:
                    self.state_store.update_contract_status(contract.contractId, TaskContractStatus.QUARANTINED)

                # Invoke Human-On-The-Loop Confirmation Hook (Isolated Supervisor Channel)
                approved = self.human_confirmation_hook(quarantine_event)
                quarantine_event.reviewedAt = time.time()

                if not approved:
                    quarantine_event.decision = HOLApprovalStatus.REJECTED
                    self.quarantine_history.append(quarantine_event)
                    self.state_store.update_quarantine_decision(
                        quarantine_event.quarantineId,
                        HOLApprovalStatus.REJECTED,
                        notes="Operator denied execution."
                    )
                    if contract:
                        self.state_store.update_contract_status(contract.contractId, TaskContractStatus.FAILED)

                    latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)
                    rejected_result = ExecutionResult(
                        requestId=request.requestId,
                        contractId=request.contractId,
                        success=False,
                        stdout="",
                        stderr=(
                            f"HOL Guard Blocked: Action '{request.intent}' was quarantined and rejected by operator. "
                            f"Impact: {verdict.plainImpact}"
                        ),
                        exitCode=403,
                        latencyMs=latency_ms,
                        tierLevel=verdict.tierLevel
                    )
                    self.execution_audit.append(rejected_result)
                    return rejected_result

                # Approved by operator: Mark approved and assign HMAC token
                quarantine_event.decision = HOLApprovalStatus.APPROVED
                self.quarantine_history.append(quarantine_event)
                self.state_store.update_quarantine_decision(
                    quarantine_event.quarantineId,
                    HOLApprovalStatus.APPROVED,
                    notes="Authorized by human operator."
                )
                with self.state_store._get_connection() as conn:
                    conn.execute(
                        "UPDATE quarantines SET one_shot_token = ? WHERE quarantine_id = ?",
                        (token, quarantine_event.quarantineId)
                    )
                request.oneShotToken = token
                # Immediately consume one-shot token for this execution run
                self.state_store.validate_one_shot_token(
                    quarantine_event.quarantineId,
                    token,
                    policy_engine=self.policy_engine,
                    current_call_hash=verdict.callHash
                )

        # -------------------------------------------------------------------
        # Step 4: Execution Actuators
        # -------------------------------------------------------------------
        raw_output, exit_code, stdout, stderr = self._run_actuator(request, tool_name, best_tool_match)

        # -------------------------------------------------------------------
        # Step 5: Plane 4 - Deterministic Out-of-Band Verifier
        # -------------------------------------------------------------------
        effective_tool = tool_name or "action"
        receipt: VerificationReceipt = self.verifier.verify_action(
            tool_name=effective_tool,
            payload=request.payload,
            raw_output=raw_output,
            request_id=request.requestId,
            contract=contract
        )

        total_latency_ms = round((time.perf_counter() - dispatch_start) * 1000.0, 3)
        final_success = receipt.verified and (exit_code == 0)

        if contract:
            new_status = TaskContractStatus.COMPLETED if final_success else TaskContractStatus.FAILED
            self.state_store.update_contract_status(contract.contractId, new_status)

        verification_summary = f"\n\n[Deterministic Verifier Receipt: {receipt.receiptId[:8]} - {receipt.verifierNotes}]"

        result = ExecutionResult(
            requestId=request.requestId,
            contractId=request.contractId,
            success=final_success,
            stdout=f"{stdout}{verification_summary}" if stdout else verification_summary,
            stderr=stderr if not final_success else "",
            exitCode=exit_code if final_success else (exit_code or 1),
            latencyMs=total_latency_ms,
            tierLevel=verdict.tierLevel,
            receipt=receipt
        )

        self.execution_audit.append(result)
        return result

    def _run_actuator(
        self,
        request: ActionRequest,
        tool_name: Optional[str],
        best_match: Optional[ToolMatchResult]
    ) -> Tuple[Any, int, str, str]:
        """Execute the physical action through LocalExecDaemon or MCPGateway."""
        # 1. Shell command direct execution
        if "command" in request.payload:
            cmd = request.payload["command"]
            timeout = request.payload.get("timeout_seconds", 15.0)
            res = self.daemon.execute_command(
                command=cmd,
                timeout_seconds=timeout,
                request_id=request.requestId
            )
            return res, res.exitCode, res.stdout, res.stderr

        # 2. Tool invocation via MCP Gateway
        target_tool = tool_name or (best_match.tool.name if best_match else None)
        tool_args = request.payload.get("arguments", request.payload)

        if target_tool:
            try:
                raw_out = self.gateway.execute_tool(target_tool, tool_args)
                out_str = str(raw_out) if not isinstance(raw_out, str) else raw_out
                return raw_out, 0, out_str, ""
            except Exception as err:
                return None, 1, "", f"Tool Execution Failure: {type(err).__name__}: {str(err)}"

        # 3. Fallback unrouted intent
        return (
            None,
            0,
            f"Processed by MAC Intake Gate. Task registered under ID {request.requestId[:8]}.",
            ""
        )
