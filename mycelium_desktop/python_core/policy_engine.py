"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: policy_engine.py
Description: Dynamic RBAC & Tiered Capability Policy Engine (T0/T1/T2).
             Enforces strict boundary isolation, cryptographic call fingerprints,
             plain-language impact synthesis, and signed one-shot tokens.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, Field

from protocol import (
    ActionRequest,
    PrivilegeTier,
    SafetyTier,
    TaskContract,
    TierLevel,
)


class PolicyVerdict(BaseModel):
    """
    Structured outcome of policy evaluation for an action.
    """
    tierLevel: TierLevel
    requiresQuarantine: bool
    callHash: str = ""
    oneShotToken: str = ""
    plainImpact: str = ""
    expiresAt: float = 0.0
    reason: str = ""


class PolicyEngine:
    """
    Enforces three-tier capability boundaries:
    - T0: Read-Only / Idempotent (Bypasses with zero latency)
    - T1: Reversible Sandbox Mutation (Audited, sandboxed, no blocking)
    - T2: Irreversible / High-Risk Mutation (Mandatory quarantine & operator token)
    """

    T0_TOOLS = {
        "read_workspace_file",
        "list_workspace_directory",
        "system_diagnostics",
        "weather_sensor_node",
        "crypto_telemetry_node",
    }

    def __init__(self, sandbox_dirname: str = "workspace_sandbox"):
        self.sandbox_dirname = sandbox_dirname.replace("\\", "/").strip("/")

    def compute_call_hash(self, tool_name: str, payload: Dict[str, Any], target: str = "") -> str:
        """Deterministic SHA-256 fingerprint of the tool, arguments, and target."""
        normalized_args = json.dumps(payload, sort_keys=True, default=str)
        raw = f"{tool_name}:{normalized_args}:{target}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def generate_one_shot_token(self) -> str:
        """Generate a cryptographically secure random one-time token."""
        return secrets.token_hex(16)

    def synthesize_plain_impact(self, tool_name: str, payload: Dict[str, Any]) -> str:
        """Produce human-readable impact statement without technical obfuscation."""
        if tool_name == "execute_shell_command" or "command" in payload:
            cmd = payload.get("command", "")
            return f"OS Terminal Subshell: Execute process command '{cmd}' on local host."

        if tool_name in ("write_workspace_file", "sandboxed_file_writer"):
            fp = payload.get("file_path", payload.get("filePath", "unknown"))
            content = payload.get("content", "")
            size = len(content.encode("utf-8")) if isinstance(content, str) else len(str(content))
            return f"Filesystem Mutation: Create or overwrite file '{fp}' ({size} bytes)."

        return f"Tool Execution: Execute mutating capability '{tool_name}' with {len(payload)} arguments."

    def evaluate(
        self,
        request: ActionRequest,
        contract: Optional[TaskContract] = None,
        tool_name: Optional[str] = None
    ) -> PolicyVerdict:
        """
        Evaluate an incoming action request against the capability policy.
        """
        payload = request.payload or {}
        effective_tool = tool_name or payload.get("tool_name", "")
        file_path = payload.get("file_path", payload.get("filePath", ""))

        # 1. Shell commands are always T2 irreversible mutations
        if "command" in payload or effective_tool == "execute_shell_command":
            target = payload.get("command", "")
            call_hash = self.compute_call_hash("execute_shell_command", payload, target)
            token = self.generate_one_shot_token()
            impact = self.synthesize_plain_impact("execute_shell_command", payload)
            expires = time.time() + 900.0  # 15 minute timeout

            return PolicyVerdict(
                tierLevel=TierLevel.T2,
                requiresQuarantine=True,
                callHash=call_hash,
                oneShotToken=token,
                plainImpact=impact,
                expiresAt=expires,
                reason="Shell execution possesses ambient system authority and requires operator sign-off."
            )

        # 2. Known T0 Read-Only Tools
        if effective_tool in self.T0_TOOLS:
            return PolicyVerdict(
                tierLevel=TierLevel.T0,
                requiresQuarantine=False,
                reason="Idempotent read-only inspection. Zero risk."
            )

        # 3. File writing inspection: Sandbox containment check
        if effective_tool == "sandboxed_file_writer":
            return PolicyVerdict(
                tierLevel=TierLevel.T1,
                requiresQuarantine=False,
                reason=f"Dedicated sandboxed tool strictly confined inside '{self.sandbox_dirname}'."
            )

        if effective_tool == "write_workspace_file":
            normalized_path = str(file_path).replace("\\", "/").lstrip("/")
            is_inside_sandbox = (
                normalized_path.startswith(f"{self.sandbox_dirname}/")
                or normalized_path == self.sandbox_dirname
            )

            if is_inside_sandbox:
                # T1: Reversible sandboxed mutation
                return PolicyVerdict(
                    tierLevel=TierLevel.T1,
                    requiresQuarantine=False,
                    reason=f"File mutation contained strictly inside sandboxed directory '{self.sandbox_dirname}'."
                )
            else:
                # T2: Mutating outside sandbox
                call_hash = self.compute_call_hash(effective_tool, payload, normalized_path)
                token = self.generate_one_shot_token()
                impact = self.synthesize_plain_impact(effective_tool, payload)
                expires = time.time() + 900.0

                return PolicyVerdict(
                    tierLevel=TierLevel.T2,
                    requiresQuarantine=True,
                    callHash=call_hash,
                    oneShotToken=token,
                    plainImpact=impact,
                    expiresAt=expires,
                    reason=f"Target path '{normalized_path}' resides outside isolated sandbox '{self.sandbox_dirname}'."
                )

        # 4. Fallback based on safetyTier in request
        if request.safetyTier in (SafetyTier.MUTATING, SafetyTier.IRREVERSIBLE) or request.tierLevel == TierLevel.T2:
            call_hash = self.compute_call_hash(effective_tool or "action", payload)
            token = self.generate_one_shot_token()
            impact = self.synthesize_plain_impact(effective_tool or "action", payload)
            expires = time.time() + 900.0

            return PolicyVerdict(
                tierLevel=TierLevel.T2,
                requiresQuarantine=True,
                callHash=call_hash,
                oneShotToken=token,
                plainImpact=impact,
                expiresAt=expires,
                reason="Action classified as state-altering mutation under zero-trust governance."
            )

        # Default T0 safe fallback
        return PolicyVerdict(
            tierLevel=TierLevel.T0,
            requiresQuarantine=False,
            reason="Unmutating or read-only operational context."
        )
