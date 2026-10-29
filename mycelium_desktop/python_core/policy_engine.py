"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: policy_engine.py
Description: Capability Grant Policy Engine (T0/T1/T2).
             Enforces zero-trust capability boundaries, HMAC-SHA256
             one-shot token signatures, external key file management (outside DB),
             plain-language impact synthesis, and argument-level capability constraints.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set

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
    Structured outcome of capability grant policy evaluation for an action.
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
    Capability Grants Policy Engine.
    Enforces three-tier capability boundaries and argument-level constraints:
    - T0: Read-Only / Idempotent (Bypasses with zero friction)
    - T1: Reversible Sandbox Mutation (Audited, sandboxed, no blocking)
    - T2: Irreversible / High-Risk / External Mutation (Mandatory quarantine & HMAC token)
    """

    T0_TOOLS: Set[str] = {
        "read_workspace_file",
        "list_workspace_directory",
        "system_diagnostics",
        "weather_sensor_node",
        "crypto_telemetry_node",
    }

    KNOWN_TOOLS: Set[str] = {
        "read_workspace_file",
        "list_workspace_directory",
        "system_diagnostics",
        "weather_sensor_node",
        "crypto_telemetry_node",
        "write_workspace_file",
        "sandboxed_file_writer",
        "execute_shell_command",
    }

    DANGEROUS_CMD_PATTERNS = [
        "rmdir /s",
        "rmdir /q",
        "format",
        "mkfs",
        "dd if=",
        ":(){ :|:& };:",
        "del /f /s /q c:",
        "shutdown",
    ]

    MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 Megabytes ceiling

    def __init__(
        self,
        sandbox_dirname: str = "workspace_sandbox",
        key_file_path: Optional[str | Path] = None
    ):
        self.sandbox_dirname = sandbox_dirname.replace("\\", "/").strip("/")
        if key_file_path is None:
            self.key_file_path = Path.home() / ".mycelium" / "mac_signing.key"
        else:
            self.key_file_path = Path(key_file_path).resolve()

        self._master_key: bytes = self._load_or_create_master_key()

    def _load_or_create_master_key(self) -> bytes:
        """Load HMAC-SHA256 signing key from external protected file outside DB."""
        try:
            if self.key_file_path.exists():
                key = self.key_file_path.read_bytes()
                if len(key) >= 32:
                    return key
            self.key_file_path.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(32)
            self.key_file_path.write_bytes(key)
            try:
                os.chmod(self.key_file_path, 0o600)
            except Exception:
                pass
            return key
        except Exception:
            return secrets.token_bytes(32)

    def generate_hmac_token(self, quarantine_id: str, call_hash: str, expires_at: float) -> str:
        """Produce HMAC-SHA256 signature binding quarantine ID, call hash, and expiry."""
        msg = f"{quarantine_id}:{call_hash}:{int(expires_at)}".encode("utf-8")
        sig = hmac.new(self._master_key, msg, hashlib.sha256).hexdigest()
        return f"mac_hmac_{sig}"

    def verify_hmac_token(self, token: str, quarantine_id: str, call_hash: str, expires_at: float) -> bool:
        """Verify token authenticity and binding using constant-time comparison."""
        if not token or not token.startswith("mac_hmac_"):
            return False
        expected = self.generate_hmac_token(quarantine_id, call_hash, expires_at)
        return hmac.compare_digest(token, expected)

    def compute_call_hash(self, tool_name: str, payload: Dict[str, Any], target: str = "") -> str:
        """Deterministic SHA-256 fingerprint of the tool, arguments, and target."""
        # Exclude ephemeral supervisor routing keys from signature calculation
        clean_args = {k: v for k, v in payload.items() if k not in ("quarantineId", "action", "approved", "decision")}
        normalized_args = json.dumps(clean_args, sort_keys=True, default=str)
        raw = f"{tool_name}:{normalized_args}:{target}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

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
        Evaluate an incoming action request against capability grant policies.
        Unknown tools default to T2 (deny/quarantine).
        """
        payload = request.payload or {}
        effective_tool = tool_name or payload.get("tool_name", "")
        file_path = payload.get("file_path", payload.get("filePath", ""))

        # -------------------------------------------------------------------
        # Rule 1: Unknown capability tools default to T2 (Zero-Trust)
        # -------------------------------------------------------------------
        if effective_tool and effective_tool not in self.KNOWN_TOOLS:
            call_hash = self.compute_call_hash(effective_tool, payload)
            expires = time.time() + 900.0
            token = self.generate_hmac_token("pending", call_hash, expires)
            return PolicyVerdict(
                tierLevel=TierLevel.T2,
                requiresQuarantine=True,
                callHash=call_hash,
                oneShotToken=token,
                plainImpact=f"Unrecognized capability '{effective_tool}' requires explicit operator grant.",
                expiresAt=expires,
                reason=f"Unknown capability '{effective_tool}' defaults to T2 under zero-trust capability grants."
            )

        # -------------------------------------------------------------------
        # Rule 2: Shell execution with dangerous command inspection
        # -------------------------------------------------------------------
        if "command" in payload or effective_tool == "execute_shell_command":
            cmd = str(payload.get("command", "")).strip()
            cmd_lower = cmd.lower()
            call_hash = self.compute_call_hash("execute_shell_command", payload, cmd)
            expires = time.time() + 900.0
            token = self.generate_hmac_token("pending", call_hash, expires)
            impact = self.synthesize_plain_impact("execute_shell_command", payload)

            matched_dangerous = any(p in cmd_lower for p in self.DANGEROUS_CMD_PATTERNS)
            reason = (
                "Shell command matched high-risk destructive signature under capability grants."
                if matched_dangerous
                else "Shell execution possesses ambient system authority and requires operator sign-off."
            )

            return PolicyVerdict(
                tierLevel=TierLevel.T2,
                requiresQuarantine=True,
                callHash=call_hash,
                oneShotToken=token,
                plainImpact=impact,
                expiresAt=expires,
                reason=reason
            )

        # -------------------------------------------------------------------
        # Rule 3: Known T0 Read-Only Tools (Zero-Friction Bypass)
        # -------------------------------------------------------------------
        if effective_tool in self.T0_TOOLS:
            return PolicyVerdict(
                tierLevel=TierLevel.T0,
                requiresQuarantine=False,
                reason="Idempotent read-only inspection capability grant."
            )

        # -------------------------------------------------------------------
        # Rule 4: File size capability constraint ceiling (5MB limit)
        # -------------------------------------------------------------------
        if effective_tool in ("write_workspace_file", "sandboxed_file_writer"):
            content = payload.get("content", "")
            size = len(content.encode("utf-8")) if isinstance(content, str) else len(str(content))
            if size > self.MAX_FILE_BYTES:
                call_hash = self.compute_call_hash(effective_tool, payload, str(file_path))
                expires = time.time() + 900.0
                token = self.generate_hmac_token("pending", call_hash, expires)
                return PolicyVerdict(
                    tierLevel=TierLevel.T2,
                    requiresQuarantine=True,
                    callHash=call_hash,
                    oneShotToken=token,
                    plainImpact=f"File mutation of {size} bytes exceeds 5MB capability grant limit.",
                    expiresAt=expires,
                    reason="File payload size exceeds capability grant ceiling (5MB limit)."
                )

        # -------------------------------------------------------------------
        # Rule 5: Sandboxed file writer (T1 within sandbox)
        # -------------------------------------------------------------------
        if effective_tool == "sandboxed_file_writer":
            return PolicyVerdict(
                tierLevel=TierLevel.T1,
                requiresQuarantine=False,
                reason=f"Dedicated sandboxed tool strictly confined inside '{self.sandbox_dirname}'."
            )

        # -------------------------------------------------------------------
        # Rule 6: Generic workspace file write (Containment check)
        # -------------------------------------------------------------------
        if effective_tool == "write_workspace_file":
            normalized_path = str(file_path).replace("\\", "/").lstrip("/")
            is_inside_sandbox = (
                normalized_path.startswith(f"{self.sandbox_dirname}/")
                or normalized_path == self.sandbox_dirname
            )

            if is_inside_sandbox:
                return PolicyVerdict(
                    tierLevel=TierLevel.T1,
                    requiresQuarantine=False,
                    reason=f"File mutation contained strictly inside sandboxed directory '{self.sandbox_dirname}'."
                )
            else:
                call_hash = self.compute_call_hash(effective_tool, payload, normalized_path)
                expires = time.time() + 900.0
                token = self.generate_hmac_token("pending", call_hash, expires)
                impact = self.synthesize_plain_impact(effective_tool, payload)

                return PolicyVerdict(
                    tierLevel=TierLevel.T2,
                    requiresQuarantine=True,
                    callHash=call_hash,
                    oneShotToken=token,
                    plainImpact=impact,
                    expiresAt=expires,
                    reason=f"Target path '{normalized_path}' resides outside isolated sandbox '{self.sandbox_dirname}'."
                )

        # -------------------------------------------------------------------
        # Fallback based on safety tier classification
        # -------------------------------------------------------------------
        if request.safetyTier in (SafetyTier.MUTATING, SafetyTier.IRREVERSIBLE) or request.tierLevel == TierLevel.T2:
            call_hash = self.compute_call_hash(effective_tool or "action", payload)
            expires = time.time() + 900.0
            token = self.generate_hmac_token("pending", call_hash, expires)
            impact = self.synthesize_plain_impact(effective_tool or "action", payload)

            return PolicyVerdict(
                tierLevel=TierLevel.T2,
                requiresQuarantine=True,
                callHash=call_hash,
                oneShotToken=token,
                plainImpact=impact,
                expiresAt=expires,
                reason="Action classified as state-altering mutation under zero-trust capability grants."
            )

        # Default T0 safe fallback
        return PolicyVerdict(
            tierLevel=TierLevel.T0,
            requiresQuarantine=False,
            reason="Unmutating or read-only operational context."
        )
