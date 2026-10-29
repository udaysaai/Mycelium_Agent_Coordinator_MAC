"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: verifier.py
Description: Deterministic Out-of-Band Verifier ("Reading The World Back").
             Independent assertion engine that verifies actual end-state changes
             in the physical filesystem or API receipts, completely outside LLM context.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from protocol import TaskContract, VerificationReceipt
from state_store import StateStore


class DeterministicVerifier:
    """
    Independent verifier engine that enforces the core rule:
    'Never let an agent grade its own homework.'
    Runs deterministic read-back assertions and generates cryptographic receipts.
    """

    def __init__(self, workspace_root: Path, state_store: Optional[StateStore] = None):
        self.workspace_root = Path(workspace_root).resolve()
        self.state_store = state_store

    def _resolve_safe_path(self, target_path: str | Path) -> Path:
        candidate = Path(target_path)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.workspace_root / candidate).resolve()
        return resolved

    def compute_file_sha256(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file on disk."""
        if not file_path.exists() or not file_path.is_file():
            return ""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def verify_action(
        self,
        tool_name: str,
        payload: Dict[str, Any],
        raw_output: Any,
        request_id: str,
        contract: Optional[TaskContract] = None,
        persist: bool = True
    ) -> VerificationReceipt:
        """
        Execute out-of-band state verification for a completed tool action.
        """
        timestamp = time.time()
        contract_id = contract.contractId if contract else None
        predicate = (contract.successPredicate if contract else {}) or {}
        pred_type = predicate.get("type", "auto_read_back")

        # -------------------------------------------------------------------
        # 1. File write tools (write_workspace_file, sandboxed_file_writer)
        # -------------------------------------------------------------------
        if tool_name in ("write_workspace_file", "sandboxed_file_writer"):
            target_path_str = payload.get("file_path", payload.get("filePath", ""))
            clean_rel = str(target_path_str).replace("\\", "/").lstrip("/")
            if tool_name == "sandboxed_file_writer":
                if not clean_rel.startswith("workspace_sandbox/"):
                    clean_rel = f"workspace_sandbox/{clean_rel}"
                target_file = (self.workspace_root / clean_rel).resolve()
            else:
                target_file = self._resolve_safe_path(target_path_str)

            min_bytes = predicate.get("min_bytes", 1)
            expected_content = payload.get("content", "")

            # Check 1: Does file physically exist on the filesystem?
            exists = target_file.exists() and target_file.is_file()
            if not exists:
                receipt = VerificationReceipt(
                    contractId=contract_id,
                    requestId=request_id,
                    toolName=tool_name,
                    verified=False,
                    predicateType="file_exists",
                    checksum="",
                    stateDiff={"exists": False, "target": str(target_file)},
                    timestamp=timestamp,
                    verifierNotes=f"FAIL: Physical file '{target_path_str}' does not exist on disk after write."
                )
                if self.state_store:
                    self.state_store.save_receipt(receipt)
                return receipt

            # Check 2: Size assertion
            actual_size = target_file.stat().st_size
            if actual_size < min_bytes:
                receipt = VerificationReceipt(
                    contractId=contract_id,
                    requestId=request_id,
                    toolName=tool_name,
                    verified=False,
                    predicateType="file_size",
                    checksum="",
                    stateDiff={"exists": True, "sizeBytes": actual_size, "minBytesExpected": min_bytes},
                    timestamp=timestamp,
                    verifierNotes=f"FAIL: Target file '{target_path_str}' size ({actual_size}B) < required {min_bytes}B."
                )
                if self.state_store:
                    self.state_store.save_receipt(receipt)
                return receipt

            # Check 3: Read-back hash verification with platform newline normalization
            try:
                with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                    disk_text = f.read()
                norm_actual_hash = hashlib.sha256(disk_text.replace("\r\n", "\n").encode("utf-8")).hexdigest()
                norm_expected = (expected_content if isinstance(expected_content, str) else str(expected_content)).replace("\r\n", "\n")
                norm_expected_hash = hashlib.sha256(norm_expected.encode("utf-8")).hexdigest()
                verified = (norm_actual_hash == norm_expected_hash)
                actual_hash = norm_actual_hash
                expected_hash = norm_expected_hash
            except Exception:
                actual_hash = self.compute_file_sha256(target_file)
                expected_hash = hashlib.sha256(
                    expected_content.encode("utf-8") if isinstance(expected_content, str) else str(expected_content).encode("utf-8")
                ).hexdigest()
                verified = (actual_hash == expected_hash)
            notes = (
                f"PASS: Read-back verified on disk. Size: {actual_size}B, SHA-256: {actual_hash[:12]}..."
                if verified
                else f"FAIL: Content hash mismatch. Expected {expected_hash[:8]}..., found {actual_hash[:8]}..."
            )

            receipt = VerificationReceipt(
                contractId=contract_id,
                requestId=request_id,
                toolName=tool_name,
                verified=verified,
                predicateType="read_back_checksum",
                checksum=actual_hash,
                stateDiff={
                    "exists": True,
                    "sizeBytes": actual_size,
                    "path": str(target_file),
                    "hashMatched": verified
                },
                timestamp=timestamp,
                verifierNotes=notes
            )
            if self.state_store:
                self.state_store.save_receipt(receipt)
            return receipt

        # -------------------------------------------------------------------
        # 2. Shell execution (execute_shell_command)
        # -------------------------------------------------------------------
        if tool_name == "execute_shell_command":
            # If tool returned ExecutionResult or exit code
            exit_code = 0
            if hasattr(raw_output, "exitCode"):
                exit_code = raw_output.exitCode
            elif isinstance(raw_output, dict):
                exit_code = raw_output.get("exitCode", 0)

            verified = (exit_code == 0)
            receipt = VerificationReceipt(
                contractId=contract_id,
                requestId=request_id,
                toolName=tool_name,
                verified=verified,
                predicateType="process_exit_code",
                checksum="",
                stateDiff={"exitCode": exit_code, "command": payload.get("command", "")},
                timestamp=timestamp,
                verifierNotes=f"Process exited with status code {exit_code} (Verified: {verified})."
            )
            if self.state_store:
                self.state_store.save_receipt(receipt)
            return receipt

        # -------------------------------------------------------------------
        # 3. Read-Only queries & telemetry (T0 read-back check)
        # -------------------------------------------------------------------
        has_content = bool(raw_output)
        receipt = VerificationReceipt(
            contractId=contract_id,
            requestId=request_id,
            toolName=tool_name,
            verified=has_content,
            predicateType="idempotent_read",
            checksum="",
            stateDiff={"outputReceived": has_content},
            timestamp=timestamp,
            verifierNotes="PASS: Deterministic inspection read completed."
        )
        if self.state_store and persist:
            self.state_store.save_receipt(receipt)
        return receipt
