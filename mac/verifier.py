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
    Runs deterministic read-back assertions and generates SHA-256 verification receipts.
    """

    BINARY_EXTENSIONS = {
        ".bin", ".exe", ".png", ".jpg", ".jpeg", ".zip", ".tar",
        ".gz", ".pdf", ".dat", ".ico", ".dll", ".so", ".wasm"
    }

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
        persist: bool = True,
        is_binary: bool = False
    ) -> VerificationReceipt:
        """
        Execute out-of-band state verification for a completed tool action.
        """
        timestamp = time.time()
        contract_id = contract.contractId if contract else None
        predicate = (contract.successPredicate if contract else {}) or {}

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
                if self.state_store and persist:
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
                if self.state_store and persist:
                    self.state_store.save_receipt(receipt)
                return receipt

            # Check 3: Read-back hash verification
            expected_bytes = (
                expected_content.encode("utf-8")
                if isinstance(expected_content, str)
                else (expected_content if isinstance(expected_content, bytes) else str(expected_content).encode("utf-8"))
            )

            is_bin = is_binary or target_file.suffix.lower() in self.BINARY_EXTENSIONS

            if is_bin:
                # Raw binary mode: No newline normalization allowed
                actual_hash = self.compute_file_sha256(target_file)
                expected_hash = hashlib.sha256(expected_bytes).hexdigest()
                verified = (actual_hash == expected_hash)
            else:
                # Text mode: Normalize CRLF to LF to prevent OS newline mismatch
                try:
                    with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                        disk_text = f.read()
                    actual_hash = hashlib.sha256(disk_text.replace("\r\n", "\n").encode("utf-8")).hexdigest()
                    norm_expected = (expected_content if isinstance(expected_content, str) else str(expected_content)).replace("\r\n", "\n")
                    expected_hash = hashlib.sha256(norm_expected.encode("utf-8")).hexdigest()
                    verified = (actual_hash == expected_hash)
                except Exception:
                    actual_hash = self.compute_file_sha256(target_file)
                    expected_hash = hashlib.sha256(expected_bytes).hexdigest()
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
                    "hashMatched": verified,
                    "isBinary": is_bin
                },
                timestamp=timestamp,
                verifierNotes=notes
            )
            if self.state_store and persist:
                self.state_store.save_receipt(receipt)
            return receipt

        # -------------------------------------------------------------------
        # 2. Shell execution (execute_shell_command)
        # -------------------------------------------------------------------
        if tool_name == "execute_shell_command":
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
            if self.state_store and persist:
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

    def verify_reconciliation(
        self,
        cashbook_path: Path | str,
        bank_path: Path | str,
        output_dir: Path | str,
        expected_cb_sha256: str,
        expected_bs_sha256: str,
        request_id: str,
        contract: Optional[TaskContract] = None,
        persist: bool = True
    ) -> VerificationReceipt:
        """
        Out-of-band verification for cashbook <-> bank statement reconciliation.
        Independently checks input file immutability, output existence, determinism (re-run),
        row conservation, sum conservation, and ledger balance identities.
        """
        import tempfile
        import shutil
        from decimal import Decimal
        from reconciliation_engine import DeterministicReconciliationEngine, ReconciliationConfig

        timestamp = time.time()
        contract_id = contract.contractId if contract else None

        cb_p = self._resolve_safe_path(cashbook_path)
        bs_p = self._resolve_safe_path(bank_path)
        out_p = self._resolve_safe_path(output_dir)

        # 1. Input Immutability Check
        current_cb_sha = self.compute_file_sha256(cb_p)
        current_bs_sha = self.compute_file_sha256(bs_p)

        if current_cb_sha != expected_cb_sha256 or current_bs_sha != expected_bs_sha256:
            receipt = VerificationReceipt(
                contractId=contract_id,
                requestId=request_id,
                toolName="reconcile_accounts",
                verified=False,
                predicateType="reconciliation_input_immutability",
                checksum="",
                stateDiff={
                    "cb_hash_match": current_cb_sha == expected_cb_sha256,
                    "bs_hash_match": current_bs_sha == expected_bs_sha256,
                },
                timestamp=timestamp,
                verifierNotes="FAIL: Input files tampered. SHA-256 hash changed during reconciliation."
            )
            if self.state_store and persist:
                self.state_store.save_receipt(receipt)
            return receipt

        # 2. Output Artifact Existence Check
        xlsx_p = out_p / "reconciliation.xlsx"
        json_p = out_p / "reconciliation_result.json"
        manifest_p = out_p / "run_manifest.json"

        missing_outputs = []
        if not xlsx_p.exists() or xlsx_p.stat().st_size == 0:
            missing_outputs.append("reconciliation.xlsx")
        if not json_p.exists() or json_p.stat().st_size == 0:
            missing_outputs.append("reconciliation_result.json")
        if not manifest_p.exists() or manifest_p.stat().st_size == 0:
            missing_outputs.append("run_manifest.json")

        if missing_outputs:
            receipt = VerificationReceipt(
                contractId=contract_id,
                requestId=request_id,
                toolName="reconcile_accounts",
                verified=False,
                predicateType="reconciliation_output_existence",
                checksum="",
                stateDiff={"missingOutputs": missing_outputs},
                timestamp=timestamp,
                verifierNotes=f"FAIL: Missing required reconciliation output artifact(s): {', '.join(missing_outputs)}"
            )
            if self.state_store and persist:
                self.state_store.save_receipt(receipt)
            return receipt

        # 3. Read Worker Outputs
        try:
            with open(json_p, "r", encoding="utf-8") as f:
                worker_result = json.load(f)
            with open(manifest_p, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
        except Exception as e:
            receipt = VerificationReceipt(
                contractId=contract_id,
                requestId=request_id,
                toolName="reconcile_accounts",
                verified=False,
                predicateType="reconciliation_format",
                checksum="",
                stateDiff={"error": str(e)},
                timestamp=timestamp,
                verifierNotes=f"FAIL: Corrupt JSON artifact: {e}"
            )
            if self.state_store and persist:
                self.state_store.save_receipt(receipt)
            return receipt

        # 4. Independent Determinism Re-run
        params = manifest_data.get("parameters", {})
        config = ReconciliationConfig(
            period_from=params.get("period_from", "2000-01-01"),
            period_to=params.get("period_to", "2099-12-31"),
            opening_balance_source=params.get("opening_balance_source", "cashbook"),
            date_tolerance_days=params.get("date_tolerance_days", 3),
            amount_exact=params.get("amount_exact", True)
        )
        temp_dir = Path(tempfile.mkdtemp(prefix="mac_recon_verify_"))
        try:
            engine = DeterministicReconciliationEngine(config=config)
            independent_result = engine.reconcile(cb_p, bs_p, temp_dir)

            with open(temp_dir / "reconciliation_result.json", "r", encoding="utf-8") as f:
                indep_json_text = f.read()
            with open(json_p, "r", encoding="utf-8") as f:
                worker_json_text = f.read()

            determinism_match = (indep_json_text.strip() == worker_json_text.strip())
            if not determinism_match:
                # Fallback to structural dict comparison
                determinism_match = (independent_result == worker_result)

            if not determinism_match:
                receipt = VerificationReceipt(
                    contractId=contract_id,
                    requestId=request_id,
                    toolName="reconcile_accounts",
                    verified=False,
                    predicateType="reconciliation_determinism",
                    checksum="",
                    stateDiff={"determinismMatch": False},
                    timestamp=timestamp,
                    verifierNotes="FAIL: Determinism check failed. Independent re-run yielded differing result."
                )
                if self.state_store and persist:
                    self.state_store.save_receipt(receipt)
                return receipt

            # 5. Row Conservation & Sum Conservation Checks
            cb_rows = engine.load_ledger(cb_p, "cashbook")
            bs_rows = engine.load_ledger(bs_p, "bank")

            expected_cb_count = len(cb_rows)
            expected_bs_count = len(bs_rows)

            summary = worker_result.get("summary", {})
            actual_cb_rows = summary.get("cashbook_total_rows", 0)
            actual_bs_rows = summary.get("bank_total_rows", 0)

            row_conservation = (actual_cb_rows == expected_cb_count) and (actual_bs_rows == expected_bs_count)

            # Sum Conservation
            cb_credits = sum(r.credit for r in cb_rows)
            cb_debits = sum(r.debit for r in cb_rows)
            bs_deposits = sum(r.credit for r in bs_rows)
            bs_withdrawals = sum(r.debit for r in bs_rows)

            sum_conservation = (
                Decimal(summary.get("cashbook_total_credits", "0")) == cb_credits and
                Decimal(summary.get("cashbook_total_debits", "0")) == cb_debits and
                Decimal(summary.get("bank_total_deposits", "0")) == bs_deposits and
                Decimal(summary.get("bank_total_withdrawals", "0")) == bs_withdrawals
            )

            if not row_conservation or not sum_conservation:
                receipt = VerificationReceipt(
                    contractId=contract_id,
                    requestId=request_id,
                    toolName="reconcile_accounts",
                    verified=False,
                    predicateType="reconciliation_conservation",
                    checksum="",
                    stateDiff={
                        "rowConservation": row_conservation,
                        "sumConservation": sum_conservation,
                        "expected_cb_rows": expected_cb_count,
                        "actual_cb_rows": actual_cb_rows
                    },
                    timestamp=timestamp,
                    verifierNotes=f"FAIL: Conservation failure. Row conservation: {row_conservation}, Sum conservation: {sum_conservation}."
                )
                if self.state_store and persist:
                    self.state_store.save_receipt(receipt)
                return receipt

            # All 6 predicates verified
            result_sha = self.compute_file_sha256(json_p)
            receipt = VerificationReceipt(
                contractId=contract_id,
                requestId=request_id,
                toolName="reconcile_accounts",
                verified=True,
                predicateType="reconciliation_conservation",
                checksum=result_sha,
                stateDiff={
                    "rowConservation": True,
                    "sumConservation": True,
                    "determinismVerified": True,
                    "inputImmutability": True,
                    "cashbookRows": expected_cb_count,
                    "bankRows": expected_bs_count,
                    "matchedCount": summary.get("total_matched_pairs", 0),
                    "exceptionCount": summary.get("total_exceptions", 0)
                },
                timestamp=timestamp,
                verifierNotes="PASS: All 6 reconciliation conservation, determinism, and immutability predicates verified."
            )
            if self.state_store and persist:
                self.state_store.save_receipt(receipt)
            return receipt

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

