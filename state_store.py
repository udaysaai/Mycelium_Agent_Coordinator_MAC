"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: state_store.py
Description: Durable SQLite WAL State Store for TaskContracts, HOL Quarantines,
             and Deterministic Out-of-Band Verification Receipts.
             Features thread-local connection caching, injectable clock for timeout
             audits, and strict one-shot token validation with call-hash and HMAC verification.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from protocol import (
    HOLApprovalStatus,
    HOLQuarantineEvent,
    TaskContract,
    TaskContractStatus,
    TierLevel,
    VerificationReceipt,
)


class StateStore:
    """
    Durable, local-first SQLite WAL persistence engine.
    Ensures that task contracts, quarantine decisions, and verification proofs
    survive crashes, reboots, and multi-process access.
    """

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        clock: Optional[Callable[[], float]] = None
    ):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent
            data_dir = base_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "mac_state.db"
        else:
            self.db_path = Path(db_path).resolve()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.clock: Callable[[], float] = clock or time.time
        self._local = threading.local()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close thread-local SQLite connection to release file locks."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _init_database(self) -> None:
        """Create schemas if not already present."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS contracts (
                    contract_id TEXT PRIMARY KEY,
                    goal TEXT NOT NULL,
                    constraints_json TEXT NOT NULL,
                    success_predicate_json TEXT NOT NULL,
                    tier_ceiling TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    completed_at REAL
                );

                CREATE TABLE IF NOT EXISTS quarantines (
                    quarantine_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    contract_id TEXT,
                    tool_name TEXT NOT NULL,
                    call_hash TEXT NOT NULL,
                    one_shot_token TEXT NOT NULL,
                    plain_impact TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    quarantined_at REAL NOT NULL,
                    reviewed_at REAL,
                    operator_id TEXT,
                    operator_notes TEXT
                );

                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    contract_id TEXT,
                    request_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    verified INTEGER NOT NULL,
                    predicate_type TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    state_diff_json TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    verifier_notes TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status);
                CREATE INDEX IF NOT EXISTS idx_quarantines_status ON quarantines(status);
                CREATE INDEX IF NOT EXISTS idx_receipts_contract ON receipts(contract_id);
            """)

    # -----------------------------------------------------------------------
    # TaskContract Operations
    # -----------------------------------------------------------------------

    def save_contract(self, contract: TaskContract) -> None:
        """Upsert a TaskContract into durable storage."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO contracts (
                    contract_id, goal, constraints_json, success_predicate_json,
                    tier_ceiling, status, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(contract_id) DO UPDATE SET
                    goal = excluded.goal,
                    constraints_json = excluded.constraints_json,
                    success_predicate_json = excluded.success_predicate_json,
                    tier_ceiling = excluded.tier_ceiling,
                    status = excluded.status,
                    completed_at = excluded.completed_at
            """, (
                contract.contractId,
                contract.goal,
                json.dumps(contract.constraints),
                json.dumps(contract.successPredicate),
                contract.tierCeiling.value if hasattr(contract.tierCeiling, "value") else str(contract.tierCeiling),
                contract.status.value if hasattr(contract.status, "value") else str(contract.status),
                contract.createdAt,
                contract.completedAt
            ))

    def get_contract(self, contract_id: str) -> Optional[TaskContract]:
        """Fetch a TaskContract by its ID."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM contracts WHERE contract_id = ?", (contract_id,))
            row = cur.fetchone()
            if not row:
                return None
            return TaskContract(
                contractId=row["contract_id"],
                goal=row["goal"],
                constraints=json.loads(row["constraints_json"] or "{}"),
                successPredicate=json.loads(row["success_predicate_json"] or "{}"),
                tierCeiling=TierLevel(row["tier_ceiling"]),
                status=TaskContractStatus(row["status"]),
                createdAt=row["created_at"],
                completedAt=row["completed_at"]
            )

    def update_contract_status(
        self,
        contract_id: str,
        status: TaskContractStatus,
        completed_at: Optional[float] = None
    ) -> None:
        """Update contract lifecycle state."""
        now = self.clock()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE contracts SET status = ?, completed_at = ? WHERE contract_id = ?",
                (
                    status.value if hasattr(status, "value") else str(status),
                    completed_at if completed_at is not None else (now if status in (TaskContractStatus.COMPLETED, TaskContractStatus.FAILED, TaskContractStatus.ABORTED) else None),
                    contract_id
                )
            )

    # -----------------------------------------------------------------------
    # HOL Quarantine Operations
    # -----------------------------------------------------------------------

    def save_quarantine(
        self,
        event: HOLQuarantineEvent,
        tool_name: str = "",
        payload: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a newly quarantined action awaiting human sign-off."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO quarantines (
                    quarantine_id, request_id, contract_id, tool_name, call_hash,
                    one_shot_token, plain_impact, payload_json, status, expires_at,
                    quarantined_at, reviewed_at, operator_id, operator_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(quarantine_id) DO UPDATE SET
                    status = excluded.status,
                    reviewed_at = excluded.reviewed_at,
                    operator_id = excluded.operator_id,
                    operator_notes = excluded.operator_notes
            """, (
                event.quarantineId,
                event.request.requestId,
                event.contractId,
                tool_name or event.request.payload.get("tool_name", "action"),
                event.callHash,
                event.oneShotToken,
                event.plainImpact,
                json.dumps(payload or event.request.payload),
                event.decision.value if hasattr(event.decision, "value") else str(event.decision),
                event.expiresAt,
                event.quarantinedAt,
                event.reviewedAt,
                event.operatorId,
                event.operatorNotes
            ))

    def get_quarantine(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored quarantine record, auto-resolving expired pending items."""
        now = self.clock()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM quarantines WHERE quarantine_id = ?", (quarantine_id,))
            row = cur.fetchone()
            if not row:
                return None
            record = dict(row)
            if record["status"] == HOLApprovalStatus.PENDING.value and record["expires_at"] <= now:
                conn.execute(
                    "UPDATE quarantines SET status = ? WHERE quarantine_id = ?",
                    (HOLApprovalStatus.REJECTED_TIMEOUT.value, quarantine_id)
                )
                record["status"] = HOLApprovalStatus.REJECTED_TIMEOUT.value
            return record

    def get_pending_quarantines(self) -> List[Dict[str, Any]]:
        """List all pending quarantines that have not expired."""
        now = self.clock()
        with self._get_connection() as conn:
            # Auto-expire any pending quarantines past expiry to REJECTED_TIMEOUT
            conn.execute(
                "UPDATE quarantines SET status = ? WHERE status = ? AND expires_at <= ?",
                (HOLApprovalStatus.REJECTED_TIMEOUT.value, HOLApprovalStatus.PENDING.value, now)
            )
            cur = conn.execute(
                "SELECT * FROM quarantines WHERE status = ? AND expires_at > ? ORDER BY quarantined_at ASC",
                (HOLApprovalStatus.PENDING.value, now)
            )
            return [dict(r) for r in cur.fetchall()]

    def update_quarantine_decision(
        self,
        quarantine_id: str,
        decision: HOLApprovalStatus,
        operator_id: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        """Resolve a quarantine entry (Approve/Reject). Default-deny if expired."""
        now = self.clock()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT status, expires_at FROM quarantines WHERE quarantine_id = ?", (quarantine_id,))
            row = cur.fetchone()
            if not row:
                return False
            if row["status"] != HOLApprovalStatus.PENDING.value:
                return False

            # Check timeout expiration
            if row["expires_at"] <= now:
                conn.execute(
                    "UPDATE quarantines SET status = ?, reviewed_at = ?, operator_notes = 'Expired before review' WHERE quarantine_id = ?",
                    (HOLApprovalStatus.REJECTED_TIMEOUT.value, now, quarantine_id)
                )
                return False

            conn.execute("""
                UPDATE quarantines
                SET status = ?, reviewed_at = ?, operator_id = ?, operator_notes = ?
                WHERE quarantine_id = ?
            """, (
                decision.value if hasattr(decision, "value") else str(decision),
                now,
                operator_id or "human_operator",
                notes or "",
                quarantine_id
            ))
            return True

    def validate_one_shot_token(
        self,
        quarantine_id: str,
        token: str,
        policy_engine: Optional[Any] = None,
        current_call_hash: Optional[str] = None
    ) -> bool:
        """
        Validate whether token matches an approved quarantine entry.
        Tokens are one-shot; consuming this validation invalidates future replay.
        Verifies call hash, expiry, and HMAC authenticity.
        """
        if not token or token == "CONSUMED":
            return False
        now = self.clock()
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT status, one_shot_token, call_hash, expires_at FROM quarantines WHERE quarantine_id = ?",
                (quarantine_id,)
            )
            row = cur.fetchone()
            if not row:
                return False

            # Check expiration
            if row["expires_at"] <= now:
                conn.execute(
                    "UPDATE quarantines SET status = ? WHERE quarantine_id = ?",
                    (HOLApprovalStatus.REJECTED_TIMEOUT.value, quarantine_id)
                )
                return False

            # Check status and token match
            if row["status"] != HOLApprovalStatus.APPROVED.value:
                return False

            if row["one_shot_token"] != token:
                return False

            # Execution-time argument tampering check: call hash must match
            if current_call_hash and current_call_hash != row["call_hash"]:
                return False

            # HMAC authenticity check
            if policy_engine and hasattr(policy_engine, "verify_hmac_token"):
                if not policy_engine.verify_hmac_token(token, quarantine_id, row["call_hash"], row["expires_at"]):
                    return False

            # Invalidate token to enforce one-shot execution
            conn.execute(
                "UPDATE quarantines SET one_shot_token = 'CONSUMED' WHERE quarantine_id = ?",
                (quarantine_id,)
            )
            return True

    # -----------------------------------------------------------------------
    # Deterministic Verification Proof Receipts
    # -----------------------------------------------------------------------

    def save_receipt(self, receipt: VerificationReceipt) -> None:
        """Persist an immutable out-of-band execution receipt."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO receipts (
                    receipt_id, contract_id, request_id, tool_name,
                    verified, predicate_type, checksum, state_diff_json,
                    timestamp, verifier_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                receipt.receiptId,
                receipt.contractId,
                receipt.requestId,
                receipt.toolName,
                1 if receipt.verified else 0,
                receipt.predicateType,
                receipt.checksum,
                json.dumps(receipt.stateDiff),
                receipt.timestamp,
                receipt.verifierNotes
            ))

    def get_receipts(self, contract_id: Optional[str] = None) -> List[VerificationReceipt]:
        """Fetch verification proofs, optionally filtered by contract."""
        with self._get_connection() as conn:
            if contract_id:
                cur = conn.execute(
                    "SELECT * FROM receipts WHERE contract_id = ? ORDER BY timestamp DESC",
                    (contract_id,)
                )
            else:
                cur = conn.execute("SELECT * FROM receipts ORDER BY timestamp DESC")
            rows = cur.fetchall()
            return [
                VerificationReceipt(
                    receiptId=r["receipt_id"],
                    contractId=r["contract_id"],
                    requestId=r["request_id"],
                    toolName=r["tool_name"],
                    verified=bool(r["verified"]),
                    predicateType=r["predicate_type"],
                    checksum=r["checksum"],
                    stateDiff=json.loads(r["state_diff_json"] or "{}"),
                    timestamp=r["timestamp"],
                    verifierNotes=r["verifier_notes"]
                )
                for r in rows
            ]
