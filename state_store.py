"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: state_store.py
Description: Durable SQLite WAL State Store for TaskContracts, HOL Quarantines,
             and Deterministic Out-of-Band Verification Receipts.
             Features thread-local connection caching, injectable clock for timeout
             audits, strict one-shot token validation with call-hash and HMAC verification,
             and cryptographic hash-chains with row-level HMACs and checkpoint rollback detection.
"""

from __future__ import annotations

import hashlib
import hmac
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
        clock: Optional[Callable[[], float]] = None,
        integrity_key: Optional[bytes] = None,
        checkpoint_path: Optional[str | Path] = None,
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
        self.integrity_key: Optional[bytes] = integrity_key
        self.checkpoint_path: Path = (
            Path(checkpoint_path).resolve()
            if checkpoint_path
            else (self.db_path.parent / f"{self.db_path.name}.checkpoint.json")
        )
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
        """Create schemas if not already present, with schema evolution for integrity columns."""
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
                    operator_notes TEXT,
                    seq INTEGER DEFAULT 0,
                    prev_hash TEXT DEFAULT '',
                    creation_hash TEXT DEFAULT '',
                    row_hmac TEXT DEFAULT ''
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
                    verifier_notes TEXT NOT NULL,
                    seq INTEGER DEFAULT 0,
                    prev_hash TEXT DEFAULT '',
                    creation_hash TEXT DEFAULT '',
                    row_hmac TEXT DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status);
                CREATE INDEX IF NOT EXISTS idx_quarantines_status ON quarantines(status);
                CREATE INDEX IF NOT EXISTS idx_receipts_contract ON receipts(contract_id);
            """)

            # Ensure backward-compatible schema evolution if tables already existed
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(quarantines)")
            q_cols = {col[1] for col in cur.fetchall()}
            for col, ctype in [
                ("seq", "INTEGER DEFAULT 0"),
                ("prev_hash", "TEXT DEFAULT ''"),
                ("creation_hash", "TEXT DEFAULT ''"),
                ("row_hmac", "TEXT DEFAULT ''"),
            ]:
                if col not in q_cols:
                    conn.execute(f"ALTER TABLE quarantines ADD COLUMN {col} {ctype};")

            cur.execute("PRAGMA table_info(receipts)")
            r_cols = {col[1] for col in cur.fetchall()}
            for col, ctype in [
                ("seq", "INTEGER DEFAULT 0"),
                ("prev_hash", "TEXT DEFAULT ''"),
                ("creation_hash", "TEXT DEFAULT ''"),
                ("row_hmac", "TEXT DEFAULT ''"),
            ]:
                if col not in r_cols:
                    conn.execute(f"ALTER TABLE receipts ADD COLUMN {col} {ctype};")

    # -----------------------------------------------------------------------
    # Cryptographic Hash & HMAC Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _calc_quarantine_creation_hash(
        prev_hash: str,
        quarantine_id: str,
        request_id: str,
        contract_id: Optional[str],
        tool_name: str,
        call_hash: str,
        plain_impact: str,
        payload_json: str,
        quarantined_at: float,
        expires_at: float,
    ) -> str:
        payload = (
            f"{prev_hash}|{quarantine_id}|{request_id}|{contract_id or ''}|"
            f"{tool_name}|{call_hash}|{plain_impact}|{payload_json}|"
            f"{quarantined_at}|{expires_at}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _calc_quarantine_row_hmac(
        key: bytes,
        creation_hash: str,
        status: str,
        one_shot_token: str,
        reviewed_at: Optional[float],
        operator_id: Optional[str],
        operator_notes: Optional[str],
    ) -> str:
        msg = (
            f"{creation_hash}|{status}|{one_shot_token}|"
            f"{reviewed_at or ''}|{operator_id or ''}|{operator_notes or ''}"
        )
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _calc_receipt_creation_hash(
        prev_hash: str,
        receipt_id: str,
        contract_id: Optional[str],
        request_id: str,
        tool_name: str,
        verified: int,
        predicate_type: str,
        checksum: str,
        state_diff_json: str,
        timestamp: float,
    ) -> str:
        payload = (
            f"{prev_hash}|{receipt_id}|{contract_id or ''}|{request_id}|"
            f"{tool_name}|{verified}|{predicate_type}|{checksum}|"
            f"{state_diff_json}|{timestamp}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _calc_receipt_row_hmac(
        key: bytes,
        creation_hash: str,
        verifier_notes: str,
    ) -> str:
        msg = f"{creation_hash}|{verifier_notes}"
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

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
        """Record a newly quarantined action awaiting human sign-off with hash chain linkage."""
        t_name = tool_name or event.request.payload.get("tool_name", "action")
        p_json = json.dumps(payload or event.request.payload)
        decision_val = event.decision.value if hasattr(event.decision, "value") else str(event.decision)

        with self._get_connection() as conn:
            # Check if record already exists
            cur = conn.execute("SELECT seq, creation_hash FROM quarantines WHERE quarantine_id = ?", (event.quarantineId,))
            existing = cur.fetchone()

            if existing:
                creation_hash = existing["creation_hash"]
                row_hmac = (
                    self._calc_quarantine_row_hmac(
                        self.integrity_key,
                        creation_hash,
                        decision_val,
                        event.oneShotToken,
                        event.reviewedAt,
                        event.operatorId,
                        event.operatorNotes,
                    )
                    if self.integrity_key
                    else ""
                )
                conn.execute("""
                    UPDATE quarantines SET
                        status = ?,
                        reviewed_at = ?,
                        operator_id = ?,
                        operator_notes = ?,
                        row_hmac = ?
                    WHERE quarantine_id = ?
                """, (
                    decision_val,
                    event.reviewedAt,
                    event.operatorId,
                    event.operatorNotes,
                    row_hmac,
                    event.quarantineId
                ))
            else:
                # Query previous tip to maintain hash chain
                tip_cur = conn.execute("SELECT seq, creation_hash FROM quarantines ORDER BY seq DESC LIMIT 1")
                tip = tip_cur.fetchone()
                if tip and tip["creation_hash"]:
                    seq = (tip["seq"] or 0) + 1
                    prev_hash = tip["creation_hash"]
                else:
                    seq = 1
                    prev_hash = "0" * 64

                creation_hash = self._calc_quarantine_creation_hash(
                    prev_hash,
                    event.quarantineId,
                    event.request.requestId,
                    event.contractId,
                    t_name,
                    event.callHash,
                    event.plainImpact,
                    p_json,
                    event.quarantinedAt,
                    event.expiresAt,
                )

                row_hmac = (
                    self._calc_quarantine_row_hmac(
                        self.integrity_key,
                        creation_hash,
                        decision_val,
                        event.oneShotToken,
                        event.reviewedAt,
                        event.operatorId,
                        event.operatorNotes,
                    )
                    if self.integrity_key
                    else ""
                )

                conn.execute("""
                    INSERT INTO quarantines (
                        quarantine_id, request_id, contract_id, tool_name, call_hash,
                        one_shot_token, plain_impact, payload_json, status, expires_at,
                        quarantined_at, reviewed_at, operator_id, operator_notes,
                        seq, prev_hash, creation_hash, row_hmac
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.quarantineId,
                    event.request.requestId,
                    event.contractId,
                    t_name,
                    event.callHash,
                    event.oneShotToken,
                    event.plainImpact,
                    p_json,
                    decision_val,
                    event.expiresAt,
                    event.quarantinedAt,
                    event.reviewedAt,
                    event.operatorId,
                    event.operatorNotes,
                    seq,
                    prev_hash,
                    creation_hash,
                    row_hmac
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
                new_status = HOLApprovalStatus.REJECTED_TIMEOUT.value
                row_hmac = record.get("row_hmac", "")
                if self.integrity_key and record.get("creation_hash"):
                    row_hmac = self._calc_quarantine_row_hmac(
                        self.integrity_key,
                        record["creation_hash"],
                        new_status,
                        record["one_shot_token"],
                        now,
                        record.get("operator_id"),
                        record.get("operator_notes"),
                    )
                conn.execute(
                    "UPDATE quarantines SET status = ?, reviewed_at = ?, row_hmac = ? WHERE quarantine_id = ?",
                    (new_status, now, row_hmac, quarantine_id)
                )
                record["status"] = new_status
                record["reviewed_at"] = now
                record["row_hmac"] = row_hmac
            return record

    def get_pending_quarantines(self) -> List[Dict[str, Any]]:
        """List all pending quarantines that have not expired."""
        now = self.clock()
        with self._get_connection() as conn:
            # Query expired to update them
            cur = conn.execute(
                "SELECT * FROM quarantines WHERE status = ? AND expires_at <= ?",
                (HOLApprovalStatus.PENDING.value, now)
            )
            expired_rows = cur.fetchall()
            for er in expired_rows:
                new_status = HOLApprovalStatus.REJECTED_TIMEOUT.value
                row_hmac = er["row_hmac"]
                if self.integrity_key and er["creation_hash"]:
                    row_hmac = self._calc_quarantine_row_hmac(
                        self.integrity_key,
                        er["creation_hash"],
                        new_status,
                        er["one_shot_token"],
                        now,
                        er["operator_id"],
                        er["operator_notes"],
                    )
                conn.execute(
                    "UPDATE quarantines SET status = ?, reviewed_at = ?, row_hmac = ? WHERE quarantine_id = ?",
                    (new_status, now, row_hmac, er["quarantine_id"])
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
            cur = conn.execute(
                "SELECT status, expires_at, creation_hash, one_shot_token FROM quarantines WHERE quarantine_id = ?",
                (quarantine_id,)
            )
            row = cur.fetchone()
            if not row:
                return False
            if row["status"] != HOLApprovalStatus.PENDING.value:
                return False

            # Check timeout expiration
            if row["expires_at"] <= now:
                new_status = HOLApprovalStatus.REJECTED_TIMEOUT.value
                row_hmac = ""
                if self.integrity_key and row["creation_hash"]:
                    row_hmac = self._calc_quarantine_row_hmac(
                        self.integrity_key,
                        row["creation_hash"],
                        new_status,
                        row["one_shot_token"],
                        now,
                        operator_id or "system_timeout",
                        "Expired before review",
                    )
                conn.execute(
                    "UPDATE quarantines SET status = ?, reviewed_at = ?, operator_notes = 'Expired before review', row_hmac = ? WHERE quarantine_id = ?",
                    (new_status, now, row_hmac, quarantine_id)
                )
                return False

            decision_str = decision.value if hasattr(decision, "value") else str(decision)
            op_str = operator_id or "human_operator"
            notes_str = notes or ""
            row_hmac = ""
            if self.integrity_key and row["creation_hash"]:
                row_hmac = self._calc_quarantine_row_hmac(
                    self.integrity_key,
                    row["creation_hash"],
                    decision_str,
                    row["one_shot_token"],
                    now,
                    op_str,
                    notes_str,
                )

            conn.execute("""
                UPDATE quarantines
                SET status = ?, reviewed_at = ?, operator_id = ?, operator_notes = ?, row_hmac = ?
                WHERE quarantine_id = ?
            """, (
                decision_str,
                now,
                op_str,
                notes_str,
                row_hmac,
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
                "SELECT status, one_shot_token, call_hash, expires_at, creation_hash, reviewed_at, operator_id, operator_notes FROM quarantines WHERE quarantine_id = ?",
                (quarantine_id,)
            )
            row = cur.fetchone()
            if not row:
                return False

            # Check expiration
            if row["expires_at"] <= now:
                new_status = HOLApprovalStatus.REJECTED_TIMEOUT.value
                row_hmac = ""
                if self.integrity_key and row["creation_hash"]:
                    row_hmac = self._calc_quarantine_row_hmac(
                        self.integrity_key,
                        row["creation_hash"],
                        new_status,
                        row["one_shot_token"],
                        now,
                        row["operator_id"],
                        row["operator_notes"],
                    )
                conn.execute(
                    "UPDATE quarantines SET status = ?, row_hmac = ? WHERE quarantine_id = ?",
                    (new_status, row_hmac, quarantine_id)
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
            row_hmac = ""
            if self.integrity_key and row["creation_hash"]:
                row_hmac = self._calc_quarantine_row_hmac(
                    self.integrity_key,
                    row["creation_hash"],
                    row["status"],
                    "CONSUMED",
                    row["reviewed_at"],
                    row["operator_id"],
                    row["operator_notes"],
                )
            conn.execute(
                "UPDATE quarantines SET one_shot_token = 'CONSUMED', row_hmac = ? WHERE quarantine_id = ?",
                (row_hmac, quarantine_id)
            )
            return True

    # -----------------------------------------------------------------------
    # Deterministic Verification Proof Receipts
    # -----------------------------------------------------------------------

    def save_receipt(self, receipt: VerificationReceipt) -> None:
        """Persist an immutable out-of-band execution receipt linked into the receipt hash chain."""
        s_diff_json = json.dumps(receipt.stateDiff)
        v_int = 1 if receipt.verified else 0

        with self._get_connection() as conn:
            tip_cur = conn.execute("SELECT seq, creation_hash FROM receipts ORDER BY seq DESC LIMIT 1")
            tip = tip_cur.fetchone()
            if tip and tip["creation_hash"]:
                seq = (tip["seq"] or 0) + 1
                prev_hash = tip["creation_hash"]
            else:
                seq = 1
                prev_hash = "0" * 64

            creation_hash = self._calc_receipt_creation_hash(
                prev_hash,
                receipt.receiptId,
                receipt.contractId,
                receipt.requestId,
                receipt.toolName,
                v_int,
                receipt.predicateType,
                receipt.checksum,
                s_diff_json,
                receipt.timestamp,
            )

            row_hmac = (
                self._calc_receipt_row_hmac(
                    self.integrity_key,
                    creation_hash,
                    receipt.verifierNotes,
                )
                if self.integrity_key
                else ""
            )

            conn.execute("""
                INSERT INTO receipts (
                    receipt_id, contract_id, request_id, tool_name,
                    verified, predicate_type, checksum, state_diff_json,
                    timestamp, verifier_notes, seq, prev_hash, creation_hash, row_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                receipt.receiptId,
                receipt.contractId,
                receipt.requestId,
                receipt.toolName,
                v_int,
                receipt.predicateType,
                receipt.checksum,
                s_diff_json,
                receipt.timestamp,
                receipt.verifierNotes,
                seq,
                prev_hash,
                creation_hash,
                row_hmac
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

    # -----------------------------------------------------------------------
    # Checkpoint and State Integrity Verification
    # -----------------------------------------------------------------------

    def save_checkpoint(self, checkpoint_path: Optional[str | Path] = None) -> Path:
        """
        Record a state checkpoint to detect rollback, truncation, or file replacement.
        """
        target = Path(checkpoint_path).resolve() if checkpoint_path else self.checkpoint_path
        with self._get_connection() as conn:
            q_tip_row = conn.execute("SELECT creation_hash FROM quarantines ORDER BY seq DESC LIMIT 1").fetchone()
            q_cnt = conn.execute("SELECT COUNT(*) as cnt FROM quarantines").fetchone()["cnt"]
            q_tip = q_tip_row["creation_hash"] if q_tip_row else ("0" * 64)

            r_tip_row = conn.execute("SELECT creation_hash FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
            r_cnt = conn.execute("SELECT COUNT(*) as cnt FROM receipts").fetchone()["cnt"]
            r_tip = r_tip_row["creation_hash"] if r_tip_row else ("0" * 64)

        now = self.clock()
        data: Dict[str, Any] = {
            "quarantines_count": q_cnt,
            "quarantines_tip_hash": q_tip,
            "receipts_count": r_cnt,
            "receipts_tip_hash": r_tip,
            "timestamp": now,
        }
        if self.integrity_key:
            msg = f"{q_cnt}|{q_tip}|{r_cnt}|{r_tip}|{now}"
            data["hmac"] = hmac.new(self.integrity_key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return target

    def verify_integrity(
        self,
        key: Optional[bytes] = None,
        checkpoint_path: Optional[str | Path] = None,
    ) -> bool:
        """
        Verify the complete cryptographic integrity of the state store:
          1. Sequential hash-chain continuity in quarantines (prev_hash links).
          2. Row-level HMAC verification on quarantines against direct tampering.
          3. Sequential hash-chain continuity in receipts.
          4. Row-level HMAC verification on receipts.
          5. Checkpoint consistency (detects database file rollback, truncation, or substitution).
        Returns True if all integrity checks pass, False on any tampering or mismatch.
        """
        check_key = key or self.integrity_key
        target_cp = Path(checkpoint_path).resolve() if checkpoint_path else self.checkpoint_path

        with self._get_connection() as conn:
            # 1. Quarantines verification
            cur = conn.execute("SELECT * FROM quarantines ORDER BY seq ASC")
            q_rows = cur.fetchall()
            expected_prev_q = "0" * 64
            q_chain_hashes: List[str] = []

            for r in q_rows:
                # Chain link check
                if r["prev_hash"] != expected_prev_q:
                    return False

                c_hash = self._calc_quarantine_creation_hash(
                    r["prev_hash"],
                    r["quarantine_id"],
                    r["request_id"],
                    r["contract_id"],
                    r["tool_name"],
                    r["call_hash"],
                    r["plain_impact"],
                    r["payload_json"],
                    r["quarantined_at"],
                    r["expires_at"],
                )
                if r["creation_hash"] != c_hash:
                    return False

                if check_key:
                    exp_hmac = self._calc_quarantine_row_hmac(
                        check_key,
                        c_hash,
                        r["status"],
                        r["one_shot_token"],
                        r["reviewed_at"],
                        r["operator_id"],
                        r["operator_notes"],
                    )
                    if not r["row_hmac"] or not hmac.compare_digest(exp_hmac, r["row_hmac"]):
                        return False

                expected_prev_q = c_hash
                q_chain_hashes.append(c_hash)

            # 2. Receipts verification
            cur = conn.execute("SELECT * FROM receipts ORDER BY seq ASC")
            r_rows = cur.fetchall()
            expected_prev_r = "0" * 64
            r_chain_hashes: List[str] = []

            for r in r_rows:
                if r["prev_hash"] != expected_prev_r:
                    return False

                c_hash = self._calc_receipt_creation_hash(
                    r["prev_hash"],
                    r["receipt_id"],
                    r["contract_id"],
                    r["request_id"],
                    r["tool_name"],
                    r["verified"],
                    r["predicate_type"],
                    r["checksum"],
                    r["state_diff_json"],
                    r["timestamp"],
                )
                if r["creation_hash"] != c_hash:
                    return False

                if check_key:
                    exp_hmac = self._calc_receipt_row_hmac(
                        check_key,
                        c_hash,
                        r["verifier_notes"],
                    )
                    if not r["row_hmac"] or not hmac.compare_digest(exp_hmac, r["row_hmac"]):
                        return False

                expected_prev_r = c_hash
                r_chain_hashes.append(c_hash)

        # 3. Checkpoint verification
        if target_cp.exists():
            try:
                with open(target_cp, "r", encoding="utf-8") as f:
                    cp = json.load(f)

                if check_key and "hmac" in cp:
                    msg = (
                        f"{cp.get('quarantines_count', 0)}|"
                        f"{cp.get('quarantines_tip_hash', '')}|"
                        f"{cp.get('receipts_count', 0)}|"
                        f"{cp.get('receipts_tip_hash', '')}|"
                        f"{cp.get('timestamp', 0)}"
                    )
                    exp_cp_hmac = hmac.new(check_key, msg.encode("utf-8"), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(exp_cp_hmac, cp["hmac"]):
                        return False

                cp_q_cnt = cp.get("quarantines_count", 0)
                cp_r_cnt = cp.get("receipts_count", 0)

                # Rollback or truncation detection
                if len(q_rows) < cp_q_cnt or len(r_rows) < cp_r_cnt:
                    return False

                if cp_q_cnt > 0:
                    if q_chain_hashes[cp_q_cnt - 1] != cp.get("quarantines_tip_hash"):
                        return False

                if cp_r_cnt > 0:
                    if r_chain_hashes[cp_r_cnt - 1] != cp.get("receipts_tip_hash"):
                        return False

            except Exception:
                return False

        return True
