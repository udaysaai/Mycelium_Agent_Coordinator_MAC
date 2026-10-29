"""
test_phase06_state_integrity.py - Phase 0.6 State Integrity & Hash Chain Tests
Covers Part 4:
  4.1 Row-level HMAC and cryptographic hash chain across state store.
  4.2 Checkpoint tracking to detect rollback, truncation, or file replacement.
  4.4 Attack simulations:
      - Direct SQLite modification of PENDING -> APPROVED
      - Row deletion
      - Row reordering
      - DB file replacement with older copy
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
import pytest

from protocol import (
    ActionRequest,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
)
from state_store import StateStore


def create_sample_quarantine(qid: str, status: HOLApprovalStatus = HOLApprovalStatus.PENDING) -> HOLQuarantineEvent:
    return HOLQuarantineEvent(
        quarantineId=qid,
        request=ActionRequest(
            intent=f"intent for {qid}",
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING,
            payload={"tool_name": "execute_shell_command", "command": f"echo {qid}"}
        ),
        quarantineReason="Needs approval",
        decision=status,
        callHash=f"callhash-{qid}",
        oneShotToken=f"token-{qid}",
        plainImpact="Impact test",
        quarantinedAt=time.time(),
        expiresAt=time.time() + 900.0
    )


def test_tamper_detect_modify_pending_to_approved_directly_in_sqlite(tmp_path):
    """
    Directly modifying a quarantine row's status from PENDING to APPROVED in SQLite
    must invalidate the row-level HMAC and be detected on verification.
    """
    db_path = tmp_path / "mac_state.db"
    key = b"A" * 32
    store = StateStore(db_path=db_path, integrity_key=key)
    try:
        q = create_sample_quarantine("qid-tamper-01", HOLApprovalStatus.PENDING)
        store.save_quarantine(q)

        # Baseline verification passes
        assert store.verify_integrity(key) is True

        # Attacker tampers directly with SQLite file
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "UPDATE quarantines SET status = 'APPROVED' WHERE quarantine_id = 'qid-tamper-01'"
            )
            conn.commit()

        # Integrity verification must detect row HMAC mismatch
        tamper_detected = store.verify_integrity(key)
        assert tamper_detected is False, "Direct row tampering was not detected by integrity check!"
    finally:
        store.close()


def test_tamper_detect_delete_row(tmp_path):
    """
    Deleting an intermediate row breaks the hash chain and must be detected.
    """
    db_path = tmp_path / "mac_state.db"
    key = b"B" * 32
    store = StateStore(db_path=db_path, integrity_key=key)
    try:
        store.save_quarantine(create_sample_quarantine("qid-chain-01"))
        store.save_quarantine(create_sample_quarantine("qid-chain-02"))
        store.save_quarantine(create_sample_quarantine("qid-chain-03"))

        assert store.verify_integrity(key) is True

        # Attacker deletes intermediate row
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM quarantines WHERE quarantine_id = 'qid-chain-02'")
            conn.commit()

        assert store.verify_integrity(key) is False, "Row deletion did not break hash chain verification!"
    finally:
        store.close()


def test_tamper_detect_reorder_rows(tmp_path):
    """
    Reordering rows or swapping IDs breaks sequential chain links and must be detected.
    """
    db_path = tmp_path / "mac_state.db"
    key = b"C" * 32
    store = StateStore(db_path=db_path, integrity_key=key)
    try:
        store.save_quarantine(create_sample_quarantine("qid-order-01"))
        store.save_quarantine(create_sample_quarantine("qid-order-02"))

        assert store.verify_integrity(key) is True

        # Attacker swaps row IDs in place
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("UPDATE quarantines SET quarantine_id = 'temp' WHERE quarantine_id = 'qid-order-01'")
            conn.execute("UPDATE quarantines SET quarantine_id = 'qid-order-01' WHERE quarantine_id = 'qid-order-02'")
            conn.execute("UPDATE quarantines SET quarantine_id = 'qid-order-02' WHERE quarantine_id = 'temp'")
            conn.commit()

        assert store.verify_integrity(key) is False, "Row reordering was not detected by hash chain!"
    finally:
        store.close()


def test_tamper_detect_rollback_to_older_db_copy(tmp_path):
    """
    Replacing the database with an older copy or truncating must be detected
    via supervisor checkpoint mismatch.
    """
    db_path = tmp_path / "mac_state.db"
    backup_path = tmp_path / "mac_state_backup.db"
    key = b"D" * 32
    store = StateStore(db_path=db_path, integrity_key=key)
    try:
        store.save_quarantine(create_sample_quarantine("qid-snap-01"))
        assert store.verify_integrity(key) is True

        # Take backup snapshot of DB at 1 row
        shutil.copy2(db_path, backup_path)

        # Append more activity
        store.save_quarantine(create_sample_quarantine("qid-snap-02"))
        store.save_quarantine(create_sample_quarantine("qid-snap-03"))
        assert store.verify_integrity(key) is True

        # Record checkpoint
        store.save_checkpoint()
    finally:
        store.close()

    # Attacker rolls back DB file to older backup
    shutil.copy2(backup_path, db_path)

    # Reopen store and verify
    reopened_store = StateStore(db_path=db_path, integrity_key=key)
    try:
        # Must detect that DB state lags behind recorded supervisor checkpoint
        assert reopened_store.verify_integrity(key) is False, "Rollback to older DB file was not detected!"
    finally:
        reopened_store.close()
