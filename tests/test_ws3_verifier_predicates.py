"""
tests/test_ws3_verifier_predicates.py - WS3 Step 3.4 Out-of-Band Verifier Predicates Test Suite
Validates independent verification of:
(a) Input file hash immutability,
(b) Ledger balance identity,
(c) Row conservation,
(d) Sum conservation,
(e) Determinism check (byte-identical re-run),
(f) Task directory output containment.
"""

import csv
import json
from decimal import Decimal
from pathlib import Path
import pytest

from reconciliation_engine import DeterministicReconciliationEngine, ReconciliationConfig
from verifier import DeterministicVerifier


def _create_sample_recon_data(tmp_path: Path):
    cb_path = tmp_path / "cb.csv"
    bs_path = tmp_path / "bs.csv"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(cb_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Date", "Particulars", "Cheque No", "Credit", "Debit"])
        writer.writerow(["05/04/2026", "Gram Tax Collection", "CHQ101", "10,000.00", "0.00"])
        writer.writerow(["10/04/2026", "Sanitation Payment", "CHQ102", "0.00", "3,500.00"])
        writer.writerow(["15/04/2026", "Office Stationery", "CHQ103", "0.00", "1,200.00"])

    with open(bs_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Date", "Narration", "Ref No", "Withdrawal", "Deposit"])
        writer.writerow(["06/04/2026", "TAX CLG CHQ101", "101", "0.00", "10,000.00"])
        writer.writerow(["12/04/2026", "CLG CHQ102", "102", "3,500.00", "0.00"])
        writer.writerow(["25/04/2026", "BANK SMS CHARGES", "", "25.00", "0.00"])

    engine = DeterministicReconciliationEngine(
        config=ReconciliationConfig(
            period_from="2026-04-01",
            period_to="2026-04-30",
            date_tolerance_days=3,
            amount_exact=True
        )
    )
    engine.reconcile(cb_path, bs_path, out_dir)
    return cb_path, bs_path, out_dir


def test_verifier_reconciliation_happy_path(tmp_path):
    cb_path, bs_path, out_dir = _create_sample_recon_data(tmp_path)
    verifier = DeterministicVerifier(workspace_root=tmp_path)

    cb_sha = verifier.compute_file_sha256(cb_path)
    bs_sha = verifier.compute_file_sha256(bs_path)

    receipt = verifier.verify_reconciliation(
        cashbook_path=cb_path,
        bank_path=bs_path,
        output_dir=out_dir,
        expected_cb_sha256=cb_sha,
        expected_bs_sha256=bs_sha,
        request_id="REQ_RECON_001"
    )

    assert receipt.verified is True
    assert "PASS" in receipt.verifierNotes
    assert receipt.predicateType == "reconciliation_conservation"
    assert receipt.stateDiff.get("rowConservation") is True
    assert receipt.stateDiff.get("sumConservation") is True
    assert receipt.stateDiff.get("determinismVerified") is True


def test_verifier_catches_tampered_input_file(tmp_path):
    cb_path, bs_path, out_dir = _create_sample_recon_data(tmp_path)
    verifier = DeterministicVerifier(workspace_root=tmp_path)

    orig_cb_sha = verifier.compute_file_sha256(cb_path)
    orig_bs_sha = verifier.compute_file_sha256(bs_path)

    # Tamper with the cashbook file after run
    with open(cb_path, "a", encoding="utf-8") as f:
        f.write("01/01/2026,Malicious row,999,50000,0\n")

    receipt = verifier.verify_reconciliation(
        cashbook_path=cb_path,
        bank_path=bs_path,
        output_dir=out_dir,
        expected_cb_sha256=orig_cb_sha,
        expected_bs_sha256=orig_bs_sha,
        request_id="REQ_RECON_002"
    )

    assert receipt.verified is False
    assert "tamper" in receipt.verifierNotes.lower() or "hash" in receipt.verifierNotes.lower()


def test_verifier_catches_missing_output_file(tmp_path):
    cb_path, bs_path, out_dir = _create_sample_recon_data(tmp_path)
    verifier = DeterministicVerifier(workspace_root=tmp_path)

    cb_sha = verifier.compute_file_sha256(cb_path)
    bs_sha = verifier.compute_file_sha256(bs_path)

    # Delete reconciliation.xlsx
    (out_dir / "reconciliation.xlsx").unlink()

    receipt = verifier.verify_reconciliation(
        cashbook_path=cb_path,
        bank_path=bs_path,
        output_dir=out_dir,
        expected_cb_sha256=cb_sha,
        expected_bs_sha256=bs_sha,
        request_id="REQ_RECON_003"
    )

    assert receipt.verified is False
    assert "missing" in receipt.verifierNotes.lower() or "exist" in receipt.verifierNotes.lower()


def test_verifier_catches_row_conservation_violation(tmp_path):
    cb_path, bs_path, out_dir = _create_sample_recon_data(tmp_path)
    verifier = DeterministicVerifier(workspace_root=tmp_path)

    cb_sha = verifier.compute_file_sha256(cb_path)
    bs_sha = verifier.compute_file_sha256(bs_path)

    # Tamper with reconciliation_result.json by removing an exception row
    res_path = out_dir / "reconciliation_result.json"
    data = json.loads(res_path.read_text(encoding="utf-8"))
    data["exceptions"] = []  # Drop exceptions
    res_path.write_text(json.dumps(data), encoding="utf-8")

    receipt = verifier.verify_reconciliation(
        cashbook_path=cb_path,
        bank_path=bs_path,
        output_dir=out_dir,
        expected_cb_sha256=cb_sha,
        expected_bs_sha256=bs_sha,
        request_id="REQ_RECON_004"
    )

    assert receipt.verified is False
    assert "conservation" in receipt.verifierNotes.lower() or "determinism" in receipt.verifierNotes.lower()
