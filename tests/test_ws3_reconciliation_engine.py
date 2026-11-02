"""
tests/test_ws3_reconciliation_engine.py - WS3 Step 3.2 & 3.3 Engine & Privacy Test Suite
Validates Indian number parsing, Devanagari header recognition, 4-pass matching,
formula injection defense, and PII redaction.
"""

import csv
import json
import unicodedata
from decimal import Decimal
from datetime import date
from pathlib import Path
import openpyxl
import pytest

from reconciliation_engine import (
    DeterministicReconciliationEngine,
    LedgerRow,
    ReconciliationConfig,
    parse_indian_amount,
    parse_flexible_date,
    sanitize_cell_formula_injection,
)
from privacy import redact_pii_string, RedactionPolicy


# -----------------------------------------------------------------------------
# 1. Parsing & Normalization Unit Tests
# -----------------------------------------------------------------------------

def test_parse_indian_amount():
    assert parse_indian_amount("₹ 1,23,456.78") == Decimal("123456.78")
    assert parse_indian_amount("12,34,567") == Decimal("1234567.00")
    assert parse_indian_amount("₹500.00 Cr") == Decimal("500.00")
    assert parse_indian_amount("-1,500.50") == Decimal("-1500.50")
    assert parse_indian_amount(" (2,500.00) ") == Decimal("-2500.00")
    assert parse_indian_amount("₹ 0.00") == Decimal("0.00")
    assert parse_indian_amount(12345) == Decimal("12345.00")
    assert parse_indian_amount(Decimal("999.99")) == Decimal("999.99")


def test_parse_flexible_date():
    assert parse_flexible_date("05/04/2026") == date(2026, 4, 5)
    assert parse_flexible_date("05-04-2026") == date(2026, 4, 5)
    assert parse_flexible_date("2026-04-05") == date(2026, 4, 5)
    assert parse_flexible_date("05.04.2026") == date(2026, 4, 5)


def test_formula_injection_sanitization():
    assert sanitize_cell_formula_injection("=cmd|'/c calc'!A0").startswith("'")
    assert sanitize_cell_formula_injection("+1234567").startswith("'")
    assert sanitize_cell_formula_injection("-malicious").startswith("'")
    assert sanitize_cell_formula_injection("@SUM(A1:A10)").startswith("'")
    assert sanitize_cell_formula_injection("\talert(1)").startswith("'")
    assert sanitize_cell_formula_injection("Normal Narration") == "Normal Narration"


# -----------------------------------------------------------------------------
# 2. Four-Pass Matching Engine Tests
# -----------------------------------------------------------------------------

def test_reconciliation_four_matching_passes(tmp_path):
    output_dir = tmp_path / "recon_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    cashbook_csv = tmp_path / "cashbook.csv"
    bank_csv = tmp_path / "bank.csv"

    # Create Cashbook entries (Marathi/English mix with Indian numbers)
    with open(cashbook_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["दिनांक", "तपशील", "पावती / चेक क्र.", "जमा (₹)", "नावे (₹)"])
        # Pass 1 candidate: exact ref (CHQ-1001) + exact amount 50,000 (different date)
        writer.writerow(["02/04/2026", "ग्रामपंचायत कर वसुली", "CHQ-1001", "50,000.00", "0.00"])
        # Pass 2 candidate: no ref, exact amount 15,000, date within 2 days
        writer.writerow(["05/04/2026", "पाणी पुरवठा देखभाल", "", "0.00", "15,000.00"])
        # Pass 3 candidate: batched deposit (10,000 total split in bank as 6,000 + 4,000)
        writer.writerow(["10/04/2026", "घरपट्टी कर भरणा (एकत्रित)", "BATCH-88", "10,000.00", "0.00"])
        # Pass 4: Amount mismatch (transposed digits: 5400 vs 4500)
        writer.writerow(["15/04/2026", "स्टेशनरी खरेदी", "CHQ-1004", "0.00", "5,400.00"])
        # Pass 4: In cashbook only
        writer.writerow(["20/04/2026", "रस्ता दुरुस्ती मजुरी", "CHQ-1005", "0.00", "25,000.00"])
        # Pass 4: Date outside period (May 2026)
        writer.writerow(["05/05/2026", "पुढील महिन्याची आगाऊ रक्कम", "CHQ-1006", "0.00", "2,000.00"])
        # Pass 4: Duplicate row in cashbook
        writer.writerow(["25/04/2026", "साफसफाई साहित्य", "CHQ-1007", "0.00", "1,200.00"])
        writer.writerow(["25/04/2026", "साफसफाई साहित्य", "CHQ-1007", "0.00", "1,200.00"])

    # Create Bank Statement entries
    with open(bank_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Date", "Narration", "Cheque / Ref No", "Withdrawal (Dr)", "Deposit (Cr)"])
        # Pass 1 match for CHQ-1001 (cleared on 08/04/2026)
        writer.writerow(["08/04/2026", "CLG CHQ 1001 GRAMPANCHAYAT", "1001", "0.00", "50,000.00"])
        # Pass 2 match for 15,000 (cleared on 07/04/2026, 2 days later)
        writer.writerow(["07/04/2026", "NEFT WATER SUPPLY MAINTENANCE", "N260407", "15,000.00", "0.00"])
        # Pass 3 match: two deposits making 10,000 (6,000 + 4,000)
        writer.writerow(["11/04/2026", "CASH DEP TAX PT1", "", "0.00", "6,000.00"])
        writer.writerow(["12/04/2026", "CASH DEP TAX PT2", "", "0.00", "4,000.00"])
        # Pass 4 match: Amount mismatch for CHQ-1004 (4,500 bank vs 5,400 cashbook)
        writer.writerow(["16/04/2026", "CLG CHQ 1004 STATIONERY", "1004", "4,500.00", "0.00"])
        # Pass 4: Suspected bank charge
        writer.writerow(["22/04/2026", "SMS ALERT CHARGES Q1", "", "23.60", "0.00"])
        # Pass 4: Suspected bank interest
        writer.writerow(["30/04/2026", "SB INT CREDITED UPTO APR", "", "0.00", "1,450.00"])
        # Pass 4: In bank only
        writer.writerow(["28/04/2026", "DIRECT GOVT SUBSIDY DBT", "DBT9988", "0.00", "80,000.00"])
        # Bank has only one CHQ-1007
        writer.writerow(["26/04/2026", "CLG CHQ 1007 SANITATION", "1007", "1,200.00", "0.00"])

    engine = DeterministicReconciliationEngine(
        config=ReconciliationConfig(
            period_from="2026-04-01",
            period_to="2026-04-30",
            date_tolerance_days=3,
            amount_exact=True
        )
    )

    result = engine.reconcile(
        cashbook_path=cashbook_csv,
        bank_path=bank_csv,
        output_dir=output_dir
    )

    # Verify Output artifacts generated
    assert (output_dir / "reconciliation.xlsx").exists()
    assert (output_dir / "reconciliation_result.json").exists()
    assert (output_dir / "run_manifest.json").exists()

    # Verify Pass 1 Match
    p1_matches = [m for m in result["matched"] if m["match_pass"] == "PASS_1_EXACT_REFERENCE"]
    assert len(p1_matches) >= 1
    assert any("1001" in m["reference"] for m in p1_matches)

    # Verify Pass 2 Match
    p2_matches = [m for m in result["matched"] if m["match_pass"] == "PASS_2_AMOUNT_DATE_TOLERANCE"]
    assert len(p2_matches) >= 1
    assert any(m["cashbook_amount"] == "15000.00" for m in p2_matches)

    # Verify Pass 3 Match (Batch/Split)
    p3_matches = [m for m in result["matched"] if m["match_pass"] == "PASS_3_SPLIT_BATCH"]
    assert len(p3_matches) >= 1
    assert any(m["cashbook_amount"] == "10000.00" for m in p3_matches)

    # Verify Exceptions Categorization
    exceptions = result["exceptions"]
    categories = {e["category"] for e in exceptions}
    assert "amount_mismatch" in categories
    assert "in_cashbook_only" in categories
    assert "in_bank_only" in categories
    assert "suspected_bank_charge_or_interest" in categories
    assert "date_outside_period" in categories
    assert "duplicate" in categories

    # Verify Transposed Amount Detection
    amt_mismatches = [e for e in exceptions if e["category"] == "amount_mismatch"]
    assert len(amt_mismatches) >= 1
    assert any(e.get("is_transposed_digits") is True for e in amt_mismatches)

    # Verify XLSX formula injection protection
    wb = openpyxl.load_workbook(output_dir / "reconciliation.xlsx")
    assert "Summary" in wb.sheetnames
    assert "Matched" in wb.sheetnames
    assert "Exceptions" in wb.sheetnames
    assert "Assumptions" in wb.sheetnames

    for sheet_name in wb.sheetnames:
        sheet = wb[sheet_name]
        for row in sheet.iter_rows(values_only=True):
            for cell in row:
                if isinstance(cell, str) and len(cell) > 0:
                    assert not cell.startswith(("=", "+", "@", "\t", "\r")), f"Unsanitized formula cell: {cell}"


# -----------------------------------------------------------------------------
# 3. Privacy & PII Redaction Tests
# -----------------------------------------------------------------------------

def test_pii_redaction_aadhaar():
    text = "Payment received from Ramesh Patil Aadhaar: 9876 5432 1098 for property tax"
    redacted = redact_pii_string(text)
    assert "9876 5432 1098" not in redacted
    assert "1098" in redacted or "[REDACTED_AADHAAR]" in redacted


def test_pii_redaction_bank_account():
    text = "Transfer to SB A/c 11223344556677 IFSC SBIN0001234"
    redacted = redact_pii_string(text)
    assert "11223344556677" not in redacted
    assert "6677" in redacted or "[REDACTED_ACCOUNT]" in redacted


def test_pii_redaction_phone_and_otp():
    text = "Alert sent to mobile 9822012345. Your OTP is 582910 for approval."
    redacted = redact_pii_string(text)
    assert "9822012345" not in redacted
    assert "582910" not in redacted
