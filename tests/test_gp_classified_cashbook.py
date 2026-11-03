"""
tests/test_gp_classified_cashbook.py - Tests for Maharashtra Gram Panchayat Classified Cashbook.
Validates multi-section parsing, Devanagari numeral normalization, double-dot date typos,
continuation row date inheritance, subtotal/summary row isolation, and section subtotal verification.
Using 100% fictional synthetic Adarshgaon Gram Panchayat dataset (Rule R11 Government Data Sanitization).
"""

from datetime import date
from decimal import Decimal
from pathlib import Path
import pytest

from reconciliation_engine import (
    DeterministicReconciliationEngine,
    LedgerRow,
    ReconciliationConfig,
    parse_flexible_date,
    parse_indian_amount,
    normalize_devanagari_digits,
    clean_date_string,
)


def test_devanagari_digits_normalization():
    """Verify Devanagari numerals ०-९ are properly converted to ASCII 0-9."""
    assert normalize_devanagari_digits("१८०") == "180"
    assert normalize_devanagari_digits("०९.१२.२०२४") == "09.12.2024"
    assert normalize_devanagari_digits("१,२३,४५६.७८") == "1,23,456.78"
    assert normalize_devanagari_digits("पावती क्रं १८०") == "पावती क्रं 180"
    assert normalize_devanagari_digits("Mixed 123 and ४५६") == "Mixed 123 and 456"


def test_flexible_date_cleaning_and_double_dots():
    """Verify double-dot date typos (03..07.2024) and Devanagari dates parse correctly."""
    assert clean_date_string("03..07.2024") == "03.07.2024"
    assert clean_date_string("16..07.2024") == "16.07.2024"
    assert clean_date_string("01//05/2024") == "01/05/2024"

    # parse_flexible_date integration
    assert parse_flexible_date("03..07.2024") == date(2024, 7, 3)
    assert parse_flexible_date("16..07.2024") == date(2024, 7, 16)
    assert parse_flexible_date("०९.१२.२०२४") == date(2024, 12, 9)
    assert parse_flexible_date("2024-11-05") == date(2024, 11, 5)
    assert parse_flexible_date("05-02-2024") == date(2024, 2, 5)


def test_classified_cashbook_multi_section_parsing(tmp_path):
    """
    Test parsing of multi-section Maharashtra Gram Panchayat classified cashbook:
    - Receipt sections (CREDIT) with repeating 'पावती क्रं,दिनांक,रक्कम'
    - Expenditure sections (DEBIT) with repeating 'प्रमाणक क्रं.,दिनांक ,रक्कम'
    - Section subtotal rows ignored as transactions
    - Summary rows (Opening, Closing, Total Receipts, Total Expenditures) captured as metadata
    - Continuation rows inherit last valid date in section
    - Section subtotal mismatch detected
    """
    cashbook_csv = tmp_path / "adarshgaon_classified_cashbook.csv"
    cashbook_csv.write_text(
        "ग्रामपंचायत आदर्शगाव (काल्पनिक चाचणी नमुना) - ग्रामनिधी सन 2024-25\n"
        "सुरुवातीची शिल्लक,,,,,,25400.00\n"
        "अनामत जमा नमुना\n"
        "पावती क्रं,दिनांक,रक्कम,नाव/तपशील\n"
        "१८०,०९.१२.२०२४,11500,अनामत रक्कम चाचणी नमुना १\n"
        "181,03..07.2024,3660,शॉपिंग भाडे चाचणी गाळा ४\n"
        "182,2024-08-10,5000,घरपट्टी वसुली चाचणी\n"
        ",,20160,,,20160,\n"  # Section subtotal row
        "बॅक चार्जेस नमुना\n"
        "प्रमाणक क्रं.,दिनांक ,रक्कम,तपशील\n"
        "१,01.04.2024,59,SMS Charges\n"
        "२,02.05.2024,118,Annual Maintenance\n"
        ",,177\n"  # Section subtotal row
        "कर्मचारी वेतन नमुना\n"
        "प्रमाणक क्रं.,दिनांक ,रक्कम,तपशील\n"
        "३,15.06.2024,25000,शिपाई पगार चाचणी\n"
        "४,,3240,रास्ता दुरस्ती चाचणी\n"  # Continuation row without date
        ",,28240\n"  # Section subtotal row
        "विशेष ग्राम विकास बक्षीस नमुना\n"
        "प्रमाणक क्रं.,दिनांक ,रक्कम,तपशील\n"
        "५,20.07.2024,3800000,ग्राम विकास योजना विकास कामे\n"
        ",,0\n"  # Section subtotal mismatch: calculated 3800000 vs declared 0
        "एकुण जमा,,,,,,8450200.00\n"
        "एकुण खर्च,,,,,,5120100.00\n"
        "अखेरची शिल्लक,,,,,,3355500.00\n"
        "एकुण एकंदर,,,,,,8475600.00\n",
        encoding="utf-8"
    )

    config = ReconciliationConfig(
        period_from="2024-04-01",
        period_to="2025-03-31",
        date_tolerance_days=3,
        amount_exact=True,
        output_folder=str(tmp_path / "out")
    )
    engine = DeterministicReconciliationEngine(config=config)
    rows = engine.load_ledger(cashbook_csv, "cashbook")

    # 1. Exactly 8 transaction rows parsed (subtotals and summaries excluded)
    assert len(rows) == 8

    # 2. Section 1 (अनामत जमा नमुना): CREDIT
    r0 = rows[0]
    assert r0.direction == "CREDIT"
    assert r0.reference == "180"  # Devanagari normalized
    assert r0.date == date(2024, 12, 9)
    assert r0.amount == Decimal("11500.00")
    assert r0.credit == Decimal("11500.00")
    assert r0.debit == Decimal("0.00")

    r1 = rows[1]
    assert r1.direction == "CREDIT"
    assert r1.reference == "181"
    assert r1.date == date(2024, 7, 3)  # Fixed double dot 03..07.2024
    assert r1.amount == Decimal("3660.00")

    r2 = rows[2]
    assert r2.direction == "CREDIT"
    assert r2.reference == "182"
    assert r2.date == date(2024, 8, 10)
    assert r2.amount == Decimal("5000.00")

    # 3. Section 2 (बॅक चार्जेस नमुना): DEBIT
    r3 = rows[3]
    assert r3.direction == "DEBIT"
    assert r3.reference == "1"
    assert r3.date == date(2024, 4, 1)
    assert r3.amount == Decimal("59.00")
    assert r3.debit == Decimal("59.00")

    r4 = rows[4]
    assert r4.direction == "DEBIT"
    assert r4.reference == "2"
    assert r4.date == date(2024, 5, 2)
    assert r4.amount == Decimal("118.00")

    # 4. Section 3 (कर्मचारी वेतन नमुना with continuation row)
    r5 = rows[5]
    assert r5.direction == "DEBIT"
    assert r5.reference == "3"
    assert r5.date == date(2024, 6, 15)
    assert r5.amount == Decimal("25000.00")

    r6 = rows[6]
    assert r6.direction == "DEBIT"
    assert r6.reference == "4"
    assert r6.date == date(2024, 6, 15)  # Inherited date from r5!
    assert r6.amount == Decimal("3240.00")
    assert "रास्ता दुरस्ती" in r6.narration

    # 5. Metadata verification
    meta = engine.get_ledger_metadata(cashbook_csv)
    assert meta["is_classified_gp_format"] is True
    assert meta["opening_balance"] == Decimal("25400.00")
    assert meta["closing_balance"] == Decimal("3355500.00")
    assert meta["summary_total_credits"] == Decimal("8450200.00")
    assert meta["summary_total_debits"] == Decimal("5120100.00")

    # 6. Section subtotal mismatch detection
    mismatches = meta.get("section_subtotal_mismatches", [])
    assert len(mismatches) >= 1
    smart_gram_mismatch = next((m for m in mismatches if "विशेष ग्राम विकास" in m["section"]), None)
    assert smart_gram_mismatch is not None
    assert smart_gram_mismatch["calculated_sum"] == Decimal("3800000.00")
    assert smart_gram_mismatch["declared_subtotal"] == Decimal("0.00")


def test_classified_cashbook_end_to_end_reconciliation(tmp_path):
    """End-to-end reconciliation pairing classified cashbook with bank statement."""
    cb_file = tmp_path / "cb.csv"
    bs_file = tmp_path / "bs.csv"
    out_dir = tmp_path / "reconciled_output"

    cb_file.write_text(
        "ग्रामपंचायत आदर्शगाव (काल्पनिक चाचणी नमुना) - ग्रामनिधी सन 2024-25\n"
        "सुरुवातीची शिल्लक,,,,,,25400.00\n"
        "अनामत जमा नमुना\n"
        "पावती क्रं,दिनांक,रक्कम,नाव/तपशील\n"
        "१८०,०९.१२.२०२४,11500,अनामत रक्कम चाचणी नमुना\n"
        "181,03..07.2024,3660,शॉपिंग भाडे चाचणी\n"
        ",,15160\n"
        "बॅक चार्जेस नमुना\n"
        "प्रमाणक क्रं.,दिनांक ,रक्कम,तपशील\n"
        "१,01.04.2024,59,SMS Charges\n"
        ",,59\n"
        "अखेरची शिल्लक,,,,,,40501.00\n",
        encoding="utf-8"
    )

    bs_file.write_text(
        "Date,Description,Withdrawals,Deposits,Balance\n"
        "01/04/2024,SMS CHARGES Q1,59.00,0.00,25341.00\n"
        "04/07/2024,CHQ CLG SHOPPING RENT 181,0.00,3660.00,29001.00\n"
        "10/12/2024,NEFT DEMO PARTY 180,0.00,11500.00,40501.00\n",
        encoding="utf-8"
    )

    config = ReconciliationConfig(
        period_from="2024-04-01",
        period_to="2025-03-31",
        date_tolerance_days=3,
        amount_exact=True,
        output_folder=str(out_dir)
    )
    engine = DeterministicReconciliationEngine(config=config)
    result = engine.reconcile(cb_file, bs_file, out_dir)

    assert result["summary"]["matched_count"] == 3
    assert result["summary"]["unmatched_cashbook_count"] == 0
    assert result["summary"]["unmatched_bank_count"] == 0
    assert (out_dir / "reconciliation.xlsx").exists()
    assert (out_dir / "reconciliation_result.json").exists()
    assert (out_dir / "run_manifest.json").exists()


def test_adarshgaon_synthetic_workbook_full_scale_parsing(tmp_path):
    """
    Ground-truth validation of the synthetic Adarshgaon Gram Panchayat workbook:
    'adarshgaon_gramnidhi_synthetic_2024_25.xlsx'.
    Asserts:
    1. Parsing 308 Receipt (जमा) rows summing to 8,450,200.00.
    2. Parsing 295 Expenditure (खर्च) rows summing to 5,120,100.00.
    3. Detection of 3,800,000 subtotal mismatch in 'विशेष ग्राम विकास बक्षीस नमुना'.
    4. Exact synthetic 5 figures:
       - Opening Balance: 25,400.00
       - Total Credits: 8,450,200.00
       - Total Debits: 5,120,100.00
       - Closing Balance: 3,355,500.00
       - Grand Total: 8,475,600.00
    5. Full-scale reconciliation against synthetic bank statement yielding 590+ matched pairs.
    """
    root = Path(__file__).resolve().parent.parent
    cb_xlsx = root / "pilot_demo" / "adarshgaon_gramnidhi_synthetic_2024_25.xlsx"
    bs_csv = root / "pilot_demo" / "adarshgaon_bank_synthetic_2024_25.csv"

    assert cb_xlsx.exists(), f"Synthetic workbook missing at {cb_xlsx}"
    assert bs_csv.exists(), f"Bank statement missing at {bs_csv}"

    config = ReconciliationConfig(
        period_from="2024-04-01",
        period_to="2025-03-31",
        date_tolerance_days=3,
        amount_exact=True,
        output_folder=str(tmp_path / "out")
    )
    engine = DeterministicReconciliationEngine(config=config)
    rows = engine.load_ledger(cb_xlsx, "cashbook")

    credit_rows = [r for r in rows if r.direction == "CREDIT"]
    assert len(credit_rows) == 308
    assert sum(r.amount for r in credit_rows) == Decimal("8450200.00")

    debit_rows = [r for r in rows if r.direction == "DEBIT"]
    assert len(debit_rows) == 295
    assert sum(r.amount for r in debit_rows) == Decimal("5120100.00")

    meta = engine.get_ledger_metadata(cb_xlsx)
    assert meta["is_classified_gp_format"] is True
    assert meta["opening_balance"] == Decimal("25400.00")
    assert meta["summary_total_credits"] == Decimal("8450200.00")
    assert meta["summary_total_debits"] == Decimal("5120100.00")
    assert meta["closing_balance"] == Decimal("3355500.00")
    assert meta["grand_total"] == Decimal("8475600.00")

    # Mismatch in Smart Gram section
    assert len(meta["section_subtotal_mismatches"]) == 1
    assert meta["section_subtotal_mismatches"][0]["difference"] == Decimal("3800000.00")

    # Full scale reconciliation
    out_dir = tmp_path / "out"
    result = engine.reconcile(cb_xlsx, bs_csv, out_dir)
    summary = result["summary"]

    assert summary["opening_balance"] == "25400.00"
    assert summary["closing_balance"] == "3355500.00"
    assert summary["grand_total"] == "8475600.00"
    assert summary["cashbook_total_credits"] == "8450200.00"
    assert summary["section_subtotal_debits"] == "5120100.00"
    assert summary["cashbook_credit_rows"] == 308
    assert summary["cashbook_debit_rows"] == 295
    assert summary["total_matched_pairs"] >= 590
    assert (out_dir / "reconciliation.xlsx").exists()
    assert (out_dir / "reconciliation_result.json").exists()
    assert (out_dir / "run_manifest.json").exists()
