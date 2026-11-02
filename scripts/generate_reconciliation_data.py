#!/usr/bin/env python3
"""
scripts/generate_reconciliation_data.py - Synthetic Gram Panchayat Reconciliation Dataset Generator
Generates realistic, bilingual (Marathi/English) cashbook and bank statement pairs (CSV & XLSX)
with configurable random seeds, injected accounting discrepancies, and verifiable ground_truth.json.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Tuple

import openpyxl


MARATHI_RECEIPT_NARRATIONS = [
    "घरपट्टी कर वसुली - वॉर्ड क्र. {w}",
    "पाणीपट्टी कर संकलन पावती क्र. {p}",
    "ग्रामपंचायत गाळा भाडे वसुली",
    "१५ वा वित्त आयोग बंधित अनुदान हप्ता",
    "महात्मा गांधी राष्ट्रीय ग्रामीण रोजगार हमी योजना निधी",
    "स्वच्छ भारत मिशन शौचालय अनुदान",
    "बाजार लिलाव पावती संकलन",
]

ENGLISH_RECEIPT_NARRATIONS = [
    "Property Tax Collection Ward {w}",
    "Water Supply Tax Collection Rcpt {p}",
    "Gram Panchayat Commercial Shop Rent",
    "15th Finance Commission Tied Grant",
    "MGNREGA Scheme Fund Transfer",
    "Swachh Bharat Mission Sanitation Fund",
    "Weekly Bazaar Auction Collection",
]

MARATHI_PAYMENT_NARRATIONS = [
    "ग्रामपंचायत पाणी पुरवठा वीज बिल महावितरण",
    "रस्ता डांबरीकरण व दुरुस्ती मजुरी",
    "ग्रामपंचायत कार्यालय स्टेशनरी व छपाई खर्च",
    "घनकचरा व्यवस्थापन सफाई कामगार मानधन",
    "पथदिवे देखभाल व दुरुस्ती साहित्य खरेदी",
    "RO वॉटर फिल्टर दुरुस्ती व फिल्टर बदलणे",
    "ग्रामसभा अल्पोपहार व चहापान खर्च",
]

ENGLISH_PAYMENT_NARRATIONS = [
    "Gram Panchayat Water Supply Electricity MSEDCL",
    "Internal Village Road Repair Wages",
    "Panchayat Office Stationery & Printing",
    "Solid Waste Sanitation Worker Wages",
    "Street Light Maintenance Spares",
    "Village RO Water Plant Filter Spares",
    "Gram Sabha Refreshment Expenses",
]

BANK_CHARGE_NARRATIONS = [
    "SMS ALERT CHARGES Q1 2026",
    "FOLIO SERVICE CHARGES",
    "SAVINGS BANK INTEREST CREDITED",
    "ANNUAL DEBIT CARD AMC CHARGES",
    "MONTHLY MINIMUM BALANCE CHARGES",
    "SB INTEREST CREDITED UPTO APR",
    "GST ON BANK CHARGES",
]


def format_indian_currency(dec: Decimal) -> str:
    """Format decimal into Indian comma grouped string: 1,23,456.78"""
    s = f"{dec:.2f}"
    parts = s.split(".")
    integer_part = parts[0]
    decimal_part = parts[1]

    if len(integer_part) <= 3:
        formatted = integer_part
    else:
        last3 = integer_part[-3:]
        rest = integer_part[:-3]
        groups = []
        while len(rest) > 2:
            groups.append(rest[-2:])
            rest = rest[:-2]
        if rest:
            groups.append(rest)
        groups.reverse()
        formatted = ",".join(groups) + "," + last3

    return f"{formatted}.{decimal_part}"


def generate_dataset(
    seed: int,
    output_dir: Path,
    num_txns: int = 30,
    file_format: str = "csv"
) -> Dict[str, Any]:
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)

    period_start = date(2026, 4, 1)
    period_end = date(2026, 4, 30)

    cb_rows: List[Dict[str, Any]] = []
    bs_rows: List[Dict[str, Any]] = []

    ground_truth_matches: List[Dict[str, Any]] = []
    ground_truth_exceptions: List[Dict[str, Any]] = []

    cheque_num_counter = 1000 + (seed % 500) * 10

    # 1. Generate Clean Matches (Pass 1 & Pass 2 candidates)
    num_clean = max(8, int(num_txns * 0.55))
    for i in range(num_clean):
        txn_date = period_start + timedelta(days=rng.randint(1, 26))
        is_receipt = rng.choice([True, False])
        amount = Decimal(str(rng.randint(5, 500) * 100)).quantize(Decimal("0.01"))
        cheque_no = f"CHQ{cheque_num_counter}"
        ref_no = f"{cheque_num_counter}"
        cheque_num_counter += 1

        is_marathi = rng.choice([True, False])
        if is_receipt:
            narr_template = rng.choice(MARATHI_RECEIPT_NARRATIONS if is_marathi else ENGLISH_RECEIPT_NARRATIONS)
        else:
            narr_template = rng.choice(MARATHI_PAYMENT_NARRATIONS if is_marathi else ENGLISH_PAYMENT_NARRATIONS)

        narr = narr_template.format(w=rng.randint(1, 6), p=rng.randint(101, 999))

        cb_rows.append({
            "date": txn_date.strftime("%d/%m/%Y"),
            "narration": narr,
            "ref": cheque_no,
            "credit": format_indian_currency(amount) if is_receipt else "0.00",
            "debit": "0.00" if is_receipt else format_indian_currency(amount),
            "_amount": amount,
            "_direction": "CREDIT" if is_receipt else "DEBIT"
        })

        # Bank side: cleared 0-3 days later
        clearing_delay = rng.randint(0, 3)
        bs_date = txn_date + timedelta(days=clearing_delay)
        bs_narr = f"CLG CHQ {ref_no} {narr[:25].upper()}"

        bs_rows.append({
            "date": bs_date.strftime("%d/%m/%Y"),
            "narration": bs_narr,
            "ref": ref_no,
            "withdrawal": "0.00" if is_receipt else format_indian_currency(amount),
            "deposit": format_indian_currency(amount) if is_receipt else "0.00",
            "_amount": amount,
            "_direction": "CREDIT" if is_receipt else "DEBIT"
        })

        ground_truth_matches.append({
            "ref": ref_no,
            "amount": str(amount),
            "direction": "CREDIT" if is_receipt else "DEBIT"
        })

    # 2. Inject Batched / Split Deposit (Pass 3)
    batch_date = date(2026, 4, 12)
    part1_amt = Decimal("6000.00")
    part2_amt = Decimal("4000.00")
    total_batch = part1_amt + part2_amt

    cb_rows.append({
        "date": batch_date.strftime("%d/%m/%Y"),
        "narration": "स्थानिक कर वसुली एकत्रित भरणा",
        "ref": "BATCH-DEP",
        "credit": format_indian_currency(total_batch),
        "debit": "0.00",
        "_amount": total_batch,
        "_direction": "CREDIT"
    })
    bs_rows.append({
        "date": (batch_date + timedelta(days=1)).strftime("%d/%m/%Y"),
        "narration": "CASH DEP PT1 GP REVENUE",
        "ref": "",
        "withdrawal": "0.00",
        "deposit": format_indian_currency(part1_amt),
        "_amount": part1_amt,
        "_direction": "CREDIT"
    })
    bs_rows.append({
        "date": (batch_date + timedelta(days=2)).strftime("%d/%m/%Y"),
        "narration": "CASH DEP PT2 GP REVENUE",
        "ref": "",
        "withdrawal": "0.00",
        "deposit": format_indian_currency(part2_amt),
        "_amount": part2_amt,
        "_direction": "CREDIT"
    })
    ground_truth_matches.append({
        "ref": "BATCH-DEP",
        "amount": str(total_batch),
        "type": "PASS_3_SPLIT_BATCH"
    })

    # 3. Inject In Cashbook Only
    cb_only_date = date(2026, 4, 18)
    cb_only_amt = Decimal("14500.00")
    chq_cb_only = f"CHQ{cheque_num_counter}"
    cheque_num_counter += 1
    cb_rows.append({
        "date": cb_only_date.strftime("%d/%m/%Y"),
        "narration": "ग्रामपंचायत संगणक दुरुस्ती खर्च",
        "ref": chq_cb_only,
        "credit": "0.00",
        "debit": format_indian_currency(cb_only_amt),
        "_amount": cb_only_amt,
        "_direction": "DEBIT"
    })
    ground_truth_exceptions.append({
        "category": "in_cashbook_only",
        "ref": chq_cb_only,
        "amount": str(cb_only_amt)
    })

    # 4. Inject In Bank Only
    bs_only_date = date(2026, 4, 20)
    bs_only_amt = Decimal("50000.00")
    bs_rows.append({
        "date": bs_only_date.strftime("%d/%m/%Y"),
        "narration": "DIRECT DBT GOVT GRANT CREDITED",
        "ref": "DBT88291",
        "withdrawal": "0.00",
        "deposit": format_indian_currency(bs_only_amt),
        "_amount": bs_only_amt,
        "_direction": "CREDIT"
    })
    ground_truth_exceptions.append({
        "category": "in_bank_only",
        "ref": "DBT88291",
        "amount": str(bs_only_amt)
    })

    # 5. Inject Amount Mismatch (Transposed Digits)
    trans_date = date(2026, 4, 14)
    chq_trans = f"CHQ{cheque_num_counter}"
    ref_trans = f"{cheque_num_counter}"
    cheque_num_counter += 1
    cb_amt_trans = Decimal("5400.00")
    bs_amt_trans = Decimal("4500.00")

    cb_rows.append({
        "date": trans_date.strftime("%d/%m/%Y"),
        "narration": "ग्रामपंचायत स्टेशनरी साहित्य खरेदी",
        "ref": chq_trans,
        "credit": "0.00",
        "debit": format_indian_currency(cb_amt_trans),
        "_amount": cb_amt_trans,
        "_direction": "DEBIT"
    })
    bs_rows.append({
        "date": (trans_date + timedelta(days=1)).strftime("%d/%m/%Y"),
        "narration": f"CLG CHQ {ref_trans} STATIONERY",
        "ref": ref_trans,
        "withdrawal": format_indian_currency(bs_amt_trans),
        "deposit": "0.00",
        "_amount": bs_amt_trans,
        "_direction": "DEBIT"
    })
    ground_truth_exceptions.append({
        "category": "amount_mismatch",
        "ref": ref_trans,
        "cashbook_amount": str(cb_amt_trans),
        "bank_amount": str(bs_amt_trans),
        "is_transposed": True
    })

    # 6. Inject Suspected Bank Charges / Interest
    charge_date = date(2026, 4, 24)
    charge_amt = Decimal("29.50")
    bs_rows.append({
        "date": charge_date.strftime("%d/%m/%Y"),
        "narration": "SMS ALERT SERVICE CHARGES Q1",
        "ref": "",
        "withdrawal": format_indian_currency(charge_amt),
        "deposit": "0.00",
        "_amount": charge_amt,
        "_direction": "DEBIT"
    })
    ground_truth_exceptions.append({
        "category": "suspected_bank_charge_or_interest",
        "narration": "SMS ALERT SERVICE CHARGES Q1",
        "amount": str(charge_amt)
    })

    # 7. Inject Date Outside Period
    prior_date = date(2026, 3, 28)
    prior_amt = Decimal("3500.00")
    cb_rows.append({
        "date": prior_date.strftime("%d/%m/%Y"),
        "narration": "मागील महिन्याची शिल्लक नोंद",
        "ref": "PREV-01",
        "credit": format_indian_currency(prior_amt),
        "debit": "0.00",
        "_amount": prior_amt,
        "_direction": "CREDIT"
    })
    ground_truth_exceptions.append({
        "category": "date_outside_period",
        "date": prior_date.strftime("%Y-%m-%d"),
        "amount": str(prior_amt)
    })

    # Shuffle rows deterministically with seeded rng
    rng.shuffle(cb_rows)
    rng.shuffle(bs_rows)

    # File paths
    cb_file = output_dir / f"cashbook.{file_format}"
    bs_file = output_dir / f"bank_statement.{file_format}"

    # Write files
    if file_format == "csv":
        with open(cb_file, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["दिनांक", "तपशील", "पावती / चेक क्र.", "जमा (₹)", "नावे (₹)"])
            for r in cb_rows:
                w.writerow([r["date"], r["narration"], r["ref"], r["credit"], r["debit"]])

        with open(bs_file, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["Date", "Narration", "Cheque / Ref No", "Withdrawal (Dr)", "Deposit (Cr)"])
            for r in bs_rows:
                w.writerow([r["date"], r["narration"], r["ref"], r["withdrawal"], r["deposit"]])
    else:
        # XLSX format
        wb_cb = openpyxl.Workbook()
        ws_cb = wb_cb.active
        ws_cb.title = "Cashbook"
        ws_cb.append(["दिनांक", "तपशील", "पावती / चेक क्र.", "जमा (₹)", "नावे (₹)"])
        for r in cb_rows:
            ws_cb.append([r["date"], r["narration"], r["ref"], r["credit"], r["debit"]])
        wb_cb.save(cb_file)

        wb_bs = openpyxl.Workbook()
        ws_bs = wb_bs.active
        ws_bs.title = "BankStatement"
        ws_bs.append(["Date", "Narration", "Cheque / Ref No", "Withdrawal (Dr)", "Deposit (Cr)"])
        for r in bs_rows:
            ws_bs.append([r["date"], r["narration"], r["ref"], r["withdrawal"], r["deposit"]])
        wb_bs.save(bs_file)

    ground_truth = {
        "dataset_seed": seed,
        "format": file_format,
        "period_from": "2026-04-01",
        "period_to": "2026-04-30",
        "total_cashbook_rows": len(cb_rows),
        "total_bank_rows": len(bs_rows),
        "expected_matched_count": len(ground_truth_matches),
        "expected_exceptions_count": len(ground_truth_exceptions),
        "expected_exceptions": ground_truth_exceptions
    }

    gt_file = output_dir / "ground_truth.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)

    return {
        "cashbook_file": str(cb_file),
        "bank_statement_file": str(bs_file),
        "ground_truth_file": str(gt_file),
        "ground_truth": ground_truth
    }


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic Gram Panchayat reconciliation datasets")
    parser.add_argument("--seed", type=int, default=101, help="Random seed")
    parser.add_argument("--count", type=int, default=1, help="Number of datasets to generate")
    parser.add_argument("--out", type=str, default="data/synthetic_recon", help="Output directory")
    parser.add_argument("--format", type=str, choices=["csv", "xlsx", "mixed"], default="csv", help="File format")
    args = parser.parse_args()

    base_out = Path(args.out).resolve()
    base_out.mkdir(parents=True, exist_ok=True)

    for i in range(args.count):
        cur_seed = args.seed + i
        cur_fmt = "xlsx" if args.format == "xlsx" or (args.format == "mixed" and i % 2 == 1) else "csv"
        ds_dir = base_out / f"dataset_{cur_seed:04d}"
        res = generate_dataset(seed=cur_seed, output_dir=ds_dir, file_format=cur_fmt)
        print(f"[+] Generated dataset {cur_seed:04d} ({cur_fmt}) at: {ds_dir}")


if __name__ == "__main__":
    main()

