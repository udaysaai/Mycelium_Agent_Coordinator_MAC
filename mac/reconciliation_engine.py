"""
mac/reconciliation_engine.py - Pure Deterministic Cashbook <-> Bank Statement Reconciliation Engine
Enforces Decimal precision, Indian currency parsing, bilingual English/Devanagari header handling,
4-pass matching logic, CSV/XLSX formula injection defenses, and manifest generation.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import openpyxl

from privacy import redact_pii_string


# -----------------------------------------------------------------------------
# 1. Parsing & Normalization Utilities
# -----------------------------------------------------------------------------

def parse_indian_amount(val: Any) -> Decimal:
    """
    Parse currency string/number into an exact Decimal quantized to 2 places.
    Supports Indian lakh/crore comma grouping (e.g. 1,23,456.78), currency symbols (₹, Rs, INR),
    parentheses for negatives (1,000.00), and Dr/Cr suffixes.
    """
    if val is None or val == "":
        return Decimal("0.00")

    if isinstance(val, (int, float, Decimal)):
        return Decimal(str(val)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    text = str(val).strip()
    if not text:
        return Decimal("0.00")

    # NFC normalize
    text = unicodedata.normalize("NFC", text)

    # Detect negative indicator in parentheses: (1,234.56)
    is_negative = False
    if text.startswith("(") and text.endswith(")"):
        is_negative = True
        text = text[1:-1].strip()

    # Detect Dr suffix or - prefix
    lower = text.lower()
    if lower.endswith("dr"):
        text = text[:-2].strip()
    elif lower.endswith("cr"):
        text = text[:-2].strip()

    if text.startswith("-"):
        is_negative = not is_negative
        text = text[1:].strip()
    elif text.startswith("+"):
        text = text[1:].strip()

    # Strip currency symbols, spaces, commas
    cleaned = re.sub(r"[₹RsINRinr,\s]", "", text)
    if not cleaned or cleaned == ".":
        return Decimal("0.00")

    try:
        dec = Decimal(cleaned)
        if is_negative:
            dec = -dec
        return dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError):
        return Decimal("0.00")


def parse_flexible_date(val: Any) -> Optional[date]:
    """
    Parse a variety of date formats (dd/mm/yyyy, dd-mm-yyyy, yyyy-mm-dd, openpyxl datetime).
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, date):
        return val

    s = str(val).strip()
    if not s:
        return None

    # Supported formats
    formats = [
        "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y",
        "%d/%m/%y", "%d-%m-%y", "%Y/%m/%d", "%d %b %Y", "%d %B %Y"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def sanitize_cell_formula_injection(val: Any) -> Any:
    """
    Sanitize text to prevent CSV/XLSX formula injection when opened in Excel/Calc.
    Prepends a single quote if string begins with =, +, -, @, \\t, or \\r.
    """
    if val is None:
        return ""
    if not isinstance(val, str):
        return val

    s = str(val)
    if not s:
        return s

    if s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"

    return s


def normalize_reference(ref_str: Any) -> str:
    """
    Normalize cheque, voucher, or UTR numbers for matching.
    Strips leading zeroes, punctuation, spaces, and prefixes (CHQ-, UTR-).
    """
    if not ref_str:
        return ""
    text = str(ref_str).strip()
    # Strip common prefixes
    text = re.sub(r"(?i)^(chq|cheque|utr|vchr|vch|trn|ref|chqno|receipt|rcpt)[-:\s#]*", "", text)
    # Retain alphanumeric only
    alphanumeric = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    # If purely digits, strip leading zeros
    if alphanumeric.isdigit():
        return str(int(alphanumeric))
    return alphanumeric


def are_transposed_amounts(a: Decimal, b: Decimal) -> bool:
    """
    Detect if two amounts differ by an adjacent digit transposition typo (e.g. 5400 vs 4500).
    """
    if a == b:
        return False
    # Format as string of cents
    str_a = f"{abs(a):.2f}".replace(".", "")
    str_b = f"{abs(b):.2f}".replace(".", "")
    if len(str_a) != len(str_b):
        return False

    # Check if swapping any two adjacent characters produces the other
    chars = list(str_a)
    for i in range(len(chars) - 1):
        if chars[i] != chars[i + 1]:
            swapped = list(chars)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            if "".join(swapped) == str_b:
                return True
    return False


# -----------------------------------------------------------------------------
# 2. Data Models
# -----------------------------------------------------------------------------

@dataclass
class LedgerRow:
    row_id: str
    source: str  # "cashbook" or "bank"
    row_index: int
    date: Optional[date]
    raw_date_str: str
    narration: str
    reference: str
    normalized_ref: str
    debit: Decimal
    credit: Decimal
    amount: Decimal  # magnitude for matching
    direction: str   # "CREDIT" (deposit) or "DEBIT" (withdrawal)
    balance: Optional[Decimal] = None
    raw_row: Dict[str, Any] = field(default_factory=dict)
    matched: bool = False


@dataclass
class ReconciliationConfig:
    period_from: str
    period_to: str
    opening_balance_source: str = "cashbook"
    date_tolerance_days: int = 3
    amount_exact: bool = True
    output_folder: str = "reconciliation_output"


# -----------------------------------------------------------------------------
# 3. Deterministic Reconciliation Engine
# -----------------------------------------------------------------------------

class DeterministicReconciliationEngine:
    """
    Pure Python deterministic reconciliation engine for Gram Panchayat & Local Body accounts.
    Executes four strictly ordered matching passes and produces tamper-evident audit outputs.
    """

    SUSPECTED_BANK_TERMS = {
        "interest", "int", "charges", "chg", "charge", "fee", "fees",
        "sms", "commission", "comm", "gst", "cgst", "sgst", "tax", "tds",
        "व्याज", "शुल्क", "चार्ज", "कमिशन", "कर"
    }

    def __init__(self, config: ReconciliationConfig):
        self.config = config
        self.period_start: Optional[date] = parse_flexible_date(config.period_from)
        self.period_end: Optional[date] = parse_flexible_date(config.period_to)

    def load_ledger(self, file_path: Path, source_name: str) -> List[LedgerRow]:
        """
        Load CSV or XLSX ledger file into normalized LedgerRow objects.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Ledger file not found: {p}")

        suffix = p.suffix.lower()
        if suffix == ".csv":
            return self._load_csv(p, source_name)
        elif suffix in (".xlsx", ".xlsm"):
            return self._load_xlsx(p, source_name)
        else:
            raise ValueError(f"Unsupported file format '{suffix}'. Supported: .csv, .xlsx")

    def _detect_headers(self, raw_headers: List[str]) -> Dict[str, int]:
        """
        Bilingual English/Marathi header detection with NFC normalization.
        """
        mapping = {}
        for idx, h in enumerate(raw_headers):
            if not h:
                continue
            norm = unicodedata.normalize("NFC", str(h)).strip().lower()

            # Date
            if any(k in norm for k in ["दिनांक", "तारीख", "date", "txn date", "transaction date", "value date"]):
                mapping.setdefault("date", idx)

            # Narration / Particulars
            elif any(k in norm for k in ["तपशील", "विवरण", "तपशिल", "narration", "particulars", "description", "details"]):
                mapping.setdefault("narration", idx)

            # Reference / Cheque
            elif any(k in norm for k in [
                "पावती", "चेक क्र", "धनादेश", "व्हाउचर", "चैक", "cheque", "chq", "ref", "reference", "utr", "voucher", "trn id"
            ]):
                mapping.setdefault("reference", idx)

            # Debit / Withdrawal / Payments
            elif any(k in norm for k in ["नावे", "खर्च", "debit", "withdrawal", "dr", "payment"]):
                mapping.setdefault("debit", idx)

            # Credit / Deposit / Receipts
            elif any(k in norm for k in ["जमा", "credit", "deposit", "cr", "receipt"]):
                mapping.setdefault("credit", idx)

            # Balance
            elif any(k in norm for k in ["शिल्लक", "बाकी", "balance"]):
                mapping.setdefault("balance", idx)

            # Single Amount column
            elif any(k in norm for k in ["रक्कम", "amount"]):
                mapping.setdefault("amount", idx)

        return mapping

    def _load_csv(self, file_path: Path, source_name: str) -> List[LedgerRow]:
        rows: List[LedgerRow] = []
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.reader(f)
            header_row = None
            for row in reader:
                if any(row):
                    header_row = row
                    break
            if not header_row:
                return []

            mapping = self._detect_headers(header_row)
            row_idx = 1
            for raw_cells in reader:
                if not any(raw_cells):
                    continue
                row_obj = self._build_ledger_row(raw_cells, mapping, source_name, row_idx)
                if row_obj:
                    rows.append(row_obj)
                    row_idx += 1
        return rows

    def _load_xlsx(self, file_path: Path, source_name: str) -> List[LedgerRow]:
        rows: List[LedgerRow] = []
        wb = openpyxl.load_workbook(file_path, data_only=True)
        sheet = wb.active
        header_row = None
        for row in sheet.iter_rows(values_only=True):
            if any(row):
                header_row = [str(c or "") for c in row]
                break
        if not header_row:
            return []

        mapping = self._detect_headers(header_row)
        row_idx = 1
        # Iterate remaining rows
        seen_header = False
        for raw_cells in sheet.iter_rows(values_only=True):
            if not seen_header:
                if any(raw_cells):
                    seen_header = True
                continue
            if not any(raw_cells):
                continue
            row_obj = self._build_ledger_row(list(raw_cells), mapping, source_name, row_idx)
            if row_obj:
                rows.append(row_obj)
                row_idx += 1
        return rows

    def _build_ledger_row(
        self,
        cells: List[Any],
        mapping: Dict[str, int],
        source_name: str,
        row_idx: int
    ) -> Optional[LedgerRow]:
        def get_val(key: str) -> str:
            if key in mapping and mapping[key] < len(cells):
                v = cells[mapping[key]]
                return str(v).strip() if v is not None else ""
            return ""

        raw_date = get_val("date")
        parsed_d = parse_flexible_date(raw_date)

        narration = unicodedata.normalize("NFC", get_val("narration"))
        reference = unicodedata.normalize("NFC", get_val("reference"))
        norm_ref = normalize_reference(reference)

        debit = parse_indian_amount(get_val("debit"))
        credit = parse_indian_amount(get_val("credit"))

        # Fallback to single amount column if separate debit/credit not present
        if debit == Decimal("0.00") and credit == Decimal("0.00") and "amount" in mapping:
            amt = parse_indian_amount(get_val("amount"))
            if amt < Decimal("0.00"):
                debit = abs(amt)
            else:
                credit = amt

        if debit > Decimal("0.00"):
            amount = debit
            direction = "DEBIT"
        else:
            amount = credit
            direction = "CREDIT"

        balance_val = get_val("balance")
        balance = parse_indian_amount(balance_val) if balance_val else None

        prefix = "CB" if source_name == "cashbook" else "BS"
        row_id = f"{prefix}_{row_idx:04d}"

        return LedgerRow(
            row_id=row_id,
            source=source_name,
            row_index=row_idx,
            date=parsed_d,
            raw_date_str=raw_date,
            narration=narration,
            reference=reference,
            normalized_ref=norm_ref,
            debit=debit,
            credit=credit,
            amount=amount,
            direction=direction,
            balance=balance,
            raw_row={f"col_{i}": str(c) for i, c in enumerate(cells)}
        )

    # -------------------------------------------------------------------------
    # 4. Reconciliation Core Logic (Four-Pass Execution)
    # -------------------------------------------------------------------------

    def reconcile(
        self,
        cashbook_path: Path,
        bank_path: Path,
        output_dir: Path
    ) -> Dict[str, Any]:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        cb_rows = self.load_ledger(cashbook_path, "cashbook")
        bs_rows = self.load_ledger(bank_path, "bank")

        # Capture file hashes before processing
        cb_hash = self._file_sha256(cashbook_path)
        bs_hash = self._file_sha256(bank_path)

        matched_records: List[Dict[str, Any]] = []
        exceptions: List[Dict[str, Any]] = []

        match_id_counter = 1

        # ---------------------------------------------------------------------
        # Pass 1: Exact Amount + Exact Normalized Reference
        # ---------------------------------------------------------------------
        for cb in cb_rows:
            if cb.matched or not cb.normalized_ref or len(cb.normalized_ref) < 3:
                continue

            # Look for exact matching reference in bank statement
            candidates = [
                bs for bs in bs_rows
                if not bs.matched
                and bs.normalized_ref == cb.normalized_ref
                and bs.amount == cb.amount
                and bs.direction == cb.direction
            ]
            if candidates:
                bs_match = candidates[0]
                cb.matched = True
                bs_match.matched = True
                matched_records.append({
                    "match_id": f"MATCH_{match_id_counter:04d}",
                    "match_pass": "PASS_1_EXACT_REFERENCE",
                    "reference": cb.reference or bs_match.reference,
                    "direction": cb.direction,
                    "cashbook_row_id": cb.row_id,
                    "cashbook_date": str(cb.date or cb.raw_date_str),
                    "cashbook_narration": cb.narration,
                    "cashbook_amount": f"{cb.amount:.2f}",
                    "bank_row_id": bs_match.row_id,
                    "bank_date": str(bs_match.date or bs_match.raw_date_str),
                    "bank_narration": bs_match.narration,
                    "bank_amount": f"{bs_match.amount:.2f}",
                    "date_diff_days": abs((cb.date - bs_match.date).days) if (cb.date and bs_match.date) else 0
                })
                match_id_counter += 1

        # ---------------------------------------------------------------------
        # Pass 2: Exact Amount + Date within Tolerance
        # ---------------------------------------------------------------------
        for cb in cb_rows:
            if cb.matched or not cb.date:
                continue

            candidates = []
            for bs in bs_rows:
                if bs.matched or not bs.date:
                    continue
                if bs.amount == cb.amount and bs.direction == cb.direction:
                    diff = abs((cb.date - bs.date).days)
                    if diff <= self.config.date_tolerance_days:
                        candidates.append((diff, bs.row_index, bs))

            if candidates:
                # Deterministic tie-breaking: minimum date diff, lowest bank row index
                candidates.sort(key=lambda x: (x[0], x[1]))
                best_bs = candidates[0][2]

                cb.matched = True
                best_bs.matched = True
                matched_records.append({
                    "match_id": f"MATCH_{match_id_counter:04d}",
                    "match_pass": "PASS_2_AMOUNT_DATE_TOLERANCE",
                    "reference": cb.reference or best_bs.reference or "N/A",
                    "direction": cb.direction,
                    "cashbook_row_id": cb.row_id,
                    "cashbook_date": str(cb.date or cb.raw_date_str),
                    "cashbook_narration": cb.narration,
                    "cashbook_amount": f"{cb.amount:.2f}",
                    "bank_row_id": best_bs.row_id,
                    "bank_date": str(best_bs.date or best_bs.raw_date_str),
                    "bank_narration": best_bs.narration,
                    "bank_amount": f"{best_bs.amount:.2f}",
                    "date_diff_days": abs((cb.date - best_bs.date).days)
                })
                match_id_counter += 1

        # ---------------------------------------------------------------------
        # Pass 3: One-to-Many / Many-to-One Bounded Subset-Sum
        # ---------------------------------------------------------------------
        # Case A: One Cashbook row matches multiple Bank Statement rows
        for cb in cb_rows:
            if cb.matched or not cb.date:
                continue

            # Eligible bank candidate pool within date tolerance
            pool = [
                bs for bs in bs_rows
                if not bs.matched
                and bs.date
                and bs.direction == cb.direction
                and abs((cb.date - bs.date).days) <= self.config.date_tolerance_days
                and bs.amount < cb.amount
            ]

            found_subset = None
            # Check combinations of size 2 up to 5
            for k in range(2, min(len(pool) + 1, 6)):
                for subset in combinations(pool, k):
                    if sum(b.amount for b in subset) == cb.amount:
                        found_subset = list(subset)
                        break
                if found_subset:
                    break

            if found_subset:
                cb.matched = True
                for b in found_subset:
                    b.matched = True
                matched_records.append({
                    "match_id": f"MATCH_{match_id_counter:04d}",
                    "match_pass": "PASS_3_SPLIT_BATCH",
                    "reference": cb.reference or "BATCH",
                    "direction": cb.direction,
                    "cashbook_row_id": cb.row_id,
                    "cashbook_date": str(cb.date or cb.raw_date_str),
                    "cashbook_narration": cb.narration,
                    "cashbook_amount": f"{cb.amount:.2f}",
                    "bank_row_id": ",".join(b.row_id for b in found_subset),
                    "bank_date": ",".join(str(b.date) for b in found_subset),
                    "bank_narration": " + ".join(b.narration for b in found_subset),
                    "bank_amount": f"{sum(b.amount for b in found_subset):.2f}",
                    "date_diff_days": max(abs((cb.date - b.date).days) for b in found_subset)
                })
                match_id_counter += 1

        # Case B: One Bank row matches multiple Cashbook rows
        for bs in bs_rows:
            if bs.matched or not bs.date:
                continue

            pool = [
                cb for cb in cb_rows
                if not cb.matched
                and cb.date
                and cb.direction == bs.direction
                and abs((bs.date - cb.date).days) <= self.config.date_tolerance_days
                and cb.amount < bs.amount
            ]

            found_subset = None
            for k in range(2, min(len(pool) + 1, 6)):
                for subset in combinations(pool, k):
                    if sum(c.amount for c in subset) == bs.amount:
                        found_subset = list(subset)
                        break
                if found_subset:
                    break

            if found_subset:
                bs.matched = True
                for c in found_subset:
                    c.matched = True
                matched_records.append({
                    "match_id": f"MATCH_{match_id_counter:04d}",
                    "match_pass": "PASS_3_SPLIT_BATCH",
                    "reference": bs.reference or "BATCH",
                    "direction": bs.direction,
                    "cashbook_row_id": ",".join(c.row_id for c in found_subset),
                    "cashbook_date": ",".join(str(c.date) for c in found_subset),
                    "cashbook_narration": " + ".join(c.narration for c in found_subset),
                    "cashbook_amount": f"{sum(c.amount for c in found_subset):.2f}",
                    "bank_row_id": bs.row_id,
                    "bank_date": str(bs.date or bs.raw_date_str),
                    "bank_narration": bs.narration,
                    "bank_amount": f"{bs.amount:.2f}",
                    "date_diff_days": max(abs((bs.date - c.date).days) for c in found_subset)
                })
                match_id_counter += 1

        # ---------------------------------------------------------------------
        # Pass 4: Exception Categorization for Unmatched Rows
        # ---------------------------------------------------------------------
        exception_id_counter = 1

        # 1. Identify Amount Mismatches (transposed digits / typos with same reference)
        for cb in cb_rows:
            if cb.matched:
                continue
            candidates = [
                bs for bs in bs_rows
                if not bs.matched
                and cb.normalized_ref
                and bs.normalized_ref == cb.normalized_ref
                and bs.direction == cb.direction
            ]
            if candidates:
                bs = candidates[0]
                cb.matched = True
                bs.matched = True
                is_trans = are_transposed_amounts(cb.amount, bs.amount)
                exceptions.append({
                    "exception_id": f"EXC_{exception_id_counter:04d}",
                    "category": "amount_mismatch",
                    "source_ledger": "both",
                    "cashbook_row_id": cb.row_id,
                    "bank_row_id": bs.row_id,
                    "date": str(cb.date or cb.raw_date_str),
                    "reference": cb.reference,
                    "narration": f"CB: {cb.narration} | BS: {bs.narration}",
                    "direction": cb.direction,
                    "cashbook_amount": f"{cb.amount:.2f}",
                    "bank_amount": f"{bs.amount:.2f}",
                    "amount_difference": f"{abs(cb.amount - bs.amount):.2f}",
                    "is_transposed_digits": is_trans,
                    "notes": "Digit transposition detected." if is_trans else "Amount typo discrepancy."
                })
                exception_id_counter += 1

        # 2. Identify Suspected Bank Charges or Interest on Bank side
        for bs in bs_rows:
            if bs.matched:
                continue
            lower_narr = bs.narration.lower()
            if any(term in lower_narr for term in self.SUSPECTED_BANK_TERMS):
                bs.matched = True
                exceptions.append({
                    "exception_id": f"EXC_{exception_id_counter:04d}",
                    "category": "suspected_bank_charge_or_interest",
                    "source_ledger": "bank",
                    "bank_row_id": bs.row_id,
                    "date": str(bs.date or bs.raw_date_str),
                    "reference": bs.reference,
                    "narration": bs.narration,
                    "direction": bs.direction,
                    "amount": f"{bs.amount:.2f}",
                    "notes": "Direct bank charge, fee, or interest credit not yet entered in cashbook."
                })
                exception_id_counter += 1

        # 3. Identify Date Outside Period Exceptions
        for r in cb_rows + bs_rows:
            if r.matched:
                continue
            if r.date:
                is_outside = False
                if self.period_start and r.date < self.period_start:
                    is_outside = True
                elif self.period_end and r.date > self.period_end:
                    is_outside = True

                if is_outside:
                    r.matched = True
                    exceptions.append({
                        "exception_id": f"EXC_{exception_id_counter:04d}",
                        "category": "date_outside_period",
                        "source_ledger": r.source,
                        "row_id": r.row_id,
                        "date": str(r.date),
                        "reference": r.reference,
                        "narration": r.narration,
                        "direction": r.direction,
                        "amount": f"{r.amount:.2f}",
                        "notes": f"Transaction date {r.date} is outside the active period."
                    })
                    exception_id_counter += 1

        # 4. Identify Duplicates within same ledger
        def _flag_duplicates(row_list: List[LedgerRow], src: str):
            nonlocal exception_id_counter
            all_counts: Dict[Tuple[str, Decimal, str], int] = {}
            for r in row_list:
                key = (r.normalized_ref or r.narration, r.amount, r.direction)
                all_counts[key] = all_counts.get(key, 0) + 1

            for r in row_list:
                if r.matched:
                    continue
                key = (r.normalized_ref or r.narration, r.amount, r.direction)
                if all_counts.get(key, 0) > 1:
                    r.matched = True
                    exceptions.append({
                        "exception_id": f"EXC_{exception_id_counter:04d}",
                        "category": "duplicate",
                        "source_ledger": src,
                        "row_id": r.row_id,
                        "date": str(r.date or r.raw_date_str),
                        "reference": r.reference,
                        "narration": r.narration,
                        "direction": r.direction,
                        "amount": f"{r.amount:.2f}",
                        "notes": f"Duplicate identical row in {src}."
                    })
                    exception_id_counter += 1

        _flag_duplicates(cb_rows, "cashbook")
        _flag_duplicates(bs_rows, "bank")

        # 5. Remaining Unmatched Rows
        for cb in cb_rows:
            if not cb.matched:
                cb.matched = True
                exceptions.append({
                    "exception_id": f"EXC_{exception_id_counter:04d}",
                    "category": "in_cashbook_only",
                    "source_ledger": "cashbook",
                    "row_id": cb.row_id,
                    "date": str(cb.date or cb.raw_date_str),
                    "reference": cb.reference,
                    "narration": cb.narration,
                    "direction": cb.direction,
                    "amount": f"{cb.amount:.2f}",
                    "notes": "Transaction entered in cashbook but not yet reflected in bank statement."
                })
                exception_id_counter += 1

        for bs in bs_rows:
            if not bs.matched:
                bs.matched = True
                exceptions.append({
                    "exception_id": f"EXC_{exception_id_counter:04d}",
                    "category": "in_bank_only",
                    "source_ledger": "bank",
                    "row_id": bs.row_id,
                    "date": str(bs.date or bs.raw_date_str),
                    "reference": bs.reference,
                    "narration": bs.narration,
                    "direction": bs.direction,
                    "amount": f"{bs.amount:.2f}",
                    "notes": "Transaction reflected in bank statement but missing from cashbook."
                })
                exception_id_counter += 1

        # Sort exceptions deterministically
        exceptions.sort(key=lambda e: (e["category"], e.get("date", ""), e.get("row_id", "")))

        # Summary Metrics
        cb_total_credits = sum(r.credit for r in cb_rows)
        cb_total_debits = sum(r.debit for r in cb_rows)
        bs_total_deposits = sum(r.credit for r in bs_rows)
        bs_total_withdrawals = sum(r.debit for r in bs_rows)

        summary = {
            "period_from": self.config.period_from,
            "period_to": self.config.period_to,
            "cashbook_total_rows": len(cb_rows),
            "bank_total_rows": len(bs_rows),
            "total_matched_pairs": len(matched_records),
            "total_exceptions": len(exceptions),
            "cashbook_total_credits": f"{cb_total_credits:.2f}",
            "cashbook_total_debits": f"{cb_total_debits:.2f}",
            "bank_total_deposits": f"{bs_total_deposits:.2f}",
            "bank_total_withdrawals": f"{bs_total_withdrawals:.2f}",
            "matched_by_pass": {
                "PASS_1_EXACT_REFERENCE": sum(1 for m in matched_records if m["match_pass"] == "PASS_1_EXACT_REFERENCE"),
                "PASS_2_AMOUNT_DATE_TOLERANCE": sum(1 for m in matched_records if m["match_pass"] == "PASS_2_AMOUNT_DATE_TOLERANCE"),
                "PASS_3_SPLIT_BATCH": sum(1 for m in matched_records if m["match_pass"] == "PASS_3_SPLIT_BATCH"),
            },
            "exceptions_by_category": {
                cat: sum(1 for e in exceptions if e["category"] == cat)
                for cat in [
                    "in_cashbook_only", "in_bank_only", "amount_mismatch",
                    "duplicate", "date_outside_period", "suspected_bank_charge_or_interest"
                ]
            }
        }

        result = {
            "summary": summary,
            "matched": matched_records,
            "exceptions": exceptions
        }

        # ---------------------------------------------------------------------
        # Output Generation
        # ---------------------------------------------------------------------
        json_path = output_dir / "reconciliation_result.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True, ensure_ascii=False)

        manifest_path = output_dir / "run_manifest.json"
        manifest = {
            "engine_version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "inputs": {
                "cashbook_file": str(cashbook_path),
                "cashbook_sha256": cb_hash,
                "bank_file": str(bank_path),
                "bank_sha256": bs_hash
            },
            "parameters": {
                "period_from": self.config.period_from,
                "period_to": self.config.period_to,
                "date_tolerance_days": self.config.date_tolerance_days,
                "amount_exact": self.config.amount_exact,
                "opening_balance_source": self.config.opening_balance_source
            },
            "outputs": {
                "reconciliation_result_json": "reconciliation_result.json",
                "reconciliation_xlsx": "reconciliation.xlsx"
            }
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        xlsx_path = output_dir / "reconciliation.xlsx"
        self._write_excel(xlsx_path, summary, matched_records, exceptions)

        return result

    def _write_excel(
        self,
        xlsx_path: Path,
        summary: Dict[str, Any],
        matched: List[Dict[str, Any]],
        exceptions: List[Dict[str, Any]]
    ) -> None:
        wb = openpyxl.Workbook()

        # Sheet 1: Summary
        ws_sum = wb.active
        ws_sum.title = "Summary"
        ws_sum.append(["Reconciliation Summary Report", ""])
        ws_sum.append(["Period", f"{summary['period_from']} to {summary['period_to']}"])
        ws_sum.append(["Cashbook Total Rows", summary["cashbook_total_rows"]])
        ws_sum.append(["Bank Statement Total Rows", summary["bank_total_rows"]])
        ws_sum.append(["Total Matched Pairs", summary["total_matched_pairs"]])
        ws_sum.append(["Total Exceptions", summary["total_exceptions"]])
        ws_sum.append(["", ""])
        ws_sum.append(["Cashbook Total Credits (₹)", summary["cashbook_total_credits"]])
        ws_sum.append(["Cashbook Total Debits (₹)", summary["cashbook_total_debits"]])
        ws_sum.append(["Bank Total Deposits (₹)", summary["bank_total_deposits"]])
        ws_sum.append(["Bank Total Withdrawals (₹)", summary["bank_total_withdrawals"]])
        ws_sum.append(["", ""])
        ws_sum.append(["Matched by Pass:", ""])
        for k, v in summary["matched_by_pass"].items():
            ws_sum.append([f"  {k}", v])
        ws_sum.append(["", ""])
        ws_sum.append(["Exceptions by Category:", ""])
        for k, v in summary["exceptions_by_category"].items():
            ws_sum.append([f"  {k}", v])

        # Sheet 2: Matched
        ws_mat = wb.create_sheet(title="Matched")
        mat_headers = [
            "Match ID", "Match Pass", "Direction", "Amount (₹)",
            "Cashbook Date", "Cashbook Ref", "Cashbook Narration",
            "Bank Date", "Bank Ref", "Bank Narration", "Date Diff (Days)"
        ]
        ws_mat.append([sanitize_cell_formula_injection(h) for h in mat_headers])
        for m in matched:
            row = [
                m["match_id"],
                m["match_pass"],
                m["direction"],
                m["cashbook_amount"],
                m["cashbook_date"],
                m["reference"],
                redact_pii_string(m["cashbook_narration"]),
                m["bank_date"],
                m["reference"],
                redact_pii_string(m["bank_narration"]),
                m["date_diff_days"]
            ]
            ws_mat.append([sanitize_cell_formula_injection(c) for c in row])

        # Sheet 3: Exceptions
        ws_exc = wb.create_sheet(title="Exceptions")
        exc_headers = [
            "Exception ID", "Category", "Source Ledger", "Date", "Reference",
            "Narration", "Direction", "Amount (₹)", "Difference / Detail", "Transposed?"
        ]
        ws_exc.append([sanitize_cell_formula_injection(h) for h in exc_headers])
        for e in exceptions:
            amt = e.get("amount", e.get("cashbook_amount", ""))
            diff = e.get("amount_difference", e.get("notes", ""))
            trans = "YES" if e.get("is_transposed_digits") else "NO"
            row = [
                e["exception_id"],
                e["category"],
                e.get("source_ledger", ""),
                e.get("date", ""),
                e.get("reference", ""),
                redact_pii_string(e.get("narration", "")),
                e.get("direction", ""),
                amt,
                diff,
                trans
            ]
            ws_exc.append([sanitize_cell_formula_injection(c) for c in row])

        # Sheet 4: Assumptions
        ws_ass = wb.create_sheet(title="Assumptions")
        ws_ass.append(["Parameter", "Value"])
        ws_ass.append(["Engine Version", "1.0.0"])
        ws_ass.append(["Arithmetic Engine", "Pure Python Decimal (Deterministic)"])
        ws_ass.append(["Date Tolerance Window", f"{self.config.date_tolerance_days} days"])
        ws_ass.append(["Amount Exact Matching", "True"])
        ws_ass.append(["Opening Balance Source", self.config.opening_balance_source])
        ws_ass.append(["Formula Injection Sanitization", "Prefixing single quote on control characters"])

        wb.save(xlsx_path)

    @staticmethod
    def _file_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
