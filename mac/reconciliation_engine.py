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

DEVANAGARI_DIGITS_MAP = str.maketrans("०१२३४५६७८९", "0123456789")


def normalize_devanagari_digits(val: Any) -> str:
    """Normalize Devanagari numerals ०-९ to ASCII 0-9."""
    if val is None:
        return ""
    s = unicodedata.normalize("NFC", str(val))
    return s.translate(DEVANAGARI_DIGITS_MAP)


def clean_date_string(val: Any) -> str:
    """Clean and normalize date string: Devanagari numerals to ASCII, multiple dots/slashes/hyphens to single separator."""
    if val is None:
        return ""
    s = normalize_devanagari_digits(val).strip()
    s = re.sub(r"\.{2,}", ".", s)
    s = re.sub(r"/{2,}", "/", s)
    s = re.sub(r"-{2,}", "-", s)
    return s

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

    text = normalize_devanagari_digits(val).strip()
    if not text:
        return Decimal("0.00")

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
    Normalizes Devanagari numerals and cleans repeated separator typos.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, date):
        return val

    s = clean_date_string(val)
    if not s:
        return None

    # Supported formats
    formats = [
        "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y",
        "%d/%m/%y", "%d-%m-%y", "%Y/%m/%d", "%d %b %Y", "%d %B %Y",
        "%d.%m.%y"
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
    text = normalize_devanagari_digits(ref_str).strip()
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
        self._ledger_metadata: Dict[str, Dict[str, Any]] = {}

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


    def get_ledger_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Retrieve extracted ledger metadata (opening/closing balance, subtotal mismatches)."""
        resolved = str(Path(file_path).resolve())
        if resolved not in self._ledger_metadata:
            self.load_ledger(file_path, "cashbook")
        return self._ledger_metadata.get(resolved, {"is_classified_gp_format": False})

    def _is_classified_gp_cashbook(self, raw_rows: List[List[Any]]) -> bool:
        """
        Auto-detect if a ledger file is a multi-section Maharashtra Gram Panchayat classified cashbook.
        """
        if raw_rows:
            head_str = " ".join(str(c or "") for c in raw_rows[0]).lower()
            if "withdrawal" in head_str or "deposit" in head_str:
                return False
        sample = raw_rows[:60]
        flat_text = " ".join(" ".join(str(c or "") for c in row) for row in sample)
        text_norm = unicodedata.normalize("NFC", flat_text).lower()

        has_summary = any(k in text_norm for k in [
            "सुरुवातीची शिल्लक", "आरंभीची शिल्लक", "अखेरची शिल्लक", "अखेर शिल्लक",
            "एकुण जमा", "एकूण जमा", "एकुण खर्च", "एकूण खर्च"
        ])
        has_voucher_header = (
            "पावती क्र" in text_norm or "प्रमाणक क्र" in text_norm or
            ("पावती" in text_norm and "प्रमाणक" in text_norm)
        )
        has_gp_terms = any(k in text_norm for k in [
            "ग्रामपंचायत", "ग्रामनिधी", "अनामत", "घरपट्टी", "शॉपिंग भाडे", "वेतन", "बॅक चार्जेस"
        ])

        return (has_summary and has_voucher_header) or (has_voucher_header and has_gp_terms)

    def _load_classified_gp_xlsx(
        self,
        classified_sheets: List[Tuple[str, Any, List[List[Any]]]],
        file_path: Path,
        source_name: str
    ) -> List[LedgerRow]:
        all_rows: List[LedgerRow] = []
        combined_mismatches: List[Dict[str, Any]] = []
        opening_balance: Optional[Decimal] = None
        closing_balance: Optional[Decimal] = None
        summary_total_credits: Optional[Decimal] = None
        summary_total_debits: Optional[Decimal] = None
        grand_total: Optional[Decimal] = None

        row_idx = 1

        for sheet_name, ws, raw_rows in classified_sheets:
            default_dir = "CREDIT" if "जमा" in sheet_name else ("DEBIT" if "खर्च" in sheet_name else "CREDIT")
            current_dir = default_dir
            current_section = ""
            current_section_rows: List[LedgerRow] = []
            last_valid_date: Optional[date] = None
            last_title = ""

            for r_idx, row in enumerate(raw_rows, start=1):
                if not any(row):
                    continue
                clean_cells = [unicodedata.normalize("NFC", str(c or "")).strip() for c in row]
                non_empty = [c for c in clean_cells if c]
                if not non_empty:
                    continue

                full_row_str = " ".join(clean_cells)

                # Summary rows
                if "सुरुवातीची शिल्लक" in full_row_str or "आरंभीची शिल्लक" in full_row_str:
                    for c in row:
                        if isinstance(c, (int, float, Decimal)):
                            opening_balance = Decimal(str(c)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                            break
                    if opening_balance is None and non_empty:
                        opening_balance = parse_indian_amount(non_empty[-1])
                    continue

                if ("एकुण जमा" in full_row_str or "एकूण जमा" in full_row_str) and summary_total_credits is None:
                    for c in row:
                        if isinstance(c, (int, float, Decimal)):
                            summary_total_credits = Decimal(str(c)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                            break
                    if summary_total_credits is None and non_empty:
                        summary_total_credits = parse_indian_amount(non_empty[-1])
                    continue

                if ("एकुण खर्च" in full_row_str or "एकूण खर्च" in full_row_str) and summary_total_debits is None:
                    for c in row:
                        if isinstance(c, (int, float, Decimal)):
                            summary_total_debits = Decimal(str(c)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                            break
                    if summary_total_debits is None and non_empty:
                        summary_total_debits = parse_indian_amount(non_empty[-1])
                    continue

                if "अखेरची शिल्लक" in full_row_str or "अखेर शिल्लक" in full_row_str:
                    for c in row:
                        if isinstance(c, (int, float, Decimal)):
                            closing_balance = Decimal(str(c)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                            break
                    if closing_balance is None and non_empty:
                        closing_balance = parse_indian_amount(non_empty[-1])
                    continue

                if "एकुण एकंदर" in full_row_str or "एकूण एकंदर" in full_row_str:
                    for c in row:
                        if isinstance(c, (int, float, Decimal)):
                            grand_total = Decimal(str(c)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                            break
                    if grand_total is None and non_empty:
                        grand_total = parse_indian_amount(non_empty[-1])
                    continue

                if any(kw in full_row_str.lower() for kw in ["income", "ग्रामपंचायत", "सन 2024-25"]) and len(non_empty) <= 2:
                    continue

                # Header rows
                c0 = clean_cells[0]
                if "पावती क्र" in c0:
                    current_dir = "CREDIT"
                    if last_title:
                        current_section = last_title
                    continue
                if "प्रमाणक क्र" in c0:
                    current_dir = "DEBIT"
                    if last_title:
                        current_section = last_title
                    continue

                # Section Title row
                if c0 and (len(clean_cells) <= 2 or not clean_cells[2]) and not isinstance(row[0], (int, float)):
                    if not any(kw in c0 for kw in ["पावती", "प्रमाणक", "सन", "ग्रामनिधी"]):
                        last_title = c0
                        current_section = c0
                        continue

                # Subtotal row
                v0 = row[0]
                v1 = row[1] if len(row) > 1 else None
                v2 = row[2] if len(row) > 2 else None
                v5 = row[5] if len(row) > 5 else None

                is_subtotal = False
                declared_sub = Decimal("0.00")

                if (v0 is None or clean_cells[0] == "") and (v1 is None or clean_cells[1] == ""):
                    if isinstance(v5, (int, float, Decimal)):
                        is_subtotal = True
                        declared_sub = Decimal(str(v5)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    elif isinstance(v2, (int, float, Decimal)):
                        is_subtotal = True
                        declared_sub = Decimal(str(v2)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    elif len(clean_cells) > 2 and clean_cells[2]:
                        try:
                            parsed_sub = parse_indian_amount(clean_cells[2])
                            if parsed_sub > Decimal("0.00"):
                                is_subtotal = True
                                declared_sub = parsed_sub
                        except Exception:
                            pass

                if is_subtotal:
                    calc_sum = sum((r.amount for r in current_section_rows), Decimal("0.00")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    declared_sub_q = declared_sub.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    if current_section_rows and calc_sum != declared_sub_q:
                        combined_mismatches.append({
                            "section": current_section or "Unknown Section",
                            "calculated_sum": calc_sum,
                            "declared_subtotal": declared_sub_q,
                            "difference": abs(calc_sum - declared_sub_q)
                        })
                    current_section_rows = []
                    last_valid_date = None
                    continue

                # Transactions
                amt = Decimal("0.00")
                if isinstance(v2, (int, float, Decimal)):
                    amt = Decimal(str(v2)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                elif len(clean_cells) > 2 and clean_cells[2]:
                    amt = parse_indian_amount(clean_cells[2])

                if amt != Decimal("0.00"):
                    raw_d = clean_cells[1]
                    p_date: Optional[date] = None
                    if isinstance(v1, (datetime, date)):
                        p_date = v1.date() if isinstance(v1, datetime) else v1
                        last_valid_date = p_date
                    elif raw_d:
                        p_date = parse_flexible_date(raw_d)
                        if p_date:
                            last_valid_date = p_date
                    elif last_valid_date:
                        p_date = last_valid_date

                    raw_ref = clean_cells[0]
                    norm_ref = normalize_reference(raw_ref)

                    narration_parts = [c for idx, c in enumerate(clean_cells) if idx not in (0, 1, 2) and c]
                    narration = " - ".join(narration_parts) if narration_parts else current_section

                    debit = amt if current_dir == "DEBIT" else Decimal("0.00")
                    credit = amt if current_dir == "CREDIT" else Decimal("0.00")
                    row_id = f"CB_{row_idx:04d}"

                    obj = LedgerRow(
                        row_id=row_id,
                        source="cashbook",
                        row_index=row_idx,
                        date=p_date,
                        raw_date_str=raw_d,
                        narration=narration,
                        reference=normalize_devanagari_digits(raw_ref),
                        normalized_ref=norm_ref,
                        debit=debit,
                        credit=credit,
                        amount=amt,
                        direction=current_dir,
                        balance=None,
                        raw_row={f"col_{i}": str(c) for i, c in enumerate(row)}
                    )
                    all_rows.append(obj)
                    current_section_rows.append(obj)
                    row_idx += 1

        resolved_path = str(Path(file_path).resolve())
        cb_cr_sum = sum((r.amount for r in all_rows if r.direction == "CREDIT"), Decimal("0.00"))
        cb_db_sum = sum((r.amount for r in all_rows if r.direction == "DEBIT"), Decimal("0.00"))
        calc_op = opening_balance if opening_balance is not None else Decimal("0.00")
        calc_cr = summary_total_credits if summary_total_credits is not None else cb_cr_sum
        calc_db = summary_total_debits if summary_total_debits is not None else cb_db_sum
        calc_gr = grand_total if grand_total is not None else (calc_op + calc_cr)
        calc_cl = closing_balance if closing_balance is not None else (calc_gr - calc_db)

        self._ledger_metadata[resolved_path] = {
            "is_classified_gp_format": True,
            "opening_balance": calc_op,
            "closing_balance": calc_cl,
            "summary_total_credits": calc_cr,
            "summary_total_debits": calc_db,
            "grand_total": calc_gr,
            "section_subtotal_mismatches": combined_mismatches
        }

        return all_rows

    def _load_classified_gp_cashbook(
        self,
        raw_rows: List[List[Any]],
        file_path: Path,
        source_name: str
    ) -> List[LedgerRow]:
        """
        Parse multi-section Maharashtra Gram Panchayat classified cashbook.
        Extracts CREDIT/DEBIT rows by section, handles continuation dates,
        ignores subtotal/summary lines as individual rows, and validates section subtotals.
        """
        ledger_rows: List[LedgerRow] = []
        current_section: str = ""
        current_direction: str = "CREDIT"
        last_valid_date: Optional[date] = None
        current_section_rows: List[LedgerRow] = []
        section_subtotal_mismatches: List[Dict[str, Any]] = []

        opening_balance: Optional[Decimal] = None
        closing_balance: Optional[Decimal] = None
        summary_total_credits: Optional[Decimal] = None
        summary_total_debits: Optional[Decimal] = None
        grand_total: Optional[Decimal] = None

        row_idx = 1

        for raw_cells in raw_rows:
            if not any(raw_cells):
                continue

            clean_cells = [unicodedata.normalize("NFC", str(c or "")).strip() for c in raw_cells]
            non_empty = [c for c in clean_cells if c]
            if not non_empty:
                continue

            full_row_str = " ".join(clean_cells)

            # 1. Summary Rows
            if "सुरुवातीची शिल्लक" in full_row_str or "आरंभीची शिल्लक" in full_row_str:
                opening_balance = parse_indian_amount(non_empty[-1])
                continue
            if "एकुण जमा" in full_row_str or "एकूण जमा" in full_row_str:
                summary_total_credits = parse_indian_amount(non_empty[-1])
                continue
            if "एकुण खर्च" in full_row_str or "एकूण खर्च" in full_row_str:
                summary_total_debits = parse_indian_amount(non_empty[-1])
                continue
            if "अखेरची शिल्लक" in full_row_str or "अखेर शिल्लक" in full_row_str:
                closing_balance = parse_indian_amount(non_empty[-1])
                continue
            if "एकुण एकंदर" in full_row_str or "एकूण एकंदर" in full_row_str:
                grand_total = parse_indian_amount(non_empty[-1])
                continue
            if "income" in full_row_str.lower() and len(non_empty) <= 2:
                continue
            if "ग्रामपंचायत" in full_row_str and "ग्रामनिधी" in full_row_str and len(non_empty) <= 2:
                continue

            # 2. Section Subtotal Rows (empty voucher and empty date)
            first_cell = clean_cells[0] if len(clean_cells) > 0 else ""
            second_cell = clean_cells[1] if len(clean_cells) > 1 else ""

            is_subtotal_row = False
            if not first_cell and not second_cell and len(non_empty) >= 1:
                is_subtotal_row = True
            elif any(k in full_row_str for k in ["एकूण", "एकुण", "subtotal", "टोटल"]) and (not first_cell or not second_cell):
                is_subtotal_row = True

            if is_subtotal_row:
                declared_subtotal = Decimal("0.00")
                if len(clean_cells) > 2 and clean_cells[2]:
                    declared_subtotal = parse_indian_amount(clean_cells[2])
                elif non_empty:
                    declared_subtotal = parse_indian_amount(non_empty[0])

                calc_sum = sum((r.amount for r in current_section_rows), Decimal("0.00"))
                if current_section_rows and calc_sum != declared_subtotal:
                    section_subtotal_mismatches.append({
                        "section": current_section or "Unknown Section",
                        "calculated_sum": calc_sum,
                        "declared_subtotal": declared_subtotal,
                        "difference": abs(calc_sum - declared_subtotal)
                    })

                current_section_rows = []
                last_valid_date = None
                continue

            # 3. Repeating Header Rows
            norm_first = normalize_devanagari_digits(first_cell).lower()
            if "पावती" in norm_first:
                current_direction = "CREDIT"
                continue
            if "प्रमाणक" in norm_first:
                current_direction = "DEBIT"
                continue

            # 4. Section Title Rows
            if len(non_empty) == 1:
                cand_title = non_empty[0]
                norm_cand = normalize_devanagari_digits(cand_title)
                if not parse_flexible_date(cand_title) and not re.search(r"^\d+$", norm_cand):
                    current_section = cand_title
                    if "जमा" in cand_title or any(k in cand_title for k in ["घरपट्टी", "शॉपिंग", "भाडे", "पाणीपट्टी", "दिवा", "इतर जमा", "अनुदान", "कर"]):
                        current_direction = "CREDIT"
                    elif "खर्च" in cand_title or any(k in cand_title for k in ["बॅक चार्जेस", "बँक", "वेतन", "पगार", "सादिल", "दुरुस्ती", "लाईट", "बक्षीस", "खरेदी", "काम"]):
                        current_direction = "DEBIT"
                    continue

            # 5. Transaction Rows
            raw_ref = first_cell
            norm_ref = normalize_reference(raw_ref)

            raw_date = second_cell
            parsed_d = None
            if raw_date:
                parsed_d = parse_flexible_date(raw_date)
                if parsed_d:
                    last_valid_date = parsed_d
            elif last_valid_date:
                # Continuation row: inherit last valid date in section
                parsed_d = last_valid_date
                raw_date = str(last_valid_date)

            row_amount = Decimal("0.00")
            amt_col_idx = 2
            if len(clean_cells) > 2 and clean_cells[2]:
                row_amount = parse_indian_amount(clean_cells[2])

            if row_amount == Decimal("0.00"):
                for idx, c in enumerate(clean_cells[3:], start=3):
                    candidate_amt = parse_indian_amount(c)
                    if candidate_amt > Decimal("0.00"):
                        row_amount = candidate_amt
                        amt_col_idx = idx
                        break

            if row_amount <= Decimal("0.00"):
                continue

            narration_parts = [c for idx, c in enumerate(clean_cells) if idx not in (0, 1, amt_col_idx) and c]
            narration = " - ".join(narration_parts) if narration_parts else (current_section or "")

            debit = row_amount if current_direction == "DEBIT" else Decimal("0.00")
            credit = row_amount if current_direction == "CREDIT" else Decimal("0.00")

            prefix = "CB" if source_name == "cashbook" else "BS"
            row_id = f"{prefix}_{row_idx:04d}"

            row_obj = LedgerRow(
                row_id=row_id,
                source=source_name,
                row_index=row_idx,
                date=parsed_d,
                raw_date_str=raw_date,
                narration=narration,
                reference=normalize_devanagari_digits(raw_ref),
                normalized_ref=norm_ref,
                debit=debit,
                credit=credit,
                amount=row_amount,
                direction=current_direction,
                balance=None,
                raw_row={f"col_{i}": str(c) for i, c in enumerate(raw_cells)}
            )

            ledger_rows.append(row_obj)
            current_section_rows.append(row_obj)
            row_idx += 1

        resolved_path = str(Path(file_path).resolve())
        self._ledger_metadata[resolved_path] = {
            "is_classified_gp_format": True,
            "opening_balance": opening_balance,
            "closing_balance": closing_balance,
            "summary_total_credits": summary_total_credits,
            "summary_total_debits": summary_total_debits,
            "grand_total": grand_total,
            "section_subtotal_mismatches": section_subtotal_mismatches
        }

        return ledger_rows

    def _load_csv(self, file_path: Path, source_name: str) -> List[LedgerRow]:
        rows: List[LedgerRow] = []
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as f:
            all_rows = list(csv.reader(f))

        if not all_rows:
            return []

        if source_name != "bank" and self._is_classified_gp_cashbook(all_rows):
            return self._load_classified_gp_cashbook(all_rows, file_path, source_name)

        header_row = None
        header_idx = -1
        for idx, row in enumerate(all_rows):
            if any(row):
                header_row = row
                header_idx = idx
                break
        if not header_row:
            return []

        mapping = self._detect_headers(header_row)
        row_idx = 1
        for raw_cells in all_rows[header_idx + 1:]:
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

        # Multi-sheet classified Gram Panchayat cashbook detection
        classified_sheets = []
        if source_name != "bank":
            for sname in wb.sheetnames:
                ws = wb[sname]
                sheet_rows = [[c for c in r] for r in ws.iter_rows(values_only=True)]
                if sheet_rows and self._is_classified_gp_cashbook([[str(c or '') for c in r] for r in sheet_rows]):
                    classified_sheets.append((sname, ws, sheet_rows))

        if classified_sheets:
            return self._load_classified_gp_xlsx(classified_sheets, file_path, source_name)

        sheet = wb.active
        raw_rows = [[str(c) if c is not None else "" for c in row] for row in sheet.iter_rows(values_only=True)]

        if not raw_rows:
            return []

        if self._is_classified_gp_cashbook(raw_rows):
            return self._load_classified_gp_cashbook(raw_rows, file_path, source_name)

        header_row = None
        header_idx = -1
        for idx, row in enumerate(raw_rows):
            if any(row):
                header_row = row
                header_idx = idx
                break
        if not header_row:
            return []

        mapping = self._detect_headers(header_row)
        row_idx = 1
        for raw_cells in raw_rows[header_idx + 1:]:
            if not any(raw_cells):
                continue
            row_obj = self._build_ledger_row(raw_cells, mapping, source_name, row_idx)
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
        cb_meta = self.get_ledger_metadata(cashbook_path)
        op_bal = cb_meta.get("opening_balance")
        cl_bal = cb_meta.get("closing_balance")
        st_credits = cb_meta.get("summary_total_credits")
        st_debits = cb_meta.get("summary_total_debits")
        gr_total = cb_meta.get("grand_total")

        cb_total_credits = sum(r.credit for r in cb_rows)
        cb_total_debits = sum(r.debit for r in cb_rows)
        bs_total_deposits = sum(r.credit for r in bs_rows)
        bs_total_withdrawals = sum(r.debit for r in bs_rows)

        summary = {
            "period_from": self.config.period_from,
            "period_to": self.config.period_to,
            "opening_balance": f"{op_bal:.2f}" if op_bal is not None else "0.00",
            "closing_balance": f"{cl_bal:.2f}" if cl_bal is not None else "0.00",
            "grand_total": f"{gr_total:.2f}" if gr_total is not None else "0.00",
            "cashbook_total_rows": len(cb_rows),
            "bank_total_rows": len(bs_rows),
            "cashbook_credit_rows": sum(1 for r in cb_rows if r.direction == "CREDIT"),
            "cashbook_debit_rows": sum(1 for r in cb_rows if r.direction == "DEBIT"),
            "total_matched_pairs": len(matched_records),
            "matched_count": len(matched_records),
            "total_exceptions": len(exceptions),
            "unmatched_cashbook_count": sum(1 for e in exceptions if e["category"] == "in_cashbook_only"),
            "unmatched_bank_count": sum(1 for e in exceptions if e["category"] == "in_bank_only"),
            "cashbook_total_credits": f"{cb_total_credits:.2f}",
            "cashbook_total_debits": f"{cb_total_debits:.2f}",
            "section_subtotal_debits": f"{st_debits:.2f}" if st_debits is not None else f"{cb_total_debits:.2f}",
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

        cb_meta = self.get_ledger_metadata(cashbook_path)
        mismatches = cb_meta.get("section_subtotal_mismatches", [])

        result = {
            "summary": summary,
            "matched": matched_records,
            "exceptions": exceptions,
            "metadata": {
                "is_classified_gp_format": cb_meta.get("is_classified_gp_format", False),
                "opening_balance": str(cb_meta.get("opening_balance") or ""),
                "closing_balance": str(cb_meta.get("closing_balance") or ""),
                "section_subtotal_mismatches": [
                    {
                        "section": m["section"],
                        "calculated_sum": str(m["calculated_sum"]),
                        "declared_subtotal": str(m["declared_subtotal"]),
                        "difference": str(m["difference"])
                    }
                    for m in mismatches
                ]
            }
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
        summary["section_subtotal_mismatches"] = cb_meta.get("section_subtotal_mismatches", [])
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

        mismatches = summary.get("section_subtotal_mismatches") or []
        if mismatches:
            ws_ass.append(["", ""])
            ws_ass.append(["Section Subtotal Mismatches Flagged", len(mismatches)])
            ws_ass.append(["Section Name", "Calculated Sum", "Declared Subtotal", "Difference"])
            for m in mismatches:
                ws_ass.append([
                    sanitize_cell_formula_injection(m["section"]),
                    str(m["calculated_sum"]),
                    str(m["declared_subtotal"]),
                    str(m["difference"])
                ])

        wb.save(xlsx_path)

    @staticmethod
    def _file_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
