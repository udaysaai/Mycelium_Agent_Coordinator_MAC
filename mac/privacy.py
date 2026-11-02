"""
mac/privacy.py - PII Redaction & Privacy Guard for Financial Records
Provides deterministic PII masking for Aadhaar, bank accounts, phone numbers,
and OTPs in error logs, telemetry, and UI presentation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Union


class RedactionPolicy:
    """Configurable PII redaction policy rules."""
    MASK_AADHAAR: bool = True
    MASK_BANK_ACCOUNTS: bool = True
    MASK_PHONES: bool = True
    MASK_OTPS: bool = True


# Regex patterns for sensitive identifiers
# 1. OTP pattern
OTP_PATTERN = re.compile(
    r"(?i)\b(?:otp|one[- ]time[- ]password|verification[- ]code|code)(?:[\s:=]+|[\s]+is[\s:=]*)(\d{4,8})\b"
)

# 2. Aadhaar pattern: 12 digits, grouped in 4s or contiguous
AADHAAR_PATTERN = re.compile(
    r"\b([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})\b"
)

# 3. Indian Mobile numbers: 10 digits starting with 6, 7, 8, or 9
PHONE_PATTERN = re.compile(
    r"(?:\+91[ -]?)?\b([6-9]\d{5})(\d{4})\b"
)

# 4. Bank Account numbers: 11 to 18 digits (e.g. SBI, HDFC, Canara, Bank of Maharashtra)
BANK_ACCOUNT_PATTERN = re.compile(
    r"(?i)(?:a/c|ac|account|acc)?[\s.:#]*\b(\d{5,14})(\d{4})\b"
)


def redact_pii_string(text: str) -> str:
    """
    Deterministically redact sensitive PII tokens from string while preserving
    the last 4 digits where necessary for operational ledger auditability.
    Never retains or logs OTPs.
    """
    if not text or not isinstance(text, str):
        return text

    # Step 1: Redact OTPs completely
    redacted = OTP_PATTERN.sub(
        lambda m: m.group(0).replace(m.group(1), "[REDACTED_OTP]"),
        text
    )

    # Step 2: Redact Aadhaar numbers (keep last 4 digits)
    redacted = AADHAAR_PATTERN.sub(
        lambda m: f"XXXX-XXXX-{m.group(3)}",
        redacted
    )

    # Step 3: Redact Phone Numbers (keep last 4 digits)
    redacted = PHONE_PATTERN.sub(
        lambda m: f"XXXXXX{m.group(2)}",
        redacted
    )

    # Step 4: Redact Bank Account Numbers (longer than 10 digits to avoid date conflicts)
    def _mask_account(m: re.Match) -> str:
        full_digits = m.group(1) + m.group(2)
        # Avoid masking YYYYMMDD date strings or small numbers
        if len(full_digits) < 11 or len(full_digits) > 18:
            return m.group(0)
        prefix = "XXXX..."
        return m.group(0).replace(full_digits, f"{prefix}{m.group(2)}")

    redacted = BANK_ACCOUNT_PATTERN.sub(_mask_account, redacted)

    return redacted


def redact_pii_data(data: Union[Dict[str, Any], List[Any], str, Any]) -> Any:
    """
    Recursively redact PII from nested dictionaries, lists, and strings.
    """
    if isinstance(data, str):
        return redact_pii_string(data)
    elif isinstance(data, dict):
        return {k: redact_pii_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_pii_data(item) for item in data]
    return data
