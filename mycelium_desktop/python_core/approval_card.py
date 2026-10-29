"""
approval_card.py - Phase 0.6 Human-On-The-Loop Approval Card Integrity Inspector
Inspects tool execution payloads to ensure exact literals are presented to the operator,
detects embedded newlines, control characters, confusables/homoglyphs, and oversized payloads.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional

CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\x1b\[[0-9;]*[a-zA-Z]")
NEWLINE_REGEX = re.compile(r"[\r\n]")


def inspect_approval_payload(
    tool_name: str,
    payload: Dict[str, Any],
    tier: str = "T2",
    call_hash: str = "",
    target_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Constructs an untruncated, flagged approval card payload for the operator UI.
    Analyzes content for prompt injection, hidden commands, and confusables.
    """
    command_str = ""
    target = target_path or ""

    if "command" in payload:
        command_str = str(payload["command"])
        target = target or command_str
    elif "file_path" in payload:
        target = target or str(payload["file_path"])
        command_str = f"write_file '{target}': {payload.get('content', '')}"
    else:
        command_str = str(payload)
        target = target or tool_name

    # 1. Exact string preservation (never truncated)
    exact_command = command_str

    # 2. Anomaly Checks
    has_newlines = bool(NEWLINE_REGEX.search(exact_command))
    has_control_chars = bool(CONTROL_CHAR_REGEX.search(exact_command))

    # Confusables / Non-ASCII check
    has_non_ascii = any(ord(c) > 127 for c in exact_command)
    has_invisible_or_override = any(
        unicodedata.category(c) in ("Cf", "Cs", "Co", "Cn") or ord(c) in (0x200B, 0x200C, 0x200D, 0x202E, 0x202D, 0x2066, 0x2067, 0x2068)
        for c in exact_command
    )
    has_confusables = has_non_ascii or has_invisible_or_override

    # Length check
    is_very_long = len(exact_command) > 1000

    warnings: List[str] = []
    if has_newlines:
        warnings.append("WARNING: Command contains embedded newline characters (potential multi-command injection).")
    if has_control_chars:
        warnings.append("WARNING: Command contains non-printable control characters or ANSI terminal escape codes.")
    if has_confusables:
        warnings.append("WARNING: Command contains non-ASCII characters, homoglyphs, or invisible directional override formatting.")
    if is_very_long:
        warnings.append(f"WARNING: Payload is very long ({len(exact_command)} characters). Review full text carefully.")

    short_hash = call_hash[:12] if len(call_hash) >= 12 else call_hash

    return {
        "tool_name": tool_name,
        "target": target,
        "tier": tier,
        "call_hash": call_hash,
        "short_hash": short_hash,
        "exact_command": exact_command,
        "payload": payload,
        "flags": {
            "has_newlines": has_newlines,
            "has_control_chars": has_control_chars,
            "has_non_ascii_or_confusables": has_confusables,
            "is_very_long": is_very_long
        },
        "warning_messages": warnings
    }
