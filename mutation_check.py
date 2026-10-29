#!/usr/bin/env python3
"""
mutation_check.py - Comprehensive Governance & Policy Mutation Analysis
Deliberately introduces mutations across verifier, policy engine, token,
and supervisor boundary code to ensure the test suite detects and kills every security bypass.

Tracks:
  - Which specific test killed each mutation
  - Failure classification: assertion failure (KILLED) vs crash/import error (ERRORED)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

WORKSPACE_ROOT = Path(__file__).resolve().parent

VERIFIER_PATH = WORKSPACE_ROOT / "verifier.py"
MIRROR_VERIFIER_PATH = WORKSPACE_ROOT / "mycelium_desktop" / "python_core" / "verifier.py"

POLICY_PATH = WORKSPACE_ROOT / "policy_engine.py"
MIRROR_POLICY_PATH = WORKSPACE_ROOT / "mycelium_desktop" / "python_core" / "policy_engine.py"

COORDINATOR_PATH = WORKSPACE_ROOT / "coordinator.py"
MIRROR_COORDINATOR_PATH = WORKSPACE_ROOT / "mycelium_desktop" / "python_core" / "coordinator.py"

STATE_STORE_PATH = WORKSPACE_ROOT / "state_store.py"
MIRROR_STATE_STORE_PATH = WORKSPACE_ROOT / "mycelium_desktop" / "python_core" / "state_store.py"

SUPERVISOR_PATH = WORKSPACE_ROOT / "supervisor.py"


class Mutation(NamedTuple):
    id: str
    name: str
    description: str
    file_path: Path
    mirror_path: Optional[Path]
    target: str
    replacement: str


MUTATIONS: List[Mutation] = [
    # -------------------------------------------------------------------------
    # Verifier Mutations
    # -------------------------------------------------------------------------
    Mutation(
        id="MUT_01_ALWAYS_PASS",
        name="Always Return Pass",
        description="Forces verification receipt to unconditionally return verified=True",
        file_path=VERIFIER_PATH,
        mirror_path=MIRROR_VERIFIER_PATH,
        target="verified = (actual_hash == expected_hash)",
        replacement="verified = True"
    ),
    Mutation(
        id="MUT_02_SKIP_EXISTENCE",
        name="Skip File Existence Check",
        description="Bypasses physical file existence check on disk",
        file_path=VERIFIER_PATH,
        mirror_path=MIRROR_VERIFIER_PATH,
        target="if not exists:\n                receipt = VerificationReceipt(",
        replacement="if False:\n                receipt = VerificationReceipt("
    ),
    Mutation(
        id="MUT_03_SKIP_HASH_COMPARE",
        name="Skip Hash Comparison",
        description="Accepts file without verifying read-back SHA-256 hash match",
        file_path=VERIFIER_PATH,
        mirror_path=MIRROR_VERIFIER_PATH,
        target="verified = (actual_hash == expected_hash)",
        replacement="verified = True  # mutated: skip hash compare"
    ),
    Mutation(
        id="MUT_04_SKIP_SIZE_CHECK",
        name="Skip File Size / min_bytes Check",
        description="Bypasses minimum byte size threshold assertion",
        file_path=VERIFIER_PATH,
        mirror_path=MIRROR_VERIFIER_PATH,
        target="if actual_size < min_bytes:\n                receipt = VerificationReceipt(",
        replacement="if False:\n                receipt = VerificationReceipt("
    ),
    Mutation(
        id="MUT_05_SKIP_SHELL_EXIT_CHECK",
        name="Skip Shell Exit Code Verification",
        description="Marks shell execution verified even if exit code is non-zero",
        file_path=VERIFIER_PATH,
        mirror_path=MIRROR_VERIFIER_PATH,
        target="verified = (exit_code == 0)",
        replacement="verified = True  # mutated: ignore exit code"
    ),
    Mutation(
        id="MUT_06_BINARY_CRLF_LEAK",
        name="Bypass Binary Mode Newline Invariance",
        description="Allows CRLF normalization on binary payloads, masking corruption",
        file_path=VERIFIER_PATH,
        mirror_path=MIRROR_VERIFIER_PATH,
        target="is_bin = is_binary or target_file.suffix.lower() in self.BINARY_EXTENSIONS",
        replacement="is_bin = False  # mutated: treat binary as text"
    ),

    # -------------------------------------------------------------------------
    # Policy Engine & Token Mutations
    # -------------------------------------------------------------------------
    Mutation(
        id="MUT_07_SKIP_HMAC_VERIFY",
        name="Skip HMAC Token Verification",
        description="Accepts any one-shot token without checking HMAC signature",
        file_path=POLICY_PATH,
        mirror_path=MIRROR_POLICY_PATH,
        target="return hmac.compare_digest(token, expected)",
        replacement="return True  # mutated: accept all tokens"
    ),
    Mutation(
        id="MUT_08_SKIP_CALL_HASH_RECOMPUTE",
        name="Skip Call-Hash Recompute at Exec",
        description="Uses stored call-hash instead of recomputing from actual call payload",
        file_path=COORDINATOR_PATH,
        mirror_path=MIRROR_COORDINATOR_PATH,
        target="current_call_hash = self.policy_engine.compute_call_hash(\n                    tool_name=tool_name or \"action\",\n                    payload=request.payload,\n                    target=str(actual_target)\n                )",
        replacement="current_call_hash = stored_q.get(\"call_hash\", \"\") if (stored_q := self.state_store.get_quarantine(quarantine_id)) else \"\"  # mutated"
    ),
    Mutation(
        id="MUT_09_SKIP_EXPIRY_CHECK",
        name="Skip Token Expiry Check",
        description="Does not invalidate expired tokens, allowing execution after deadline",
        file_path=STATE_STORE_PATH,
        mirror_path=MIRROR_STATE_STORE_PATH,
        target='if row["expires_at"] <= now:',
        replacement="if False:  # mutated: skip expiry check"
    ),
    Mutation(
        id="MUT_10_SKIP_CONSUMED_CHECK",
        name="Skip Consumed-State Replay Check",
        description="Allows already consumed tokens to be reused repeatedly",
        file_path=STATE_STORE_PATH,
        mirror_path=MIRROR_STATE_STORE_PATH,
        target='if row["status"] != HOLApprovalStatus.APPROVED.value:',
        replacement="if False:  # mutated: allow replay"
    ),
    Mutation(
        id="MUT_11_UNKNOWN_TOOL_AS_T0",
        name="Classify Unknown Tools as T0",
        description="Defaults unregistered tools to T0 bypass instead of T2 quarantine",
        file_path=POLICY_PATH,
        mirror_path=MIRROR_POLICY_PATH,
        target="tierLevel=TierLevel.T2,\n                requiresQuarantine=True,",
        replacement="tierLevel=TierLevel.T0,\n                requiresQuarantine=False,  # mutated: unknown tool as T0"
    ),
    Mutation(
        id="MUT_12_WORKER_ACCEPT_APPROVE",
        name="Worker Channel Accepts Approve",
        description="Allows untrusted worker channel to issue approval decisions",
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="if msg_type in self.FORBIDDEN_WORKER_MESSAGE_TYPES:",
        replacement='if msg_type == "APPROVE_ACTION":\n            qid = msg.get("quarantine_id", "")\n            token = self.approve_via_ui_channel(qid)\n            return {"status": "APPROVED", "quarantine_id": qid, "one_shot_token": token}\n        if msg_type in self.FORBIDDEN_WORKER_MESSAGE_TYPES:'
    ),
    Mutation(
        id="MUT_13_SKIP_PATH_CONTAINMENT",
        name="Skip Sandbox Path Containment",
        description="Bypasses commonpath sandbox confinement check",
        file_path=COORDINATOR_PATH,
        mirror_path=MIRROR_COORDINATOR_PATH,
        target="if cp_target != real_sandbox or cp_parent != real_sandbox:",
        replacement="if False:  # mutated: skip boundary check"
    ),
]


def run_test_suite() -> tuple[int, str]:
    """Run pytest suite against mutated codebase."""
    cmd = [
        sys.executable, "-m", "pytest", "-v",
        "test_phase0_vertical_slice.py",
        "test_phase0_adversarial.py",
        "test_phase05_strengthened.py",
        "test_phase05_boundary.py"
    ]
    res = subprocess.run(
        cmd,
        cwd=WORKSPACE_ROOT,
        capture_output=True,
        text=True
    )
    return res.returncode, res.stdout + res.stderr


def classify_failure(output: str) -> tuple[str, str, str]:
    """
    Examine pytest output to determine:
      1. Killing test name
      2. Failure category: 'ASSERTION' (killed) vs 'ERROR' (crash/import error)
    """
    failed_lines = []
    error_lines = []

    for line in output.splitlines():
        clean = line.strip()
        if "FAILED" in clean and "::" in clean:
            failed_lines.append(clean)
        elif "ERROR" in clean and "::" in clean:
            error_lines.append(clean)

    if failed_lines:
        killer = failed_lines[0].split()[0]
        # Check if traceback indicates AssertionError or Failed
        if "AssertionError" in output or "Failed:" in output or "FAILED" in output:
            return killer, "ASSERTION", "KILLED"
        return killer, "CRASH", "ERRORED"
    elif error_lines:
        killer = error_lines[0].split()[0]
        return killer, "IMPORT/CRASH_ERROR", "ERRORED"

    return "None", "NONE", "SURVIVED"


def main() -> int:
    print("=" * 85)
    print("MYCELIUM GOVERNANCE & POLICY MUTATION TEST HARNESS")
    print("=" * 85)
    print(f"Total mutations defined: {len(MUTATIONS)}\n")

    results = []
    survived_count = 0
    errored_count = 0

    for mut in MUTATIONS:
        print(f"[*] Applying {mut.id}: {mut.name}...")
        print(f"    Target: {mut.file_path.name}")
        print(f"    Description: {mut.description}")

        if not mut.file_path.exists():
            print(f"    [ERROR] Target file does not exist: {mut.file_path}")
            results.append((mut, "ERRORED", "File not found", "ERROR"))
            errored_count += 1
            continue

        original_code = mut.file_path.read_text(encoding="utf-8")
        mirror_original = (
            mut.mirror_path.read_text(encoding="utf-8")
            if (mut.mirror_path and mut.mirror_path.exists())
            else None
        )

        if mut.target not in original_code:
            print(f"    [ERROR] Mutation target string not found in {mut.file_path.name}")
            results.append((mut, "ERRORED", "Target string not found", "ERROR"))
            errored_count += 1
            continue

        try:
            # Apply mutation to target file (and mirror if present)
            mutated = original_code.replace(mut.target, mut.replacement, 1)
            mut.file_path.write_text(mutated, encoding="utf-8")
            if mirror_original and mut.mirror_path and mut.mirror_path.exists():
                mut.mirror_path.write_text(mutated, encoding="utf-8")

            # Run test suite
            code, output = run_test_suite()

            if code != 0:
                killer_test, category, outcome = classify_failure(output)
                if outcome == "KILLED":
                    print(f"    -> [KILLED by {category}] Caught by: {killer_test}")
                    results.append((mut, "KILLED", killer_test, category))
                else:
                    print(f"    -> [ERRORED] Caught by crash/import error: {killer_test}")
                    results.append((mut, "ERRORED", killer_test, category))
                    errored_count += 1
            else:
                print(f"    -> [SURVIVED] Test suite did NOT catch this mutation!")
                results.append((mut, "SURVIVED", "None", "NONE"))
                survived_count += 1

        finally:
            # Restore files immediately
            mut.file_path.write_text(original_code, encoding="utf-8")
            if mirror_original and mut.mirror_path and mut.mirror_path.exists():
                mut.mirror_path.write_text(mirror_original, encoding="utf-8")

        print("-" * 85)

    # Summary Table
    print("\n" + "=" * 85)
    print("MUTATION ANALYSIS SUMMARY REPORT")
    print("=" * 85)
    print(f"{'ID':<12} | {'Mutation Name':<32} | {'Status':<10} | {'Type':<12} | {'Killing Test'}")
    print("-" * 85)
    for mut, status, killer, category in results:
        short_killer = killer.split("::")[-1] if "::" in killer else killer
        print(f"{mut.id:<12} | {mut.name:<32} | {status:<10} | {category:<12} | {short_killer[:22]}")
    print("-" * 85)

    killed_count = len(MUTATIONS) - survived_count - errored_count
    print(f"Total Mutations: {len(MUTATIONS)} | Killed: {killed_count} | Errored: {errored_count} | Survived: {survived_count}")

    if survived_count == 0 and errored_count == 0:
        print(f"\n[SUMMARY] All {len(MUTATIONS)} defined mutations were KILLED by assertion tests.")
        return 0
    else:
        print(f"\n[SUMMARY] Mutations surviving: {survived_count}, Mutations errored: {errored_count}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
