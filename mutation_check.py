#!/usr/bin/env python3
"""
mutation_check.py - Deterministic Verifier Mutation Analysis
Deliberately introduces mutations into verifier.py to ensure the test suite
detects and kills every verifier bypass.

Usage:
    python mutation_check.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple

WORKSPACE_ROOT = Path(__file__).resolve().parent
VERIFIER_PATH = WORKSPACE_ROOT / "verifier.py"
MIRROR_VERIFIER_PATH = WORKSPACE_ROOT / "mycelium_desktop" / "python_core" / "verifier.py"


class Mutation(NamedTuple):
    id: str
    name: str
    description: str
    target: str
    replacement: str


MUTATIONS: List[Mutation] = [
    Mutation(
        id="MUT_01_ALWAYS_PASS",
        name="Always Return Pass",
        description="Forces verification receipt to unconditionally return verified=True",
        target="verified = (actual_hash == expected_hash)",
        replacement="verified = True"
    ),
    Mutation(
        id="MUT_02_SKIP_EXISTENCE",
        name="Skip File Existence Check",
        description="Bypasses physical file existence check on disk",
        target="if not exists:\n                receipt = VerificationReceipt(",
        replacement="if False:\n                receipt = VerificationReceipt("
    ),
    Mutation(
        id="MUT_03_SKIP_HASH_COMPARE",
        name="Skip Hash Comparison",
        description="Accepts file without verifying read-back SHA-256 hash match",
        target="verified = (actual_hash == expected_hash)",
        replacement="verified = True  # mutated: skip hash compare"
    ),
    Mutation(
        id="MUT_04_SKIP_SIZE_CHECK",
        name="Skip File Size / min_bytes Check",
        description="Bypasses minimum byte size threshold assertion",
        target="if actual_size < min_bytes:\n                receipt = VerificationReceipt(",
        replacement="if False:\n                receipt = VerificationReceipt("
    ),
    Mutation(
        id="MUT_05_SKIP_SHELL_EXIT_CHECK",
        name="Skip Shell Exit Code Verification",
        description="Marks shell execution verified even if exit code is non-zero",
        target="verified = (exit_code == 0)",
        replacement="verified = True  # mutated: ignore exit code"
    ),
    Mutation(
        id="MUT_06_BINARY_CRLF_LEAK",
        name="Bypass Binary Mode Newline Invariance",
        description="Allows CRLF normalization on binary payloads, masking corruption",
        target="is_bin = is_binary or target_file.suffix.lower() in self.BINARY_EXTENSIONS",
        replacement="is_bin = False  # mutated: treat binary as text"
    )
]


def run_test_suite() -> tuple[int, str]:
    """Run pytest suite against mutated verifier."""
    cmd = [
        sys.executable, "-m", "pytest", "-v",
        "test_phase0_vertical_slice.py",
        "test_phase0_adversarial.py"
    ]
    res = subprocess.run(
        cmd,
        cwd=WORKSPACE_ROOT,
        capture_output=True,
        text=True
    )
    return res.returncode, res.stdout + res.stderr


def main() -> int:
    print("=" * 80)
    print("MYCELIUM VERIFIER MUTATION TEST HARNESS")
    print("=" * 80)
    print(f"Target: {VERIFIER_PATH.name}")
    print(f"Total mutations defined: {len(MUTATIONS)}\n")

    original_code = VERIFIER_PATH.read_text(encoding="utf-8")
    mirror_original = MIRROR_VERIFIER_PATH.read_text(encoding="utf-8") if MIRROR_VERIFIER_PATH.exists() else None

    results = []
    survived_count = 0

    try:
        for mut in MUTATIONS:
            print(f"[*] Applying {mut.id}: {mut.name}...")
            print(f"    Description: {mut.description}")

            if mut.target not in original_code:
                print(f"    [ERROR] Mutation target not found in verifier.py: '{mut.target[:40]}...'")
                results.append((mut, "ERROR: Target not found", ""))
                survived_count += 1
                continue

            # Mutate
            mutated_code = original_code.replace(mut.target, mut.replacement, 1)
            VERIFIER_PATH.write_text(mutated_code, encoding="utf-8")
            if MIRROR_VERIFIER_PATH.exists():
                MIRROR_VERIFIER_PATH.write_text(mutated_code, encoding="utf-8")

            # Run tests
            code, output = run_test_suite()

            # Restore immediately
            VERIFIER_PATH.write_text(original_code, encoding="utf-8")
            if mirror_original and MIRROR_VERIFIER_PATH.exists():
                MIRROR_VERIFIER_PATH.write_text(mirror_original, encoding="utf-8")

            if code != 0:
                # Tests failed -> Mutation was caught and KILLED!
                # Extract first failing test name
                failed_tests = [line.strip() for line in output.splitlines() if "FAILED" in line]
                first_failed = failed_tests[0] if failed_tests else "Test suite failed"
                print(f"    -> [KILLED] Caught by: {first_failed}")
                results.append((mut, "KILLED", first_failed))
            else:
                # Tests passed -> Mutation SURVIVED! Vulnerability!
                print(f"    -> [SURVIVED] WARNING: Test suite did NOT catch this mutation!")
                results.append((mut, "SURVIVED", "None (All tests passed)"))
                survived_count += 1

            print("-" * 80)

    finally:
        # Guarantee clean restoration
        VERIFIER_PATH.write_text(original_code, encoding="utf-8")
        if mirror_original and MIRROR_VERIFIER_PATH.exists():
            MIRROR_VERIFIER_PATH.write_text(mirror_original, encoding="utf-8")

    # Final Summary Table
    print("\n" + "=" * 80)
    print("MUTATION TEST SUMMARY REPORT")
    print("=" * 80)
    print(f"{'ID':<12} | {'Mutation Name':<32} | {'Status':<10} | {'Caught By'}")
    print("-" * 80)
    for mut, status, killer in results:
        print(f"{mut.id:<12} | {mut.name:<32} | {status:<10} | {killer[:30]}")
    print("-" * 80)
    print(f"Total Mutations: {len(MUTATIONS)} | Killed: {len(MUTATIONS) - survived_count} | Survived: {survived_count}")

    if survived_count == 0:
        print("\n[SUCCESS] 100% of verifier mutations were KILLED. Verifier is robust!")
        return 0
    else:
        print(f"\n[FAILURE] {survived_count} mutation(s) survived! Add tests to kill them.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
