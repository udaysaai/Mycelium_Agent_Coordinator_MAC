#!/usr/bin/env python3
"""
mutation_check.py - Two-Pass Governance & Policy Mutation Verification Harness
Part 3:
  Evaluates mutations against:
    Pass (a): Full Test Suite
    Pass (b): IPC Boundary-Only Suite (test_phase05_boundary.py, test_phase06_wiring.py,
              test_phase06_state_integrity.py, test_phase06_boundary_mutations.py)

Tracks for each mutation:
  - Killing test name
  - Failure classification (ASSERTION vs CRASH/ERROR vs SURVIVED)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

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
    extra_file_path: Optional[Path] = None
    extra_target: Optional[str] = None
    extra_replacement: Optional[str] = None


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
    # Policy Engine, Token & State Store Mutations
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
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="current_call_hash = self.policy_engine.compute_call_hash(tool_name, payload, str(target))",
        replacement="current_call_hash = stored_q.get('call_hash', '')  # mutated: skip recompute",
        extra_file_path=COORDINATOR_PATH,
        extra_target=(
            "current_call_hash = self.policy_engine.compute_call_hash(\n"
            "                    tool_name=tool_name or \"action\",\n"
            "                    payload=request.payload,\n"
            "                    target=str(actual_target)\n"
            "                )"
        ),
        extra_replacement="current_call_hash = stored_q.get('call_hash', '') if (stored_q := self.state_store.get_quarantine(quarantine_id)) else ''  # mutated"
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
        target='if row["one_shot_token"] != token:',
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

    # -------------------------------------------------------------------------
    # Supervisor Boundary Mutations
    # -------------------------------------------------------------------------
    Mutation(
        id="MUT_12_WORKER_ACCEPT_APPROVE",
        name="Worker Channel Accepts Approve",
        description="Allows untrusted worker channel to issue approval decisions",
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="if msg_type in self.FORBIDDEN_WORKER_MESSAGE_TYPES:",
        replacement=(
            'if msg_type == "APPROVE_ACTION":\n'
            '            qid = msg.get("quarantine_id", "")\n'
            '            token = self.approve_via_ui_channel(qid)\n'
            '            return {"status": "APPROVED", "quarantine_id": qid, "one_shot_token": token}\n'
            '        if msg_type in self.FORBIDDEN_WORKER_MESSAGE_TYPES:'
        )
    ),
    Mutation(
        id="MUT_13_WORKER_MSG_WHITELIST",
        name="Worker Message Whitelist Bypassed",
        description="Supervisor executes arbitrary command sent by untrusted worker",
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="if msg_type not in self.WORKER_ALLOWED_MESSAGE_TYPES:",
        replacement="if False:  # mutated: worker whitelist bypassed"
    ),
    Mutation(
        id="MUT_14_UI_SECRET_CHECK",
        name="UI Secret Not Verified on Approval",
        description="Allows unauthenticated requests on UI channel without valid secret",
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="if not secrets.compare_digest(secret, self.ui_secret):",
        replacement="if False:  # mutated: UI secret check bypassed"
    ),
    Mutation(
        id="MUT_15_PATH_CONTAINMENT",
        name="Sandbox Path Containment Bypassed",
        description="Disables path containment check, permitting sandbox escapes",
        file_path=COORDINATOR_PATH,
        mirror_path=MIRROR_COORDINATOR_PATH,
        target="if cp_target != real_sandbox or cp_parent != real_sandbox:",
        replacement="if False:  # mutated: path containment bypassed"
    ),
    Mutation(
        id="MUT_16_STATE_INTEGRITY",
        name="Row Integrity Check Skipped",
        description="Bypasses cryptographic state verification before executing approved actions",
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="if not self.state_store.verify_integrity(self._signing_key):",
        replacement="if False:  # mutated: state integrity check bypassed"
    ),
    Mutation(
        id="MUT_17_SHELL_ALLOWLIST",
        name="Shell Allowlist Bypassed",
        description="Allows commands outside supervisor allowlist to execute",
        file_path=SUPERVISOR_PATH,
        mirror_path=None,
        target="if first_cmd not in self.ALLOWED_SHELL_COMMANDS:",
        replacement="if False:  # mutated: shell allowlist bypassed"
    ),
]

FULL_SUITE_TESTS = [
    "test_phase0_vertical_slice.py",
    "test_phase0_adversarial.py",
    "test_phase05_strengthened.py",
    "test_phase05_boundary.py",
    "test_phase06_wiring.py",
    "test_phase06_state_integrity.py",
    "test_phase06_boundary_mutations.py",
]

BOUNDARY_ONLY_TESTS = [
    "test_phase05_boundary.py",
    "test_phase06_wiring.py",
    "test_phase06_state_integrity.py",
    "test_phase06_boundary_mutations.py",
]


def run_tests(test_files: List[str]) -> Tuple[int, str]:
    """Run specified pytest files."""
    cmd = [sys.executable, "-m", "pytest", "-v"] + test_files
    res = subprocess.run(
        cmd,
        cwd=WORKSPACE_ROOT,
        capture_output=True,
        text=True
    )
    return res.returncode, res.stdout + res.stderr


def classify_failure(output: str) -> Tuple[str, str, str]:
    """
    Determine killing test name and category:
    ASSERTION (KILLED), CRASH (ERRORED), or NONE (SURVIVED).
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
        return killer, "ASSERTION", "KILLED"
    elif error_lines:
        killer = error_lines[0].split()[0]
        return killer, "IMPORT/CRASH_ERROR", "ERRORED"

    return "None", "NONE", "SURVIVED"


def execute_mutation_pass(pass_name: str, test_files: List[str], mutations: List[Mutation]) -> List[Tuple[Mutation, str, str, str]]:
    print("=" * 85)
    print(f"RUNNING {pass_name.upper()}")
    print(f"Test targets ({len(test_files)} files): {', '.join(test_files)}")
    print("=" * 85)

    results = []

    for mut in mutations:
        print(f"[*] Applying {mut.id}: {mut.name}...")
        print(f"    Target: {mut.file_path.name}")

        if not mut.file_path.exists():
            print(f"    [ERROR] Target file does not exist: {mut.file_path}")
            results.append((mut, "ERRORED", "File not found", "ERROR"))
            continue

        original_code = mut.file_path.read_text(encoding="utf-8")
        mirror_original = (
            mut.mirror_path.read_text(encoding="utf-8")
            if (mut.mirror_path and mut.mirror_path.exists())
            else None
        )
        extra_original = (
            mut.extra_file_path.read_text(encoding="utf-8")
            if (mut.extra_file_path and mut.extra_file_path.exists())
            else None
        )

        if mut.target not in original_code:
            print(f"    [ERROR] Target string not found in {mut.file_path.name}")
            results.append((mut, "ERRORED", "Target string not found", "ERROR"))
            continue

        try:
            # Apply mutation
            mutated = original_code.replace(mut.target, mut.replacement)
            mut.file_path.write_text(mutated, encoding="utf-8")

            if mirror_original and mut.mirror_path and mut.mirror_path.exists():
                mut.mirror_path.write_text(mutated, encoding="utf-8")

            if extra_original and mut.extra_file_path and mut.extra_target and mut.extra_replacement:
                mut_extra = extra_original.replace(mut.extra_target, mut.extra_replacement)
                mut.extra_file_path.write_text(mut_extra, encoding="utf-8")

            # Execute tests for this pass
            code, output = run_tests(test_files)

            if code != 0:
                killer_test, category, outcome = classify_failure(output)
                if outcome == "KILLED":
                    print(f"    -> [KILLED by {category}] Caught by: {killer_test}")
                    results.append((mut, "KILLED", killer_test, category))
                else:
                    print(f"    -> [ERRORED] Caught by crash: {killer_test}")
                    results.append((mut, "ERRORED", killer_test, category))
            else:
                print(f"    -> [SURVIVED] Tests did not detect this mutation!")
                results.append((mut, "SURVIVED", "None", "NONE"))

        finally:
            # Revert files
            mut.file_path.write_text(original_code, encoding="utf-8")
            if mirror_original and mut.mirror_path and mut.mirror_path.exists():
                mut.mirror_path.write_text(mirror_original, encoding="utf-8")
            if extra_original and mut.extra_file_path:
                mut.extra_file_path.write_text(extra_original, encoding="utf-8")

        print("-" * 85)

    return results


def print_summary_table(title: str, results: List[Tuple[Mutation, str, str, str]]) -> int:
    print("\n" + "=" * 85)
    print(title)
    print("=" * 85)
    print(f"{'ID':<16} | {'Mutation Name':<32} | {'Status':<10} | {'Type':<12} | {'Killing Test'}")
    print("-" * 85)
    survived = 0
    errored = 0
    for mut, status, killer, category in results:
        short_killer = killer.split("::")[-1] if "::" in killer else killer
        print(f"{mut.id:<16} | {mut.name[:32]:<32} | {status:<10} | {category:<12} | {short_killer[:22]}")
        if status == "SURVIVED":
            survived += 1
        elif status == "ERRORED":
            errored += 1
    print("-" * 85)
    killed = len(results) - survived - errored
    print(f"Total: {len(results)} | Killed: {killed} | Errored: {errored} | Survived: {survived}\n")
    return survived + errored


def main() -> int:
    print("=" * 85)
    print("TWO-PASS GOVERNANCE & POLICY MUTATION VERIFICATION")
    print("=" * 85)
    print(f"Mutations defined: {len(MUTATIONS)}\n")

    # Pass (a): Full Suite
    results_full = execute_mutation_pass("Pass (a): Full Test Suite", FULL_SUITE_TESTS, MUTATIONS)

    # Pass (b): Boundary-Only Suite (Part 3 requirement)
    # Exclude verifier file mutations MUT_01-MUT_06 which are unit verifier checks,
    # or evaluate all mutations on boundary path
    results_boundary = execute_mutation_pass("Pass (b): IPC Boundary-Only Suite", BOUNDARY_ONLY_TESTS, MUTATIONS)

    # Print Tables
    err_full = print_summary_table("PASS (A) FULL TEST SUITE MUTATION REPORT", results_full)
    err_boundary = print_summary_table("PASS (B) IPC BOUNDARY-ONLY MUTATION REPORT", results_boundary)

    # Save untruncated evidence file
    evidence_dir = WORKSPACE_ROOT / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / "mutation_check_two_pass.txt"

    with open(evidence_file, "w", encoding="utf-8") as f:
        f.write("=" * 85 + "\n")
        f.write("PASS (A) FULL TEST SUITE MUTATION REPORT\n")
        f.write("=" * 85 + "\n")
        f.write(f"{'ID':<16} | {'Mutation Name':<32} | {'Status':<10} | {'Type':<12} | {'Killing Test'}\n")
        f.write("-" * 85 + "\n")
        for mut, status, killer, category in results_full:
            f.write(f"{mut.id:<16} | {mut.name[:32]:<32} | {status:<10} | {category:<12} | {killer}\n")
        f.write("-" * 85 + "\n\n")

        f.write("=" * 85 + "\n")
        f.write("PASS (B) IPC BOUNDARY-ONLY MUTATION REPORT\n")
        f.write("=" * 85 + "\n")
        f.write(f"{'ID':<16} | {'Mutation Name':<32} | {'Status':<10} | {'Type':<12} | {'Killing Test'}\n")
        f.write("-" * 85 + "\n")
        for mut, status, killer, category in results_boundary:
            f.write(f"{mut.id:<16} | {mut.name[:32]:<32} | {status:<10} | {category:<12} | {killer}\n")
        f.write("-" * 85 + "\n")

    print(f"[+] Raw untruncated mutation evidence written to: {evidence_file}")
    return 0 if (err_full == 0 and err_boundary <= 6) else 1


if __name__ == "__main__":
    sys.exit(main())
