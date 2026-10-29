# Phase 0 Adversarial Hardening & Verification Report

**Repository**: Mycelium Agent Coordinator (MAC)  
**Evaluator**: US Neural Security Reviewer & Implementer  
**Audit Baseline**: Phase 0 Initial Commit `8e6de60`  
**Current Hardened Commit**: `6397a4f`  
**Evaluation Date**: 2026-10-29  
**Status**: COMPLETE (All 35 tests passing, 6/6 mutations killed, 40/40 replay benchmarks verified)

---

## 1. Executive Summary

Phase 0 introduced the foundational governance layer (Intake Gate, Policy Engine, HOL Quarantine Guard, Deterministic Verifier, and SQLite WAL State Store). An adversarial audit against commit `8e6de60` revealed critical vulnerabilities:
1. Pre-existing test `test_mac.py` assertion had been loosened in commit `8e6de60`.
2. One-shot tokens were plain unauthenticated random hex, vulnerable to forgery and replay.
3. Call arguments and file targets were not re-validated against the approval token at execution time (argument tampering vector).
4. Quarantine timeouts did not fail closed under process restarts or injectable clock advancement.
5. Path traversal checks allowed UNC paths, Windows drive letters, and symlink escapes outside the sandbox.
6. The out-of-band verifier normalized CRLF/LF unconditionally, masking real data corruption in binary payloads.
7. `TaskContract` was mutable post-creation, allowing state tampering.

All vulnerabilities were weaponized into spec-driven adversarial tests in `test_phase0_adversarial.py`, patched with granular commits, verified via a mutation analysis harness (`mutation_check.py`), and stress-tested with an automated N=20 end-to-end replay harness (`eval_replay.py`).

---

## 2. Test Integrity Audit (`test_mac.py`)

### What Changed in Commit `8e6de60`
Running `git diff 8e6de60~1 8e6de60 -- test_mac.py` revealed:

```diff
diff --git a/test_mac.py b/test_mac.py
index 716c3b0..aec2215 100644
--- a/test_mac.py
+++ b/test_mac.py
@@ -125,7 +125,7 @@ def test_daemon_execute_command_timeout(daemon: LocalExecDaemon):
     )
     assert res.success is False
     assert res.exitCode == -1
-    assert "exceeded maximum allowed timeout" in res.stderr.lower() or "timeout" in res.stderr.lower()
+    assert "timeout" in res.stderr.lower() or "timed out" in res.stderr.lower()
```

### Assessment & Restoration
- **Impact**: The assertion was weakened to permit `"timed out"` from a non-conforming daemon implementation.
- **Action Taken**: In commit `ca5cc3b`, `test_mac.py` was restored to its exact pre-Phase 0 state (`8e6de60~1`). The underlying daemon `local_daemon.py` was fixed to emit `"Execution exceeded maximum allowed timeout..."`, satisfying the original strict assertion.
- **Verification**: `git diff 8e6de60~1 HEAD -- test_mac.py` produces **zero diff**.

---

## 3. Vulnerability Findings & Fixes Matrix

| ID | Finding | Severity | Status | Evidence (Commit Hash & Test Name) |
| :--- | :--- | :--- | :--- | :--- |
| **FIND-01** | Weakened timeout assertion in `test_mac.py` | Medium | **FIXED** | Commit `ca5cc3b`<br>`test_mac.py::test_daemon_execute_command_timeout` |
| **FIND-02** | Token forgery: Tokens were plain random hex without cryptographic binding | Critical | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_03_token_authenticity_hmac` |
| **FIND-03** | Argument tampering: Benign approval token reused to execute tampered payload | Critical | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_02_argument_tampering_detected` |
| **FIND-04** | Token replay: Consumed tokens could be re-submitted | High | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_01_token_replay_rejected` |
| **FIND-05** | Timeout fail-open: Quarantined actions past expiry did not resolve to default-deny | High | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_04_timeout_default_deny_with_clock` |
| **FIND-06** | Crash durability: Pending state must survive process restarts in SQLite WAL | High | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_05_crash_durability_pending_survives` |
| **FIND-07** | Path traversal & symlink breakout via UNC paths (`//`), drive letters (`C:`), `..`, and junctions | Critical | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_06_path_traversal_and_symlinks` |
| **FIND-08** | Approval channel isolation: Agent payload could inject approval flags | Critical | **FIXED** | Commit `131bc13`<br>`test_phase0_adversarial.py::test_adv_08_approval_channel_isolation` |
| **FIND-09** | Mutable `TaskContract`: Agent could mutate contract constraints post-creation | High | **FIXED** | Commit `24565f9`<br>`test_phase0_adversarial.py::test_adv_12_task_contract_immutability` |
| **FIND-10** | Intake slot bypass: Vague prompts ("save report") did not trigger missing-slot prompt | Medium | **FIXED** | Commit `24565f9`<br>`test_phase0_adversarial.py::test_adv_11_intake_vague_prompts_request_missing_slots` |
| **FIND-11** | Verifier binary mode leak: CRLF normalization masked real byte corruption in binary files | High | **FIXED** | Commit `51fe0a7`<br>`test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases` |
| **FIND-12** | Agent self-report: Unverified tasks could end as COMPLETED without receipt | High | **FIXED** | Commit `51fe0a7`<br>`test_phase0_adversarial.py::test_adv_10_agent_self_report_unverified_task_fails` |
| **FIND-13** | Unsupported marketing claims in documentation, UI, and code comments | Low | **FIXED** | Commit `6397a4f`<br>Diff in `README.md`, `demo_runner.py`, `mcp_gateway.py`, `renderer/index.html` |

---

## 4. Trust Boundary Architecture

### Current Phase 0 Architecture
Currently, `MyceliumCoordinator`, `PolicyEngine`, `StateStore`, `DeterministicVerifier`, and the LLM agent caller execute in the **same host Python process**. While `LocalExecDaemon` spawns real isolated OS subprocesses for shell commands (`execute_command`), in-process tool executions (such as `sandboxed_file_writer`) share memory space with the coordinator.

```
+-------------------------------------------------------------------------+
| Single Host Python Process                                              |
|  +-------------------------+  +---------------------------------------+ |
|  | Untrusted Agent Context |  | Supervisor Domain                     | |
|  | - LLM Prompt & Reasoning|  | - StateStore (SQLite WAL)              | |
|  | - ActionRequest Creator |  | - PolicyEngine (HMAC Key File 0o600)  | |
|  |                         |  | - HOL Guard Quarantine Queue          | |
|  |                         |  | - Deterministic Verifier              | |
|  +-------------------------+  +---------------------------------------+ |
+-------------------------------------------------------------------------+
                                    |
                                    v (Process Boundary)
                   +----------------------------------+
                   | Isolated OS Subprocess (Shell)   |
                   +----------------------------------+
```

### Proposed Minimal Process Split (Phase 1 Migration)
To achieve true zero-trust containment, the architecture will be partitioned into two distinct OS processes communicating over an authenticated local IPC channel (Unix Domain Socket / Windows Named Pipe):

1. **Supervisor Process (Privileged)**:
   - Owns the SQLite WAL database (`data/mac_state.db`).
   - Owns the HMAC master signing key (`~/.mycelium/mac_signing.key`, `0o600`).
   - Owns the HOL approval queue and the isolated UI/Human confirmation IPC interface.
   - Executes the Deterministic Out-of-Band Verifier.
2. **Untrusted Worker Process (Unprivileged)**:
   - Runs LLM API calls, prompt chains, and agent reasoning loops.
   - Possesses zero database handles, zero cryptographic keys, and zero filesystem write permissions.
   - Submits raw `ActionRequest` envelopes to the supervisor process via pipe/socket.
   - Waits for supervisor authorization and execution receipts.

---

## 5. Raw Evidence & Command Outputs

### A. Full Test Suite (`pytest -v`)
Command: `pytest -v test_mac.py test_phase0_vertical_slice.py test_phase0_adversarial.py`

```text
============================= test session starts =============================
platform win32 -- Python 3.12.4, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\Uday\AppData\Local\Programs\Python\Python312\python.exe
cachedir: .pytest_cache
rootdir: D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC)
plugins: anyio-4.13.0, langsmith-0.10.15
collecting ... collected 35 items

test_mac.py::test_protocol_privilege_and_safety_enums PASSED             [  2%]
test_mac.py::test_action_request_defaults PASSED                         [  5%]
test_mac.py::test_execution_result_contract PASSED                       [  8%]
test_mac.py::test_daemon_file_write_and_read PASSED                      [ 11%]
test_mac.py::test_daemon_sandbox_escape_prevention PASSED                [ 14%]
test_mac.py::test_daemon_file_not_found PASSED                           [ 17%]
test_mac.py::test_daemon_execute_command_success PASSED                  [ 20%]
test_mac.py::test_daemon_execute_command_timeout PASSED                  [ 22%]
test_mac.py::test_mcp_gateway_semantic_vector_discovery PASSED           [ 25%]
test_mac.py::test_mcp_gateway_argument_validation PASSED                 [ 28%]
test_mac.py::test_coordinator_read_only_fast_path PASSED                 [ 31%]
test_mac.py::test_coordinator_hol_guard_approval PASSED                  [ 34%]
test_mac.py::test_coordinator_hol_guard_rejection PASSED                 [ 37%]
test_phase0_vertical_slice.py::test_intake_greeting_no_404 PASSED        [ 40%]
test_phase0_vertical_slice.py::test_intake_slot_filling_for_vague_request PASSED [ 42%]
test_phase0_vertical_slice.py::test_intake_compiles_task_contract PASSED [ 45%]
test_phase0_vertical_slice.py::test_t0_read_bypasses_quarantine PASSED   [ 48%]
test_phase0_vertical_slice.py::test_t1_sandboxed_atomic_writer PASSED    [ 51%]
test_phase0_vertical_slice.py::test_t2_quarantine_rejection_blocks_execution PASSED [ 54%]
test_phase0_vertical_slice.py::test_t2_quarantine_approval_with_token PASSED [ 57%]
test_phase0_vertical_slice.py::test_t2_token_replay_blocked PASSED       [ 60%]
test_phase0_vertical_slice.py::test_verifier_catches_tampered_or_missing_file PASSED [ 62%]
test_phase0_vertical_slice.py::test_sqlite_wal_persistence_across_restart PASSED [ 65%]
test_phase0_adversarial.py::test_adv_01_token_replay_rejected PASSED     [ 68%]
test_phase0_adversarial.py::test_adv_02_argument_tampering_detected PASSED [ 71%]
test_phase0_adversarial.py::test_adv_03_token_authenticity_hmac PASSED   [ 74%]
test_phase0_adversarial.py::test_adv_04_timeout_default_deny_with_clock PASSED [ 77%]
test_phase0_adversarial.py::test_adv_05_crash_durability_pending_survives PASSED [ 80%]
test_phase0_adversarial.py::test_adv_06_path_traversal_and_symlinks PASSED [ 82%]
test_phase0_adversarial.py::test_adv_07_tier_classification_and_capability_grants PASSED [ 85%]
test_phase0_adversarial.py::test_adv_08_approval_channel_isolation PASSED [ 88%]
test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases PASSED     [ 91%]
test_phase0_adversarial.py::test_adv_10_agent_self_report_unverified_task_fails PASSED [ 94%]
test_phase0_adversarial.py::test_adv_11_intake_vague_prompts_request_missing_slots PASSED [ 97%]
test_phase0_adversarial.py::test_adv_12_task_contract_immutability PASSED [100%]

============================= 35 passed in 2.34s ==============================
```

---

### B. Verifier Mutation Check (`mutation_check.py`)
Command: `python mutation_check.py`

```text
================================================================================
MYCELIUM VERIFIER MUTATION TEST HARNESS
================================================================================
Target: verifier.py
Total mutations defined: 6

[*] Applying MUT_01_ALWAYS_PASS: Always Return Pass...
    Description: Forces verification receipt to unconditionally return verified=True
    -> [KILLED] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases FAILED     [ 86%]
--------------------------------------------------------------------------------
[*] Applying MUT_02_SKIP_EXISTENCE: Skip File Existence Check...
    Description: Bypasses physical file existence check on disk
    -> [KILLED] Caught by: test_phase0_vertical_slice.py::test_verifier_catches_tampered_or_missing_file FAILED [ 40%]
--------------------------------------------------------------------------------
[*] Applying MUT_03_SKIP_HASH_COMPARE: Skip Hash Comparison...
    Description: Accepts file without verifying read-back SHA-256 hash match
    -> [KILLED] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases FAILED     [ 86%]
--------------------------------------------------------------------------------
[*] Applying MUT_04_SKIP_SIZE_CHECK: Skip File Size / min_bytes Check...
    Description: Bypasses minimum byte size threshold assertion
    -> [KILLED] Caught by: test_phase0_vertical_slice.py::test_verifier_catches_tampered_or_missing_file FAILED [ 40%]
--------------------------------------------------------------------------------
[*] Applying MUT_05_SKIP_SHELL_EXIT_CHECK: Skip Shell Exit Code Verification...
    Description: Marks shell execution verified even if exit code is non-zero
    -> [KILLED] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases FAILED     [ 86%]
--------------------------------------------------------------------------------
[*] Applying MUT_06_BINARY_CRLF_LEAK: Bypass Binary Mode Newline Invariance...
    Description: Allows CRLF normalization on binary payloads, masking corruption
    -> [KILLED] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases FAILED     [ 86%]
--------------------------------------------------------------------------------

================================================================================
MUTATION TEST SUMMARY REPORT
================================================================================
ID           | Mutation Name                    | Status     | Caught By
--------------------------------------------------------------------------------
MUT_01_ALWAYS_PASS | Always Return Pass               | KILLED     | test_phase0_adversarial.py::te
MUT_02_SKIP_EXISTENCE | Skip File Existence Check        | KILLED     | test_phase0_vertical_slice.py:
MUT_03_SKIP_HASH_COMPARE | Skip Hash Comparison             | KILLED     | test_phase0_adversarial.py::te
MUT_04_SKIP_SIZE_CHECK | Skip File Size / min_bytes Check | KILLED     | test_phase0_vertical_slice.py:
MUT_05_SKIP_SHELL_EXIT_CHECK | Skip Shell Exit Code Verification | KILLED     | test_phase0_adversarial.py::te
MUT_06_BINARY_CRLF_LEAK | Bypass Binary Mode Newline Invariance | KILLED     | test_phase0_adversarial.py::te
--------------------------------------------------------------------------------
Total Mutations: 6 | Killed: 6 | Survived: 0

[SUCCESS] 100% of verifier mutations were KILLED. Verifier is robust!
```

---

### C. Reliability Replay & Latency Benchmark (`eval_replay.py`)
Command: `python eval_replay.py --iterations 20`

```text
================================================================================
MYCELIUM PHASE 0 REPLAY & RELIABILITY EVAL HARNESS (N=20)
================================================================================
Output File: D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC)\eval_results\phase0_replay.json

[*] Running Workflow 1: T1 Sandboxed File Write (Intake -> Actuator -> Verifier) x 20...
.................... Done.
[*] Running Workflow 2: T2 HOL Quarantine (Intake -> Quarantine -> UI Hook -> Verifier) x 20...
.................... Done.

================================================================================
PHASE 0 REPLAY & EVALUATION BENCHMARK SUMMARY
================================================================================
Workflow 1 (T1 Sandboxed File Write):
  Runs: 20 | Success: 20 | Failures: 0 | Unverified: 0
  Intake Latency (ms) : Mean=0.065 | Median=0.052 | p95=0.061
  Policy Latency (ms) : Mean=0.018 | Median=0.018 | p95=0.021
  Total Dispatch (ms) : Mean=15.859 | Median=16.081 | p95=17.332

Workflow 2 (T2 Quarantined Shell Process with Isolated UI Approval):
  Runs: 20 | Success: 20 | Failures: 0 | Unverified: 0
  UI Hook Latency (ms): Mean=0.003 | Median=0.003 | p95=0.004
  Total Dispatch (ms) : Mean=374.496 | Median=292.395 | p95=827.803
================================================================================
Results successfully saved to: D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC)\eval_results\phase0_replay.json
```

---

## 6. List of Tests That Could Not Pass

**Count: 0**  
Every test in the test suite passes cleanly:
- `test_mac.py`: 13/13 PASSED
- `test_phase0_vertical_slice.py`: 10/10 PASSED
- `test_phase0_adversarial.py`: 12/12 PASSED
- **Total**: 35/35 PASSED

---

## 7. Known Remaining Weaknesses & Architectural Realities

1. **Shared Process Memory**:
   As noted in Section 4, until the Phase 1 IPC supervisor/worker separation is deployed, an agent running arbitrary Python in-process could theoretically access `self.coordinator` internals via `gc` or introspection. This is mitigated by restricting untrusted code execution to external OS subprocesses (`LocalExecDaemon.execute_command`).
2. **Windows Path Inconsistencies**:
   Windows supports alternative data streams (e.g., `file.txt:hidden`), 8.3 short filenames (e.g., `WORKSP~1`), and case-insensitive NTFS matching. `sandboxed_file_writer` normalizes paths using `.resolve()`, but comprehensive NTFS stream filtering should be hardened before multi-user enterprise deployment.
3. **SQLite Write Concurrency Under Multi-Thread Load**:
   While WAL mode permits concurrent readers with a single writer, high-frequency concurrent writes from multiple agents can encounter `sqlite3.BusyError`. Thread-local connection pooling and a 5-second busy timeout mitigate this, but a dedicated database daemon will be needed at higher concurrency scales.
4. **Shell Output Verification Limit**:
   For arbitrary shell execution (`execute_shell_command`), the verifier can only assert the process exit code (`exitCode == 0`) and captured stdout/stderr length. It cannot deterministically prove side-effects performed by opaque binary executables unless specific post-condition files or endpoints are declared in the contract's success predicate.

---

## 8. Exact Reproduction Commands

To reproduce every result from a clean terminal:

```bash
# 1. Activate environment and verify clean git status
git status

# 2. Verify test_mac.py has zero diff against baseline (8e6de60~1)
git diff 8e6de60~1 HEAD -- test_mac.py

# 3. Run the complete test suite (35 tests)
pytest -v test_mac.py test_phase0_vertical_slice.py test_phase0_adversarial.py

# 4. Run the deterministic verifier mutation check
python mutation_check.py

# 5. Run the Phase 0 end-to-end replay and latency benchmark harness
python eval_replay.py --iterations 20
```
