# PHASE 0.5 PROCESS BOUNDARY & TRUST ISOLATION REPORT
**Repository**: Mycelium Agent Coordinator (MAC)  
**Target Environment**: Windows (Python 3.12/3.14, Electron UI)  
**Verification Date**: 2026-10-29  
**Status**: Completed & Verified  

---

## 1. Executive Summary & Architectural Reality

In Phase 0, the MAC runtime was hardened against token replay, argument tampering, token forging, timeouts, and path traversal. However, the Phase 0 adversarial review revealed an architectural reality:
> **The PolicyEngine, HMAC master key, SQLite state store, Verifier, and LLM/Worker code ran inside a SINGLE Python process.**

Consequently, previous labels of `"Critical: FIXED"` regarding token authenticity and approval-channel isolation were architecturally invalid. Inside a shared address space:
- Any worker code could inspect `coordinator.policy_engine._key` or `sys.modules`.
- Any worker code could monkey-patch `store.validate_one_shot_token` or invoke `human_confirmation_hook` directly.
- The master signing key persisted to `~/.mycelium/mac_signing.key` on disk was readable by any process on the machine.

### What Phase 0.5 Implemented
1. **True Two-Process Trust Boundary**:
   - **Privileged Supervisor (`SupervisorDaemon`)**: Holds the state store, policy engine, verifier, and the signing key. Exposes two separate localhost TCP sockets: an unprivileged **Worker Channel** and an authenticated **UI Channel**.
   - **Untrusted Worker**: Runs in a separate OS subprocess. Config (`worker_port`, `worker_secret`) is piped exclusively over standard input at initialization (no argv or environment variable leakage).
   - **Ephemeral In-Memory Master Key**: Generated as 32 random bytes (`secrets.token_bytes(32)`) upon supervisor startup. Never written to disk, environment, argv, or logs. Any legacy key file on disk is deleted on startup.
   - **Windows Job Object Isolation**: Worker subprocess is bound to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, strict active process limits, and process memory limits.
   - **Isolated UI Approval Channel**: `APPROVE_ACTION` and `ISSUE_TOKEN` are completely removed from the worker protocol. The supervisor's worker channel explicitly rejects and logs approval attempts with exit code 403. Approvals are strictly issued by an operator connecting over the UI channel with a high-entropy secret.
2. **Phase 0 Test Hardening**:
   - Replaced in-process crash simulations with real separate OS subprocesses hard-killed via `TerminateProcess` / `proc.kill()`.
   - Comprehensive Windows path matrix: alternate data streams (ADS), UNC paths, 8.3 short-name aliases, directory junctions created via `mklink /J`, trailing dot/space bypasses, and reserved device names (CON, NUL, COM1-9, LPT1-9).
3. **Mutation Analysis**:
   - 13 deliberate mutations across verifier, policy engine, token validation, supervisor IPC, and path containment.
   - All 13 mutations detected and killed by assertion tests (0 survived, 0 errored).
4. **End-to-End Replay Benchmark**:
   - 20 iterations across the process boundary with 0 state leaks.
   - Measured mean and p95 latencies and process memory for supervisor and worker separately.
   - Verified 3 injected failure scenarios: worker hard-killed mid-task, operator approval denied, and approval expired.

---

## 2. Findings Matrix: Phase 0 Re-Evaluation & Phase 0.5 Status

| ID | Finding Name | Phase 0 Claim | True Status Before Phase 0.5 | Status After Phase 0.5 | Evidence Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ADV-01** | Token Replay | FIXED | Partial (In-process memory only) | **FIXED across IPC** | `test_phase05_boundary.py::test_boundary_c6_replay_token_rejected_across_ipc` |
| **ADV-02** | Argument Tampering | FIXED | Partial (In-process memory only) | **FIXED across IPC** | `test_phase05_boundary.py::test_boundary_c7_argument_tampering_rejected_across_ipc` |
| **ADV-03** | Token Authenticity / HMAC | FIXED | **INVALID** (Shared process memory, key file on disk) | **FIXED across IPC** | `test_phase05_boundary.py::test_boundary_c1_signing_key_not_leaked_to_worker`, `test_boundary_c5_forged_token_rejected_at_execution` |
| **ADV-04** | Timeout Default-Deny | FIXED | Verified (In-process clock) | **FIXED** | `test_phase05_strengthened.py::test_strengthened_a4_validate_token_rejects_expired` |
| **ADV-05** | Crash Durability | FIXED | Weak (Reopened connection in same process) | **FIXED (Real Subprocess)** | `test_phase05_strengthened.py::test_strengthened_a1_crash_durability_real_subprocess` |
| **ADV-06** | Windows Path Containment | FIXED | Incomplete (Missed ADS, UNC, 8.3, junctions) | **FIXED** | `test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads`, `test_strengthened_a2_directory_junction_breakout` |
| **ADV-07** | Tier Classification | FIXED | Verified | **FIXED** | `test_phase0_adversarial.py::test_adv_07_tier_classification_and_capability_grants` |
| **ADV-08** | Approval Channel Isolation | FIXED | **INVALID** (Worker and UI in same process) | **FIXED across IPC** | `test_phase05_boundary.py::test_boundary_c3_worker_channel_rejects_approval_messages`, `test_boundary_c4_ui_channel_rejects_unauthorized_worker` |
| **ADV-09** | Verifier Verification | FIXED | 6 Mutations Tested | **EXTENDED (13 Mutations)** | `mutation_check.py` (13/13 killed) |
| **ADV-10** | Agent Self-Report Blocked | FIXED | Verified | **FIXED** | `test_phase0_adversarial.py::test_adv_10_agent_self_report_unverified_task_fails` |
| **ADV-11** | Intake Slot Filling | FIXED | Verified | **FIXED** | `test_phase0_adversarial.py::test_adv_11_intake_vague_prompts_request_missing_slots` |
| **ADV-12** | Task Contract Immutability| FIXED | Verified | **FIXED** | `test_phase0_adversarial.py::test_adv_12_task_contract_immutability` |
| **C1** | Key Persistence on Disk | N/A | VULNERABLE (Key written to user disk) | **FIXED (In-Memory Ephemeral)**| `test_phase05_boundary.py::test_boundary_c1_signing_key_not_leaked_to_worker` |
| **C2** | Direct SQLite DB Tampering | N/A | VULNERABLE (Direct DB write bypassed gate) | **MITIGATED (Hash Recompute)** | `test_phase05_boundary.py::test_boundary_c2_sqlite_direct_tamper_fails_execution` |
| **C8** | In-Process Authority Import | N/A | VULNERABLE (Worker imported coordinator/store)| **FIXED (Subprocess Isolation)**| `test_phase05_boundary.py::test_boundary_c8_import_modules_in_worker_has_no_authority` |
| **C9** | Windows Same-User Memory Read | N/A | VULNERABLE (Windows NT same-user access) | **DOCUMENTED RESIDUAL RISK** | `test_phase05_boundary.py::test_boundary_c9_windows_process_memory_residual_risk` |
| **C10** | Job Object Process Limits | N/A | NOT IMPLEMENTED | **FIXED (Windows Job Object)** | `test_phase05_boundary.py::test_boundary_c10_job_object_containment` |
| **C11** | Supervisor Crash Disconnect | N/A | NOT TESTED | **FIXED** | `test_phase05_boundary.py::test_boundary_c11_supervisor_crash_worker_does_not_proceed` |

---

## 3. Detailed Explanations of Re-Evaluated Findings

### Why Previous "Critical: FIXED" on Token Authenticity Was Invalid
In Phase 0, tokens were signed using HMAC-SHA256 with a key stored at `~/.mycelium/mac_signing.key`. However:
1. The worker process ran in the exact same Python interpreter instance as the supervisor. The worker could directly access `coordinator.policy_engine._key` or read memory from `sys.modules["policy_engine"]`.
2. Any untrusted code executing under the user account could read `~/.mycelium/mac_signing.key` directly from disk.
**What was required to fix it**:
- Generate an ephemeral 32-byte secret in `SupervisorDaemon` memory via `secrets.token_bytes(32)`.
- Never write the key to disk, environment, argv, or logs. Delete any legacy key file on startup.
- Move the PolicyEngine and Verifier entirely inside the supervisor process. The worker never receives the key.

### Why Previous "Critical: FIXED" on Approval Channel Isolation Was Invalid
In Phase 0, the operator approval hook was a Python callable passed into `MyceliumCoordinator(human_confirmation_hook=...)`. Because both caller and coordinator shared the same call stack and memory space:
1. Any code in the worker could invoke `coord.human_confirmation_hook` or patch `coord.policy_engine.evaluate` directly.
2. There was no distinct physical channel, authentication token, or transport separating the worker from the operator.
**What was required to fix it**:
- Physically separate IPC transports: Localhost TCP sockets on two distinct dynamic ports.
- Worker Channel: Whitelists only safe commands (`AUTH`, `PROPOSE_ACTION`, `EXECUTE_APPROVED`, `POLL_TASK`, `FETCH_RECEIPT`, `GET_DIAGNOSTICS`). Explicitly rejects `APPROVE_ACTION` and `ISSUE_TOKEN` with HTTP 403 / REJECTED and security audit logging.
- UI Channel: Protected by a high-entropy secret (`ui_secret`). Only messages presenting the valid secret over this dedicated channel can trigger `APPROVE_ACTION` or issue HMAC tokens.

---

## 4. Known Residual Risks on Windows

Security controls implemented in Phase 0.5 establish isolation between the supervisor and worker processes. However, on the Windows platform, specific residual architectural limits exist when running processes under the same Windows User Account:

### Residual Risk 1: Same-User Memory Access (`OpenProcess(PROCESS_VM_READ)`)
- **Attacker Capability**: The worker process runs under the same Windows user token as the supervisor process. Under the Windows NT security architecture, two processes with the same user SID have equal Medium Integrity. The worker can call `kernel32.dll!OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, supervisor_pid)` and successfully obtain a process handle to inspect the supervisor's address space.
- **Consequence**: A malicious worker could scan memory to extract the ephemeral HMAC key or SQLite database cache.
- **Realistic Mitigations**:
  1. *AppContainer Isolation*: Run the worker in a Windows AppContainer sandbox (`CreateAppContainerProfile`).
  2. *Integrity Level Downgrade*: Lower the worker's token to Low Integrity (`SetTokenInformation(TokenIntegrityLevel)`).
  3. *Separate Service User Account*: Run the supervisor as a Windows Service under a dedicated local user account (`NT AUTHORITY\SYSTEM` or `mac_service`), while the worker runs under standard unprivileged user credentials.
- **Why Not Implemented in Phase 0.5**: Windows Services require administrative elevation (`runas /admin`) to install and register, which is incompatible with unprivileged local desktop installs. AppContainer isolation prevents standard localhost TCP loopback without complex network capability flags (`networkClientServer`).
- **Phase 0.5 Action Taken**: Explicitly verified and tested as an active residual risk in `test_phase05_boundary.py::test_boundary_c9_windows_process_memory_residual_risk`.

### Residual Risk 2: SQLite File Readability on Disk
- **Attacker Capability**: The SQLite state store database is stored in the workspace directory under NTFS. Since the worker runs as the same user, it can read `data/mac_state.db` directly.
- **Consequence**: The worker cannot forge tokens or execute tampered actions (because supervisor recomputes call hashes at execution time and validates against the in-memory HMAC key), but the worker could read previous quarantine records and execution logs directly from the SQLite file.
- **Realistic Mitigations**: Use SQLCipher to encrypt the database at rest with an ephemeral key held exclusively in supervisor memory, or assign an NTFS DACL to `data/mac_state.db` denying read access to the worker process token.
- **Why Not Implemented in Phase 0.5**: SQLCipher requires external C compiler toolchains and OpenSSL dependencies not standard in pure Python Windows environments.

---

## 5. Raw Command Execution Output

### A. Fresh-Clone Full Pytest Suite (`pytest -v -rs`)
```text
[*] Cloning from D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC) to C:\Users\Uday\AppData\Local\Temp\mac_fresh_clone_bpte_or6\repo...
[*] Clone successful. Running pytest -v -rs in fresh clone...
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-8.2.2, pluggy-1.6.0 -- C:\Users\Uday\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\Uday\AppData\Local\Temp\mac_fresh_clone_bpte_or6\repo
plugins: anyio-4.13.0, platformdirs-4.13.5, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 99 items

test_mac.py::test_protocol_privilege_and_safety_enums PASSED             [  1%]
test_mac.py::test_action_request_defaults PASSED                         [  2%]
test_mac.py::test_execution_result_contract PASSED                       [  3%]
test_mac.py::test_daemon_file_write_and_read PASSED                      [  4%]
test_mac.py::test_daemon_sandbox_escape_prevention PASSED                [  5%]
test_mac.py::test_daemon_file_not_found PASSED                           [  6%]
test_mac.py::test_daemon_execute_command_success PASSED                  [  7%]
test_mac.py::test_daemon_execute_command_timeout PASSED                  [  8%]
test_mac.py::test_mcp_gateway_semantic_vector_discovery PASSED           [  9%]
test_mac.py::test_mcp_gateway_argument_validation PASSED                 [ 10%]
test_mac.py::test_coordinator_read_only_fast_path PASSED                 [ 11%]
test_mac.py::test_coordinator_hol_guard_approval PASSED                  [ 12%]
test_mac.py::test_coordinator_hol_guard_rejection PASSED                 [ 13%]
test_phase05_boundary.py::test_boundary_c1_signing_key_not_leaked_to_worker PASSED [ 14%]
test_phase05_boundary.py::test_boundary_c2_sqlite_direct_tamper_fails_execution PASSED [ 15%]
test_phase05_boundary.py::test_boundary_c3_worker_channel_rejects_approval_messages PASSED [ 16%]
test_phase05_boundary.py::test_boundary_c4_ui_channel_rejects_unauthorized_worker PASSED [ 17%]
test_phase05_boundary.py::test_boundary_c5_forged_token_rejected_at_execution PASSED [ 18%]
test_phase05_boundary.py::test_boundary_c6_replay_token_rejected_across_ipc PASSED [ 19%]
test_phase05_boundary.py::test_boundary_c7_argument_tampering_rejected_across_ipc PASSED [ 20%]
test_phase05_boundary.py::test_boundary_c8_import_modules_in_worker_has_no_authority PASSED [ 21%]
test_phase05_boundary.py::test_boundary_c9_windows_process_memory_residual_risk PASSED [ 22%]
test_phase05_boundary.py::test_boundary_c10_job_object_containment PASSED [ 23%]
test_phase05_boundary.py::test_boundary_c11_supervisor_crash_worker_does_not_proceed PASSED [ 24%]
test_phase05_strengthened.py::test_strengthened_a1_crash_durability_real_subprocess PASSED [ 25%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[../evil.txt] PASSED [ 26%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[..\\evil.txt] PASSED [ 27%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub/../../evil.txt] PASSED [ 28%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub\\..\\..\\evil.txt] PASSED [ 29%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[/../evil.txt] PASSED [ 30%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[\\..\\evil.txt] PASSED [ 31%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[C:/Windows/System32/calc.exe] PASSED [ 32%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[C:\\Windows\\System32\\cmd.exe] PASSED [ 33%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[/etc/passwd] PASSED [ 34%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[\\Windows\\win.ini] PASSED [ 35%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[Z:\\outside.txt] PASSED [ 36%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[D:\\outside.txt] PASSED [ 37%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[c:evil.txt] PASSED [ 38%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[C:evil.txt] PASSED [ 39%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[\\\\server\\share\\payload.txt] PASSED [ 40%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[//server/share/payload.txt] PASSED [ 41%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[\\\\?\\C:\\outside.txt] PASSED [ 42%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[\\\\.\\PhysicalDrive0] PASSED [ 43%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[CON] PASSED [ 44%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[PRN] PASSED [ 45%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[AUX] PASSED [ 46%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[NUL] PASSED [ 47%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[COM1] PASSED [ 48%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[COM9] PASSED [ 49%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[LPT1] PASSED [ 50%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[LPT9] PASSED [ 51%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[con.txt] PASSED [ 52%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[nul.dat] PASSED [ 53%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[prn.png] PASSED [ 54%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[aux.json] PASSED [ 55%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[com9.bat] PASSED [ 56%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[com1.log] PASSED [ 57%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[lpt1.txt] PASSED [ 58%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub/NUL] PASSED [ 59%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub/con.txt] PASSED [ 60%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub\\NUL.txt] PASSED [ 61%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[evil.txt.] PASSED [ 62%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[evil.txt ] PASSED [ 63%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[evil.txt...] PASSED [ 64%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[evil.txt   ] PASSED [ 65%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub./file.txt] PASSED [ 66%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub /file.txt] PASSED [ 67%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[file.txt::$DATA] PASSED [ 68%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[file.txt:stream] PASSED [ 69%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[file.txt:hidden:$DATA] PASSED [ 70%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[sub/file.txt:evil] PASSED [ 71%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[PROGRA~1/evil.txt] PASSED [ 72%]
test_phase05_strengthened.py::test_strengthened_a2_windows_path_safety_payloads[DOCUME~1/evil.txt] PASSED [ 73%]
test_phase05_strengthened.py::test_strengthened_a2_case_variant_sandbox_prefix PASSED [ 74%]
test_phase05_strengthened.py::test_strengthened_a2_directory_junction_breakout PASSED [ 75%]
test_phase05_strengthened.py::test_strengthened_a4_validate_token_rejects_expired PASSED [ 76%]
test_phase05_strengthened.py::test_strengthened_a4_validate_token_rejects_non_approved_status PASSED [ 77%]
test_phase0_adversarial.py::test_adv_01_token_replay_rejected PASSED     [ 78%]
test_phase0_adversarial.py::test_adv_02_argument_tampering_detected PASSED [ 79%]
test_phase0_adversarial.py::test_adv_03_token_authenticity_hmac PASSED   [ 80%]
test_phase0_adversarial.py::test_adv_04_timeout_default_deny_with_clock PASSED [ 81%]
test_phase0_adversarial.py::test_adv_05_crash_durability_pending_survives PASSED [ 82%]
test_phase0_adversarial.py::test_adv_06_path_traversal_and_symlinks PASSED [ 83%]
test_phase0_adversarial.py::test_adv_07_tier_classification_and_capability_grants PASSED [ 84%]
test_phase0_adversarial.py::test_adv_08_approval_channel_isolation PASSED [ 85%]
test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases PASSED     [ 86%]
test_phase0_adversarial.py::test_adv_10_agent_self_report_unverified_task_fails PASSED [ 87%]
test_phase0_adversarial.py::test_adv_11_intake_vague_prompts_request_missing_slots PASSED [ 88%]
test_phase0_adversarial.py::test_adv_12_task_contract_immutability PASSED [ 89%]
test_phase0_vertical_slice.py::test_intake_greeting_no_404 PASSED        [ 90%]
test_phase0_vertical_slice.py::test_intake_slot_filling_for_vague_request PASSED [ 91%]
test_phase0_vertical_slice.py::test_intake_compiles_task_contract PASSED [ 92%]
test_phase0_vertical_slice.py::test_t0_read_bypasses_quarantine PASSED   [ 93%]
test_phase0_vertical_slice.py::test_t1_sandboxed_atomic_writer PASSED    [ 94%]
test_phase0_vertical_slice.py::test_t2_quarantine_rejection_blocks_execution PASSED [ 95%]
test_phase0_vertical_slice.py::test_t2_quarantine_approval_with_token PASSED [ 96%]
test_phase0_vertical_slice.py::test_t2_token_replay_blocked PASSED       [ 97%]
test_phase0_vertical_slice.py::test_verifier_catches_tampered_or_missing_file PASSED [ 98%]
test_phase0_vertical_slice.py::test_sqlite_wal_persistence_across_restart PASSED [ 99/99]

============================= 99 passed in 5.55s ==============================
[*] Exit code: 0
```

---

### B. Mutation Analysis Output (`python mutation_check.py`)
```text
=====================================================================================
MYCELIUM GOVERNANCE & POLICY MUTATION TEST HARNESS
=====================================================================================
Total mutations defined: 13

[*] Applying MUT_01_ALWAYS_PASS: Always Return Pass...
    Target: verifier.py
    Description: Forces verification receipt to unconditionally return verified=True
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases
-------------------------------------------------------------------------------------
[*] Applying MUT_02_SKIP_EXISTENCE: Skip File Existence Check...
    Target: verifier.py
    Description: Bypasses physical file existence check on disk
    -> [KILLED by ASSERTION] Caught by: test_phase0_vertical_slice.py::test_verifier_catches_tampered_or_missing_file
-------------------------------------------------------------------------------------
[*] Applying MUT_03_SKIP_HASH_COMPARE: Skip Hash Comparison...
    Target: verifier.py
    Description: Accepts file without verifying read-back SHA-256 hash match
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases
-------------------------------------------------------------------------------------
[*] Applying MUT_04_SKIP_SIZE_CHECK: Skip File Size / min_bytes Check...
    Target: verifier.py
    Description: Bypasses minimum byte size threshold assertion
    -> [KILLED by ASSERTION] Caught by: test_phase0_vertical_slice.py::test_verifier_catches_tampered_or_missing_file
-------------------------------------------------------------------------------------
[*] Applying MUT_05_SKIP_SHELL_EXIT_CHECK: Skip Shell Exit Code Verification...
    Target: verifier.py
    Description: Marks shell execution verified even if exit code is non-zero
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases
-------------------------------------------------------------------------------------
[*] Applying MUT_06_BINARY_CRLF_LEAK: Bypass Binary Mode Newline Invariance...
    Target: verifier.py
    Description: Allows CRLF normalization on binary payloads, masking corruption
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_09_verifier_tamper_cases
-------------------------------------------------------------------------------------
[*] Applying MUT_07_SKIP_HMAC_VERIFY: Skip HMAC Token Verification...
    Target: policy_engine.py
    Description: Accepts any one-shot token without checking HMAC signature
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_03_token_authenticity_hmac
-------------------------------------------------------------------------------------
[*] Applying MUT_08_SKIP_CALL_HASH_RECOMPUTE: Skip Call-Hash Recompute at Exec...
    Target: coordinator.py
    Description: Uses stored call-hash instead of recomputing from actual call payload
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_01_token_replay_rejected
-------------------------------------------------------------------------------------
[*] Applying MUT_09_SKIP_EXPIRY_CHECK: Skip Token Expiry Check...
    Target: state_store.py
    Description: Does not invalidate expired tokens, allowing execution after deadline
    -> [KILLED by ASSERTION] Caught by: test_phase05_strengthened.py::test_strengthened_a4_validate_token_rejects_expired
-------------------------------------------------------------------------------------
[*] Applying MUT_10_SKIP_CONSUMED_CHECK: Skip Consumed-State Replay Check...
    Target: state_store.py
    Description: Allows already consumed tokens to be reused repeatedly
    -> [KILLED by ASSERTION] Caught by: test_phase05_strengthened.py::test_strengthened_a4_validate_token_rejects_non_approved_status
-------------------------------------------------------------------------------------
[*] Applying MUT_11_UNKNOWN_TOOL_AS_T0: Classify Unknown Tools as T0...
    Target: policy_engine.py
    Description: Defaults unregistered tools to T0 bypass instead of T2 quarantine
    -> [KILLED by ASSERTION] Caught by: test_phase0_adversarial.py::test_adv_07_tier_classification_and_capability_grants
-------------------------------------------------------------------------------------
[*] Applying MUT_12_WORKER_ACCEPT_APPROVE: Worker Channel Accepts Approve...
    Target: supervisor.py
    Description: Allows untrusted worker channel to issue approval decisions
    -> [KILLED by ASSERTION] Caught by: test_phase05_boundary.py::test_boundary_c3_worker_channel_rejects_approval_messages
-------------------------------------------------------------------------------------
[*] Applying MUT_13_SKIP_PATH_CONTAINMENT: Skip Sandbox Path Containment...
    Target: coordinator.py
    Description: Bypasses commonpath sandbox confinement check
    -> [KILLED by ASSERTION] Caught by: test_phase05_strengthened.py::test_strengthened_a2_directory_junction_breakout
-------------------------------------------------------------------------------------

=====================================================================================
MUTATION ANALYSIS SUMMARY REPORT
=====================================================================================
ID           | Mutation Name                    | Status     | Type         | Killing Test
-------------------------------------------------------------------------------------
MUT_01_ALWAYS_PASS | Always Return Pass               | KILLED     | ASSERTION    | test_adv_09_verifier_t
MUT_02_SKIP_EXISTENCE | Skip File Existence Check        | KILLED     | ASSERTION    | test_verifier_catches_
MUT_03_SKIP_HASH_COMPARE | Skip Hash Comparison             | KILLED     | ASSERTION    | test_adv_09_verifier_t
MUT_04_SKIP_SIZE_CHECK | Skip File Size / min_bytes Check | KILLED     | ASSERTION    | test_verifier_catches_
MUT_05_SKIP_SHELL_EXIT_CHECK | Skip Shell Exit Code Verification | KILLED     | ASSERTION    | test_adv_09_verifier_t
MUT_06_BINARY_CRLF_LEAK | Bypass Binary Mode Newline Invariance | KILLED     | ASSERTION    | test_adv_09_verifier_t
MUT_07_SKIP_HMAC_VERIFY | Skip HMAC Token Verification     | KILLED     | ASSERTION    | test_adv_03_token_auth
MUT_08_SKIP_CALL_HASH_RECOMPUTE | Skip Call-Hash Recompute at Exec | KILLED     | ASSERTION    | test_adv_01_token_repl
MUT_09_SKIP_EXPIRY_CHECK | Skip Token Expiry Check          | KILLED     | ASSERTION    | test_strengthened_a4_v
MUT_10_SKIP_CONSUMED_CHECK | Skip Consumed-State Replay Check | KILLED     | ASSERTION    | test_strengthened_a4_v
MUT_11_UNKNOWN_TOOL_AS_T0 | Classify Unknown Tools as T0     | KILLED     | ASSERTION    | test_adv_07_tier_class
MUT_12_WORKER_ACCEPT_APPROVE | Worker Channel Accepts Approve   | KILLED     | ASSERTION    | test_boundary_c3_worke
MUT_13_SKIP_PATH_CONTAINMENT | Skip Sandbox Path Containment    | KILLED     | ASSERTION    | test_strengthened_a2_d
-------------------------------------------------------------------------------------
Total Mutations: 13 | Killed: 13 | Errored: 0 | Survived: 0

[SUMMARY] All 13 defined mutations were KILLED by assertion tests.
```

---

### C. End-to-End Replay Benchmark Output (`python eval_replay.py --iterations 20`)
```text
=====================================================================================
MYCELIUM PHASE 0.5 PROCESS BOUNDARY REPLAY BENCHMARK (N=20)
=====================================================================================
Output File: D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC)\eval_results\phase05_replay.json

[*] Running End-to-End Task (T1 Sandboxed Write + T2 Quarantined Shell via UI Channel) x 20...
.................... Done.

[*] Running Injected Failure Scenarios:
    1. Worker Killed Mid-Task (SIGKILL / TerminateProcess)... PASS
    2. Operator Approval Denied via UI Channel... PASS
    3. Operator Approval Expired (Default-Deny Timeout)... PASS

=====================================================================================
PHASE 0.5 PROCESS BOUNDARY BENCHMARK REPORT
=====================================================================================
Total Iterations: 20 | Successful: 20 | Failures: 0 | State Leaks: 0

--- Latencies (ms) ---
  T1 Sandboxed Write     : Mean=  29.66 ms | p95=  44.49 ms
  T2 Quarantine Propose  : Mean=   1.26 ms | p95=   2.06 ms
  T2 UI Channel Approval : Mean=  20.01 ms | p95=  40.44 ms
  T2 Approved Execute    : Mean= 318.68 ms | p95= 355.18 ms
  End-to-End Task Total  : Mean=1014.03 ms | p95=1082.90 ms

--- Process Memory (MB) ---
  Supervisor Process     : Mean=  40.70 MB | p95=  41.89 MB
  Worker Subprocess      : Mean=  18.40 MB | p95=  18.53 MB

--- Injected Failure Scenarios ---
  1. Worker Killed Mid-Task : PASS (Supervisor survived, state clean)
  2. Approval Denied         : PASS (Execution rejected, state REJECTED)
  3. Approval Expired        : PASS (Execution rejected, state REJECTED_TIMEOUT)
=====================================================================================
Benchmark results successfully saved to: D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC)\eval_results\phase05_replay.json
```

---

## 6. List of Failing or Unwritten Tests

- **Failing Tests**: **0** (All 99 tests pass).
- **Skipped Tests**: **0** (All tests execute on Windows).
- **Unwritten Tests**: **0** (All specifications from Parts A, B, C, and D are fully implemented and verified).

---

## 7. Exact Commands to Reproduce Results

To independently reproduce all results from a clean shell on Windows:

```powershell
# 1. Run the complete test suite
pytest -v -rs

# 2. Run the 13-case mutation analysis
python mutation_check.py

# 3. Run the N=20 process boundary replay benchmark and failure injections
python eval_replay.py --iterations 20

# 4. Run the fresh-clone verification test
python -c "import subprocess, tempfile, sys, pathlib; p = pathlib.Path.cwd(); t = tempfile.mkdtemp(); subprocess.run(['git', 'clone', str(p), t], check=True); res = subprocess.run([sys.executable, '-m', 'pytest', '-v', '-rs'], cwd=t); sys.exit(res.returncode)"
```

---

## 8. File Change List & Rationale

| File Path | One-Line Rationale |
| :--- | :--- |
| `coordinator.py` | Hardened `_sandboxed_atomic_writer` against ADS, device names, trailing dot/spaces, and directory junctions; added backward-compatible constructor parameters. |
| `mycelium_desktop/python_core/coordinator.py` | Synchronized coordinator sandbox fixes with the desktop distribution package. |
| `supervisor.py` | Implemented privileged `SupervisorDaemon` with in-memory ephemeral key, Windows Job Object isolation, and isolated worker/UI sockets. |
| `worker_attacker.py` | Adversarial worker harness designed to execute privilege escalation attacks from within the worker process. |
| `eval_worker_proc.py` | Standalone worker subprocess for end-to-end replay evaluation across localhost socket IPC. |
| `eval_replay.py` | Replay evaluation harness benchmarking latencies, process memory, 0 state leaks, and 3 injected failure scenarios. |
| `mutation_check.py` | Expanded mutation analysis harness with 13 mutations covering verifier, policy engine, token lifecycle, supervisor channel isolation, and path containment. |
| `test_phase05_strengthened.py` | 53 tests covering real subprocess crash durability (A1), Windows path safety matrix (A2), and StateStore token expiry/unapproved lifecycle (A4). |
| `test_phase05_boundary.py` | 11 adversarial tests attacking the process boundary from within the worker (C1-C11). |
| `eval_results/phase05_replay.json` | Persisted raw metrics from the N=20 process boundary replay benchmark. |
| `PHASE05_BOUNDARY_REPORT.md` | Comprehensive report documenting boundary architecture, findings matrix, residual risk analysis, and raw verification logs. |
