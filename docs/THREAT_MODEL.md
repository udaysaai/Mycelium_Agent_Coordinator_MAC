# Mycelium Agent Coordinator (MAC) Threat Model (Phase 0.7)

**Document Version**: 1.0.0  
**Target Environment**: Windows 11 Build 26340+, Python 3.12 / 3.14, Electron Desktop UI  
**Security Status**: MITIGATED (Process Boundary + Low Integrity Level + Job Object)  

---

## 1. Threat Actor & Attacker Profile

- **Primary Threat Actor**: Compromised or prompt-injected Large Language Model (LLM) / Autonomous Subagent.
- **Attack Vector**: Indirect prompt injection via ingested untrusted text (e.g. web scraping, email, repository code, panchayat ledger inputs) inducing the worker to execute arbitrary commands, exfiltrate sensitive files, or forge approvals.
- **Capabilities of Attacker**: Arbitrary Python code execution inside the worker process; local loopback IPC access; same-user read access to medium-integrity files under Windows default security policy.
- **Explicit Goals of Attacker**:
  1. Bypass T2 Human-On-The-Loop quarantine gate and execute mutating shell/filesystem actions without human approval.
  2. Forge one-shot authorization tokens or replay previously consumed tokens.
  3. Tamper with SQLite WAL audit logs or receipts to hide malicious modifications.
  4. Exfiltrate sensitive user data (e.g. financial records, API keys, credentials) over the local network or internet.
  5. Escalate privileges from Worker to Supervisor or inject memory into other desktop applications.

---

## 2. Trust Boundaries & Architecture

```
+-------------------------------------------------------------------------+
|                              USER SESSION                               |
|                                                                         |
|  +---------------------------+         +-----------------------------+  |
|  |     ELECTRON DESKTOP      |  Named  |     SUPERVISOR DAEMON       |  |
|  |  (main.js / renderer UI)  |<------->|    (supervisor.py)          |  |
|  |   Medium Integrity Level  |  Pipe   |   Medium Integrity Level    |  |
|  |                           |  (UI)   |                             |  |
|  | - Displays untruncated cmd|         | - Owns SQLite WAL Database  |  |
|  | - Visual anomaly chips    |         | - Ephemeral 256-bit HMAC key|  |
|  | - 15m quarantine expiry   |         | - Policy & Deterministic Ver|  |
|  +---------------------------+         | - Process DACL Protected    |  |
|                                        +-----------------------------+  |
|                                                       ^                 |
|                                                       | Named Pipe      |
|                                                       | (Worker)        |
|                                                       v                 |
|                                        +-----------------------------+  |
|                                        |     WORKER PROCESS          |  |
|                                        |    (LocalExec / LLM)        |  |
|                                        |     Low Integrity Level     |  |
|                                        |                             |  |
|                                        | - Token: DISABLE_MAX_PRIV   |  |
|                                        | - Windows Job Object Confin |  |
|                                        | - Blocked: MIC NO_WRITE_UP  |  |
|                                        | - Workspace Sandbox CWD     |  |
|                                        +-----------------------------+  |
+-------------------------------------------------------------------------+
```

### Boundary 1: Supervisor vs Worker
- **Supervisor**: Runs at **Medium Integrity Level** with custom process DACL (removing `PROCESS_TERMINATE` from user/logon SID). Owns the ephemeral in-memory state signing key, SQLite WAL database, policy evaluation engine, and out-of-band deterministic verifier.
- **Worker**: Runs at **Low Integrity Level** (`S-1-16-4096`) with `DISABLE_MAX_PRIVILEGE` restricted token, confined inside a Windows Job Object (`KILL_ON_JOB_CLOSE`, 512MB RAM cap).
- **Enforcement**: Windows Mandatory Integrity Control (MIC) blocks write-up (`NO_WRITE_UP`) and handle manipulation (`NO_READ_UP` for process handles: `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_DUP_HANDLE`).

### Boundary 2: UI vs Supervisor
- Communicates over authenticated Windows Named Pipe (`\\.\pipe\mac_ui_<secret>`).
- Client must authenticate using a 256-bit per-session secret generated at startup. The secret is held solely in Electron `main.js` memory and is never exposed to renderer processes or workers.
- The UI pipe is DACL-restricted to current user logon SID.

### Boundary 3: Worker vs Filesystem
- Task sandbox (`workspace_sandbox`) is labeled with Low Integrity (`(OI)(CI)L`).
- All directories outside sandbox (repository root, supervisor source code, system directories, user documents) have Medium or High Integrity.
- Windows MIC blocks all write, create, overwrite, and delete operations outside the sandbox.

### Boundary 4: Worker vs Network
- **Residual Exfiltration Risk**: Standard Windows Low Integrity tokens do not restrict outbound TCP/UDP connections. Windows Job Objects do not provide a network filtering mechanism.
- Therefore, a compromised worker can initiate outbound socket connections unless an external container or network firewall rule is applied.

---

## 3. Analysis of Same-User OS Limitations (Windows Architecture)

Under the Windows NT security architecture:
1. **MIC Read-Up Permissions**: Windows Mandatory Integrity Control enforces `NO_WRITE_UP` (0x1), meaning a Low IL process cannot alter Medium IL objects. However, MIC does **not** enforce `NO_READ_UP` by default on standard filesystem objects. Therefore, any file in the user's profile (`%USERPROFILE%`, documents, desktop) that does not have an explicit Deny-read ACL for Low IL remains readable by a same-user Low IL process.
2. **AppContainer Incompatibility for Win32 CPython**: While AppContainers provide full read isolation and network isolation, standard Win32 CPython fails with `0xc0000135` (`STATUS_DLL_NOT_FOUND`) under AppContainer because CPython dependencies (`python312.dll`, standard library C-extensions) lack UWP/AppContainer package filesystem permissions.
3. **Implication for Financial Records**: Real financial records (e.g. Gram Panchayat cashbooks, vouchers, bank statements, personal tax documents) **must not be processed directly in this environment without external isolation**.

> [!CAUTION]
> **Financial & Sensitive Data Processing Warning**:
> Operating MAC in standalone desktop mode with Low IL worker isolation provides strong mutation resistance and tamper-proofing, but does NOT guarantee confidentiality against local file read or network exfiltration. Real financial ledgers or confidential records must be hosted inside an isolated hypervisor boundary (WSL2, Docker container with read-only volume mounts, or Windows Sandbox).

---

## 4. Residual Risk Matrix (W1 - W9)

| ID | Attack Vector | Security Mechanism | Status | Measured Residual Risk |
|---|---|---|---|---|
| **W1** | Read user files outside task sandbox | Windows MIC | **DOCUMENTED RESIDUAL** | **Medium**: Low IL can read same-user Medium IL files. Confidential data must use external sandbox. |
| **W2** | Write/tamper outside task sandbox | MIC `NO_WRITE_UP` (0x1) | **FIXED** | **None**: Attempts to write outside sandbox fail with Win32 Error 5 (`ERROR_ACCESS_DENIED`). |
| **W3** | Outbound network socket exfiltration | Windows Token / Job Object | **DOCUMENTED RESIDUAL** | **High**: Low IL token does not filter TCP. Worker can open outbound connections. |
| **W4** | OpenProcess against Supervisor memory/kill | MIC + Process DACL (`~PROCESS_TERMINATE`) | **FIXED** | **None**: Non-vacuously verified. `OpenProcess` fails with `ERROR_ACCESS_DENIED` (code 5). |
| **W5** | Direct write to SQLite WAL state store | MIC `NO_WRITE_UP` on `data/mac_state.db` | **FIXED** | **None**: Database file is Medium IL. Low IL worker write returns `PermissionError`. |
| **W6** | Enumerate UI pipe and approve actions | Pipe DACL + 256-bit UI secret | **FIXED** | **None**: Worker pipe whitelist forbids approvals; UI pipe requires unshared per-session secret. |
| **W7** | Fork bomb / RAM exhaustion (>512MB) | Windows Job Object limits | **FIXED** | **None**: Memory allocations exceeding limit trigger `MemoryError` or job termination. |
| **W8** | Overwrite supervisor code / DLLs | Medium IL label on binaries & source | **FIXED** | **None**: Verified that supervisor loaded scripts and C-extensions are Medium IL, not writable by worker. |
| **W9** | Leak secrets via env, argv, or handles | Inherited handle stripping (`close_fds=True`) | **FIXED** | **None**: Zero secrets in worker `os.environ`, `sys.argv`, or open handles. |

---

## 5. Mitigation Roadmap for Future Phases

1. **Hypervisor Containerization (Phase 1.0)**: Move worker execution into WSL2 or lightweight Linux container with isolated filesystem namespace and disabled network interfaces (`--network none`).
2. **Dedicated Service Account**: Run the worker under a separate low-privileged Windows local user account (`MAC_Worker_User`) with explicit Deny ACLs on the host user profile.
3. **Windows Filtering Platform (WFP) Callout**: Implement a local WFP driver or packet filter restricting loopback IPC to supervisor ports and blocking outbound internet traffic.

