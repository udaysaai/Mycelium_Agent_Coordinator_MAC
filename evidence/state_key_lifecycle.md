# State-Integrity Key Lifecycle & Restart Security Model (Phase 0.7 - Question Q6)

**Date**: 2026-10-29  
**Auditor**: Antigravity Security Reviewer & Implementer  

---

## 1. Key Generation and Storage Architecture

### Key Creation
The state-integrity HMAC key and token-signing key are instantiated during `SupervisorDaemon.__init__` using:
```python
self._signing_key: bytes = secrets.token_bytes(32)
```
This is a 256-bit cryptographically strong pseudorandom byte array generated directly from the operating system's CSP (`CryptGenRandom` / `BCryptGenRandom` via Python `secrets`).

### Key In-Memory Location
- The key resides strictly in private virtual memory of the `SupervisorDaemon` process (`self._signing_key`, passed to `StateStore(integrity_key=...)` and `PolicyEngine(signing_key=...)`).
- **Never written to disk**: The key is never saved to any file, config, SQLite table, or log.
- **Never in environment variables**: `os.environ` does not contain the key.
- **Never in command-line arguments**: Worker process `sys.argv` does not contain the key.
- **Never inherited across subprocess handles**: Worker process handle inheritance is disabled (`close_fds=True`).

---

## 2. Worker Access Boundary (Low-IL Isolation)

Can a compromised Low-Integrity worker process read the key?

1. **Process Memory Protection (W4)**:
   The supervisor runs at Medium Integrity with a protected DACL. Under Windows Mandatory Integrity Control (MIC), a Low-Integrity process attempting `OpenProcess(PROCESS_VM_READ, ...)` on the supervisor receives Win32 error code 5 (`ERROR_ACCESS_DENIED`).
2. **Channel Whitelist**:
   The worker communicates with the supervisor exclusively through the Worker Named Pipe. The worker pipe protocol rejects all attempts to query tokens, keys, or decisions (`FORBIDDEN_WORKER_MESSAGE_TYPES = {"APPROVE_ACTION", "REJECT_ACTION", "ISSUE_TOKEN"}`).
3. **Database File Separation**:
   The SQLite database file stores HMAC signatures computed over rows (`row_hmac`), but does not store the secret key itself.

---

## 3. Behavior Across Supervisor Restart

### Invalidation of Outstanding Tokens (Fail-Secure)
Because the key is ephemeral:
1. When the supervisor stops, crashes, or is restarted, the previous signing key is destroyed.
2. Upon restart, a fresh, unrelated 32-byte key is generated.
3. If an unconsumed one-shot token signed by the prior supervisor instance is submitted to the new supervisor:
   - `PolicyEngine.verify_hmac_token` recalculates the HMAC using the new key.
   - The token signature mismatches.
   - Verification returns `False`.
   - Supervisor execution returns `403 Forbidden` (`{"status": "ERROR", "message": "Invalid or forged token"}`).
4. This ensures that a compromised worker cannot reuse tokens across service restarts.

### Database Row HMAC Audit
- State row HMACs generated during an earlier supervisor session cannot be verified against the new session's ephemeral key.
- This is intentional: the ephemeral key model is designed to prevent cross-session token forgery and replay attacks.
- If persistent historical verification across cold boots is required in a future release, a hardware-bound key (Windows DPAPI with machine/user scope) will be evaluated. In Phase 0.7, the architecture is explicitly fail-secure: **restarts invalidate outstanding approvals**.
