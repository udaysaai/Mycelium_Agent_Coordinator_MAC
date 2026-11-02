# Machine Changes Audit Log

This document records all machine-level changes made outside the repository, their justification, and their exact verification and revert commands.

---

## Change 1: Revert of Phase 0.6 `_ctypes.pyd` Low Integrity Relabeling

### Incident Description
During Phase 0.6 development, `icacls "C:\Users\Uday\AppData\Local\Programs\Python\Python312\DLLs\_ctypes.pyd" /setintegritylevel L` was run to test DLL loading in a Low-integrity worker process. This altered the system Python installation outside the repository, leaving `_ctypes.pyd` with `Mandatory Label\Low Mandatory Level:(NW)`, which created an integrity vulnerability: a Low-integrity worker could modify `_ctypes.pyd`, leading to code execution inside the Medium-integrity supervisor when loading `ctypes`.

### Applied Command (Phase 0.6)
```cmd
icacls "C:\Users\Uday\AppData\Local\Programs\Python\Python312\DLLs\_ctypes.pyd" /setintegritylevel L
```

### Revert Command Executed (Phase 0.7)
```cmd
icacls "C:\Users\Uday\AppData\Local\Programs\Python\Python312\DLLs\_ctypes.pyd" /setintegritylevel M
```

### Verification Command & Output
```cmd
icacls "C:\Users\Uday\AppData\Local\Programs\Python\Python312\DLLs\_ctypes.pyd"
```

**Raw Output**:
```
C:\Users\Uday\AppData\Local\Programs\Python\Python312\DLLs\_ctypes.pyd US\CodexSandboxUsers:(I)(RX)
                                                                       NT AUTHORITY\SYSTEM:(I)(F)
                                                                       BUILTIN\Administrators:(I)(F)
                                                                       US\Uday:(I)(F)
                                                                       Mandatory Label\Medium Mandatory Level:(NW)

Successfully processed 1 files; Failed processing 0 files
```

### Status
**REVERTED & VERIFIED**. `_ctypes.pyd` is restored to `Medium Mandatory Level`.

---

## Architectural Rule
No system Python installation files or registry keys may have their ACLs or integrity levels modified. The worker process must execute from an isolated runtime or AppContainer with permissions granted strictly within the repository workspace.

---

## Change 2: Phase 0.8 / WS2 Repo-Local Runtime & Workspace Sandbox Package ACLs

### Description
To enforce AppContainer isolation (W1 file read denial and W3 network denial) without machine-level changes, permissions were granted strictly to repo-local directories:
1. `runtime/worker_python`: Granted `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) `(OI)(CI)(RX)` (Read & Execute only, no write/modify).
2. `workspace_sandbox`: Granted `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) `(OI)(CI)(M)` (Modify within task sandbox only).

### Applied Commands
```cmd
icacls "runtime\worker_python" /grant "*S-1-15-2-1:(OI)(CI)(RX)"
icacls "workspace_sandbox" /grant "*S-1-15-2-1:(OI)(CI)(M)"
```

### Verification
Zero files outside the repository directory were touched. System Python at `C:\Users\Uday\AppData\Local\Programs\Python` remains strictly untouched with default Medium Mandatory Level.


