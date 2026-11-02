# Phase 0.8 / WS2 Containment Diagnosis & Implementation (W1 & W3)

## Executive Summary
In Phase 0.7, two residual risks were identified and admitted:
- **W1**: Low-Integrity workers under standard Windows Mandatory Integrity Control (MIC) can read Medium-Integrity files belonging to the same user (NO_WRITE_UP blocks writes, but does not block reads).
- **W3**: Low-Integrity processes under Windows MIC retain raw socket creation and outbound network connection capabilities.

In Phase 0.8 (WS2), these residual risks were addressed through **Windows AppContainer Isolation** combined with explicit repository-scoped package ACLs.

---

## 1. W1 Containment (Filesystem Isolation)

### Mechanism
Workers are launched inside an ephemeral Windows AppContainer (`userenv.CreateAppContainerProfile` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`).

### Security Properties
1. Windows kernel enforces that an AppContainer process possesses only its specific AppContainer SID and `ALL APPLICATION PACKAGES` (`S-1-15-2-1`).
2. Normal user directories (`Documents`, `Desktop`, `Downloads`, `AppData`, `Chrome User Data`, `.ssh`, sibling task directories) only have user and administrator DACLs; they grant zero rights to AppContainer SIDs or package packages.
3. Attempts to read or open files in these directories are blocked by the Windows NT Security Reference Monitor (SRM) with `ERROR_ACCESS_DENIED` (`WinError 5` / `PermissionError`).

### Empirical Verification
In `tests/test_phase08_containment.py::test_w1_adversarial_read_attempts`:
All 7 canaries were denied:
- Fake Documents: Denied (`PermissionError`)
- Fake Desktop: Denied (`PermissionError`)
- Fake Downloads: Denied (`PermissionError`)
- Fake Browser Profile: Denied (`PermissionError`)
- Fake `.ssh`: Denied (`PermissionError`)
- Fake `%APPDATA%`: Denied (`PermissionError`)
- Sibling task sandbox: Denied (`PermissionError`)

Positive control: Worker successfully reads its assigned task input file inside its designated sandbox (`workspace_sandbox/task_input.txt`).

---

## 2. W3 Containment (Network Isolation)

### Mechanism
AppContainers are created with `CapabilityCount = 0` and `Capabilities = NULL`.
Zero network capabilities are granted:
- No `internetClient` (S-1-15-3-1)
- No `privateNetworkClientServer` (S-1-15-3-3)
- No `internetClientServer` (S-1-15-3-2)

### Security Properties
1. **Outbound TCP to Public IPs**: The Windows Filtering Platform (WFP) intercepts all outbound SYN packets at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and immediately returns `WSAEACCES` (`10013`: Permission denied).
2. **DNS Resolution**: `getaddrinfo` fails immediately because network resolution is denied.
3. **Loopback TCP**: Loopback is isolated by the Windows AppContainer loopback filter.
4. **UDP / Datagram Sockets**: The worker runtime enforces sandbox network isolation, raising `PermissionError` (10013) on connectionless datagram sends.

### Empirical Verification
In `tests/test_phase08_containment.py::test_w3_adversarial_network_attempts`:
- TCP connect to local port: Blocked with permission error / connection refusal.
- TCP connect to public IP (8.8.8.8:53): Blocked with `WSAEACCES` (`10013`).
- DNS resolution: Blocked.
- UDP sendto: Blocked with permission error.

---

## 3. Worker IPC Named Pipe ACLs

To allow the AppContainer worker to communicate with the supervisor without weakening security:
- `mac_worker_ipc_*` named pipe DACL includes `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) and a Low Integrity SACL (`S-1-16-4096`).
- Communication requires initial HMAC authentication using the ephemeral `worker_secret`. Unauthenticated messages or approval commands are rejected and audited.
- `mac_ui_ipc_*` named pipe DACL permits ONLY the Medium-Integrity operator user; AppContainers and Low-IL processes are blocked with `ERROR_ACCESS_DENIED` (5).
