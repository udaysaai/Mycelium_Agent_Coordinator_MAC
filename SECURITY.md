# Security Policy

## Scope & Prototype Status

Mycelium Agent Coordinator (MAC) is an experimental prototype designed to enforce execution governance, deterministic state verification, and Human-On-The-Loop approval gates over autonomous agent actions.

> [!WARNING]
> **Prototype Notice**: This software is an engineering research prototype. It is **NOT** safe for processing real financial or personal records until external container/VM isolation (Gate C) is complete.

---

## Threat Model & Trust Boundaries

The system architecture splits trust across isolated processes:
1. **Supervisor Daemon**: Medium Integrity process holding the SQLite WAL state database, ephemeral 256-bit CSP HMAC signing key, and policy engine.
2. **Desktop UI (Electron)**: Operator interface connected to the supervisor via authenticated Windows Named Pipes (`\\.\pipe\mac_ui_ipc_<token>`).
3. **Worker Subprocess**: Low Integrity process running in a Windows Job Object with dropped privileges (`DISABLE_MAX_PRIVILEGE`).

### Disclosed Residual Risks (Current Prototype Phase)

- **W1 (Filesystem Read Access)**: Under Windows Mandatory Integrity Control (MIC), Low Integrity processes retain read access to standard user profile directories (Documents, Desktop, Downloads) unless protected by external container boundaries (AppContainer, WSL2, or Docker).
- **W3 (Outbound Network Sockets)**: Low Integrity tokens permit outbound network socket creation on standard Windows editions without network isolation filters.

---

## Reporting a Security Vulnerability

If you discover a security vulnerability or containment bypass in Mycelium Agent Coordinator:
1. Do **NOT** open a public issue.
2. Report the vulnerability privately to the project maintainers via GitHub Private Vulnerability Reporting or via security email.
3. Include detailed reproduction steps, target Windows build, Python version, and proof-of-concept code.
4. Maintainers will acknowledge receipt within 48 hours and provide a timeline for remediation.
