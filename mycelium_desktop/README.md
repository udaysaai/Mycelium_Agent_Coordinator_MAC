# US Neural - Mycelium Desktop Application

[![Framework: Electron](https://img.shields.io/badge/Framework-Electron%20v44-47848F.svg)](#)
[![Theme: Claude Code / Cursor](https://img.shields.io/badge/Theme-Claude%20Code%20%7C%20Cursor-79c0ff.svg)](#)
[![Security: Native HOL Guard](https://img.shields.io/badge/Security-Native%20HOL%20Guard-d29922.svg)](#)
[![Architecture: Split-Execution](https://img.shields.io/badge/Architecture-Split--Execution-3fb950.svg)](#)

A full-fledged, standalone Desktop Graphical User Interface (GUI) for the **Mycelium Agent Coordinator (MAC)** and **HOL Guard**, inspired by the design aesthetic and ergonomics of **Claude Code Desktop** and **Cursor IDE**.

---

## 🎨 UI & Ergonomics

1. **Left Sidebar (260px)**:
   - **Workspace File Explorer**: Live directory tree with file inspection.
   - **Active Mycelium Mesh Nodes**:
     - Filesystem Sandboxed Daemon (`0.12ms`)
     - Terminal Subshell Daemon (`0.25ms`)
     - Weather Sensor Cluster Node (`0.42ms`)
     - Crypto Telemetry Node (`0.58ms`)
     - Real-time pulsating green ping indicators.
   - **HOL Zero-Trust Policy Status Box**: Live SLA and safety classification telemetry.

2. **Central Workspace & Chat Pane**:
   - Natural language input bar ("*Ask Mycelium to inspect code, run terminal tasks, or edit files...*").
   - Privilege tier toggle: `PERSON (Foreground)` vs `BACKGROUND (Automated)`.
   - Real-time **Claude Code Reasoning Trace Stream** displaying sub-10ms semantic discovery matches.
   - Formatted output blocks with execution status, exit codes, and latency breakdowns.

3. **Bottom Execution & Diff Drawer (Toggleable)**:
   - **Tab 1: Subshell Terminal**: Real live stdout/stderr streams from isolated subprocesses.
   - **Tab 2: Workspace File & Diff Viewer**: Line-numbered code inspections and modification diffs.
   - **Tab 3: HOL Telemetry Audit**: Tabular tracking of all agent requests, safety classifications, and quarantine decisions.

4. **Native Graphical HOL Guard Modal**:
   - In-app glassmorphic modal with pulsing amber-red warning header: `⚠️ HOL Guard: Mutating Action Quarantined`.
   - Displays full risk details: target command/payload, reason, and risk tier.
   - Interactive buttons:
     - `[Authorize & Execute]` (Green glowing primary button)
     - `[Quarantine / Reject]` (Red glowing outline button)
   - The backend Python daemon strictly blocks execution until the operator clicks Authorize in the GUI.

---

## 🚀 Quick Start

### Launch via npm
```bash
cd "D:\US_Neural ai agent\mycelium_desktop"
npm start
```

### Launch via Python Entrypoint
```bash
cd "D:\US_Neural ai agent\Mycelium Agent Coordinator (MAC)"
python desktop_app.py
```
