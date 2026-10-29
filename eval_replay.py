#!/usr/bin/env python3
"""
eval_replay.py - Phase 0 Replay & Reliability Evaluation Harness
Executes N iterations (default N=20) of end-to-end workflows in isolated temp workspaces:
  Workflow 1 (T1): Concrete Intake -> Sandboxed Atomic File Writer -> Deterministic Verifier
  Workflow 2 (T2): Quarantined Shell Process -> Isolated UI Approval Channel -> Actuator -> Verifier

Outputs:
  - success count, failure count, unverified count
  - mean / median / p95 latency per stage (Intake, Policy, Execution, Verifier, Total)
  - Failure audit logs
  - JSON results saved to eval_results/phase0_replay.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from coordinator import MyceliumCoordinator
from local_daemon import LocalExecDaemon
from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
    TaskContractStatus,
    TierLevel,
)
from state_store import StateStore


def calc_stats(values: List[float]) -> Dict[str, float]:
    """Compute mean, median, and p95 for a list of latency samples."""
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
    sorted_v = sorted(values)
    n = len(sorted_v)
    p95_idx = min(int(round(0.95 * (n - 1))), n - 1)
    return {
        "mean": round(statistics.mean(values), 3),
        "median": round(statistics.median(values), 3),
        "p95": round(sorted_v[p95_idx], 3),
        "min": round(sorted_v[0], 3),
        "max": round(sorted_v[-1], 3)
    }


def run_t1_workflow_iteration(iter_idx: int) -> Dict[str, Any]:
    """
    Workflow 1 (T1):
    Intake -> Sandboxed File Write -> Out-of-Band Verifier.
    Runs in a completely fresh temporary workspace.
    """
    temp_dir = tempfile.TemporaryDirectory(prefix=f"mac_eval_t1_{iter_idx}_")
    ws_root = Path(temp_dir.name).resolve()
    db_path = ws_root / "data" / "mac_state.db"
    key_path = ws_root / "keys" / "test_key.key"

    daemon = LocalExecDaemon(workspace_root=ws_root)
    store = StateStore(db_path=db_path)
    coord = MyceliumCoordinator(
        local_daemon=daemon,
        state_store=store,
        key_file_path=key_path
    )

    content = f'{{"iteration": {iter_idx}, "status": "active", "timestamp": {time.time()}}}'
    filename = f"eval_metrics_{iter_idx}.json"
    intent = f"create file 'workspace_sandbox/{filename}' with content '{content}'"

    req = ActionRequest(
        intent=intent,
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING_SANDBOX,
        payload={
            "tool_name": "sandboxed_file_writer",
            "file_path": filename,
            "content": content
        }
    )

    t_start = time.perf_counter()
    # 1. Intake Stage
    s1_start = time.perf_counter()
    intake_outcome = coord.intake_gate.evaluate_intent(intent=req.intent, payload=req.payload)
    s1_ms = (time.perf_counter() - s1_start) * 1000.0

    # 2. Policy Stage
    s2_start = time.perf_counter()
    verdict = coord.policy_engine.evaluate(request=req, contract=intake_outcome.contract, tool_name="sandboxed_file_writer")
    s2_ms = (time.perf_counter() - s2_start) * 1000.0

    # 3. Full dispatch through coordinator (Actuator + Verifier)
    res: ExecutionResult = coord.dispatch(req)
    t_total_ms = (time.perf_counter() - t_start) * 1000.0

    # Verifier Receipt Verification
    is_verified = res.receipt is not None and res.receipt.verified is True
    is_success = res.success and is_verified

    failure_reason = None
    if not is_success:
        failure_reason = res.stderr or (res.receipt.verifierNotes if res.receipt else "Unknown failure")

    result = {
        "iteration": iter_idx,
        "type": "T1_WORKFLOW",
        "success": is_success,
        "verified": is_verified,
        "exit_code": res.exitCode,
        "failure_reason": failure_reason,
        "stages_ms": {
            "intake": round(s1_ms, 3),
            "policy": round(s2_ms, 3),
            "total_dispatch": round(res.latencyMs, 3),
            "end_to_end": round(t_total_ms, 3)
        }
    }
    store.close()
    try:
        temp_dir.cleanup()
    except Exception:
        pass
    return result


def run_t2_workflow_iteration(iter_idx: int) -> Dict[str, Any]:
    """
    Workflow 2 (T2):
    Shell execution -> Policy Engine Quarantine -> Supervisor UI Channel Approval -> Execution -> Verifier.
    Approvals are simulated strictly through the isolated UI supervisor confirmation hook.
    """
    temp_dir = tempfile.TemporaryDirectory(prefix=f"mac_eval_t2_{iter_idx}_")
    ws_root = Path(temp_dir.name).resolve()
    db_path = ws_root / "data" / "mac_state.db"
    key_path = ws_root / "keys" / "test_key.key"

    ui_approval_called = False
    ui_approval_latency_ms = 0.0

    def isolated_ui_supervisor_channel(quarantine_event: HOLQuarantineEvent) -> bool:
        """Simulates the human supervisor UI IPC channel authorizing the action."""
        nonlocal ui_approval_called, ui_approval_latency_ms
        t0 = time.perf_counter()
        # Verify quarantine integrity
        assert quarantine_event.quarantineId is not None
        assert quarantine_event.plainImpact != ""
        assert quarantine_event.request.safetyTier in (SafetyTier.MUTATING, SafetyTier.MUTATING_SANDBOX)
        ui_approval_called = True
        ui_approval_latency_ms = (time.perf_counter() - t0) * 1000.0
        return True  # Authorized by UI Supervisor

    daemon = LocalExecDaemon(workspace_root=ws_root)
    store = StateStore(db_path=db_path)
    coord = MyceliumCoordinator(
        local_daemon=daemon,
        state_store=store,
        key_file_path=key_path,
        human_confirmation_hook=isolated_ui_supervisor_channel
    )

    command_str = f"python -c \"import sys; sys.stdout.write('EVAL_RUN_{iter_idx}_OK')\""
    req = ActionRequest(
        intent=f"execute diagnostics command {iter_idx}",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={"command": command_str}
    )

    t_start = time.perf_counter()
    res: ExecutionResult = coord.dispatch(req)
    t_total_ms = (time.perf_counter() - t_start) * 1000.0

    is_verified = res.receipt is not None and res.receipt.verified is True
    is_success = res.success and is_verified and ui_approval_called and ("EVAL_RUN" in res.stdout)

    failure_reason = None
    if not is_success:
        if not ui_approval_called:
            failure_reason = "UI approval channel was not invoked"
        elif not res.success:
            failure_reason = res.stderr or "Coordinator dispatch failed"
        elif not is_verified:
            failure_reason = "Verifier failed to confirm exit code"

    result = {
        "iteration": iter_idx,
        "type": "T2_WORKFLOW",
        "success": is_success,
        "verified": is_verified,
        "ui_channel_invoked": ui_approval_called,
        "exit_code": res.exitCode,
        "failure_reason": failure_reason,
        "stages_ms": {
            "ui_approval": round(ui_approval_latency_ms, 3),
            "total_dispatch": round(res.latencyMs, 3),
            "end_to_end": round(t_total_ms, 3)
        }
    }
    store.close()
    try:
        temp_dir.cleanup()
    except Exception:
        pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 0 Replay and Eval Harness")
    parser.add_argument("--iterations", "-n", type=int, default=20, help="Number of iterations (default 20)")
    parser.add_argument("--output", "-o", type=str, default="eval_results/phase0_replay.json", help="Output path")
    args = parser.parse_args()

    n = args.iterations
    out_file = Path(args.output).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"MYCELIUM PHASE 0 REPLAY & RELIABILITY EVAL HARNESS (N={n})")
    print("=" * 80)
    print(f"Output File: {out_file}\n")

    t1_results: List[Dict[str, Any]] = []
    t2_results: List[Dict[str, Any]] = []

    print(f"[*] Running Workflow 1: T1 Sandboxed File Write (Intake -> Actuator -> Verifier) x {n}...")
    for i in range(1, n + 1):
        r = run_t1_workflow_iteration(i)
        t1_results.append(r)
        status_char = "." if r["success"] else "F"
        print(status_char, end="", flush=True)
    print(" Done.")

    print(f"[*] Running Workflow 2: T2 HOL Quarantine (Intake -> Quarantine -> UI Hook -> Verifier) x {n}...")
    for i in range(1, n + 1):
        r = run_t2_workflow_iteration(i)
        t2_results.append(r)
        status_char = "." if r["success"] else "F"
        print(status_char, end="", flush=True)
    print(" Done.\n")

    # Aggregate T1
    t1_successes = sum(1 for r in t1_results if r["success"])
    t1_unverified = sum(1 for r in t1_results if not r["verified"])
    t1_failures = [r for r in t1_results if not r["success"]]
    t1_intake_latencies = [r["stages_ms"]["intake"] for r in t1_results]
    t1_policy_latencies = [r["stages_ms"]["policy"] for r in t1_results]
    t1_total_latencies = [r["stages_ms"]["total_dispatch"] for r in t1_results]
    t1_e2e_latencies = [r["stages_ms"]["end_to_end"] for r in t1_results]

    # Aggregate T2
    t2_successes = sum(1 for r in t2_results if r["success"])
    t2_unverified = sum(1 for r in t2_results if not r["verified"])
    t2_failures = [r for r in t2_results if not r["success"]]
    t2_ui_latencies = [r["stages_ms"]["ui_approval"] for r in t2_results]
    t2_total_latencies = [r["stages_ms"]["total_dispatch"] for r in t2_results]
    t2_e2e_latencies = [r["stages_ms"]["end_to_end"] for r in t2_results]

    stats_summary = {
        "metadata": {
            "iterations_per_workflow": n,
            "total_runs": n * 2,
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S")
        },
        "workflow_t1_sandboxed_write": {
            "total": n,
            "success_count": t1_successes,
            "failure_count": len(t1_failures),
            "unverified_count": t1_unverified,
            "success_rate_pct": round((t1_successes / n) * 100.0, 2),
            "latencies_ms": {
                "intake_stage": calc_stats(t1_intake_latencies),
                "policy_stage": calc_stats(t1_policy_latencies),
                "coordinator_dispatch": calc_stats(t1_total_latencies),
                "end_to_end": calc_stats(t1_e2e_latencies)
            },
            "failures": t1_failures
        },
        "workflow_t2_quarantine_shell": {
            "total": n,
            "success_count": t2_successes,
            "failure_count": len(t2_failures),
            "unverified_count": t2_unverified,
            "success_rate_pct": round((t2_successes / n) * 100.0, 2),
            "latencies_ms": {
                "ui_channel_approval": calc_stats(t2_ui_latencies),
                "coordinator_dispatch": calc_stats(t2_total_latencies),
                "end_to_end": calc_stats(t2_e2e_latencies)
            },
            "failures": t2_failures
        }
    }

    # Save to JSON
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(stats_summary, f, indent=2)

    # Print Report
    print("=" * 80)
    print("PHASE 0 REPLAY & EVALUATION BENCHMARK SUMMARY")
    print("=" * 80)
    print(f"Workflow 1 (T1 Sandboxed File Write):")
    print(f"  Runs: {n} | Success: {t1_successes} | Failures: {len(t1_failures)} | Unverified: {t1_unverified}")
    print(f"  Intake Latency (ms) : Mean={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['intake_stage']['mean']} | Median={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['intake_stage']['median']} | p95={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['intake_stage']['p95']}")
    print(f"  Policy Latency (ms) : Mean={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['policy_stage']['mean']} | Median={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['policy_stage']['median']} | p95={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['policy_stage']['p95']}")
    print(f"  Total Dispatch (ms) : Mean={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['coordinator_dispatch']['mean']} | Median={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['coordinator_dispatch']['median']} | p95={stats_summary['workflow_t1_sandboxed_write']['latencies_ms']['coordinator_dispatch']['p95']}")
    print()
    print(f"Workflow 2 (T2 Quarantined Shell Process with Isolated UI Approval):")
    print(f"  Runs: {n} | Success: {t2_successes} | Failures: {len(t2_failures)} | Unverified: {t2_unverified}")
    print(f"  UI Hook Latency (ms): Mean={stats_summary['workflow_t2_quarantine_shell']['latencies_ms']['ui_channel_approval']['mean']} | Median={stats_summary['workflow_t2_quarantine_shell']['latencies_ms']['ui_channel_approval']['median']} | p95={stats_summary['workflow_t2_quarantine_shell']['latencies_ms']['ui_channel_approval']['p95']}")
    print(f"  Total Dispatch (ms) : Mean={stats_summary['workflow_t2_quarantine_shell']['latencies_ms']['coordinator_dispatch']['mean']} | Median={stats_summary['workflow_t2_quarantine_shell']['latencies_ms']['coordinator_dispatch']['median']} | p95={stats_summary['workflow_t2_quarantine_shell']['latencies_ms']['coordinator_dispatch']['p95']}")
    print("=" * 80)
    print(f"Results successfully saved to: {out_file}\n")

    return 0 if (t1_successes == n and t2_successes == n) else 1


if __name__ == "__main__":
    sys.exit(main())
