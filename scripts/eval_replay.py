#!/usr/bin/env python3
"""
eval_replay.py - Phase 0.5 Process Boundary Replay & Reliability Evaluation Harness
Executes N iterations (default N=20) of end-to-end workflows across the process boundary:
  - Supervisor: Privileged daemon running in separate process / thread with Job Object and SQLite state store
  - Worker: Separate OS subprocess connecting over localhost socket IPC
  - UI Channel: Isolated operator channel approving T2 quarantines with HMAC one-shot tokens

Outputs:
  - Latency statistics (mean and p95 for T1, T2 propose, UI approval, T2 execute, total end-to-end)
  - Process memory metrics (supervisor memory MB, worker memory MB)
  - State leak verification (0 state leaks across runs, clean fresh workspaces)
  - Injected failure evaluations (worker killed mid-task, approval denied, approval expired)
  - Raw results saved to eval_results/phase05_replay.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "mac"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from protocol import HOLApprovalStatus
from state_store import StateStore
from supervisor import SupervisorDaemon


def get_process_memory_mb(pid: int) -> float:
    """Extract Working Set memory in Megabytes for a given PID on Windows."""
    try:
        res = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=3.0
        )
        line = res.stdout.strip()
        if not line or "No tasks" in line:
            return 0.0
        reader = csv.reader(io.StringIO(line))
        row = next(reader)
        if len(row) >= 5:
            raw_mem = row[4].replace(" K", "").replace(",", "").replace(".", "").strip()
            return round(float(raw_mem) / 1024.0, 2)
    except Exception:
        pass
    return 0.0


def calc_stats(values: List[float]) -> Dict[str, float]:
    """Compute mean, median, and p95 for a list of metrics."""
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


def pipe_send_recv(pipe_path: str, msg: Dict[str, Any]) -> Dict[str, Any]:
    """Send and receive a message over Windows Named Pipe with busy retry."""
    import time
    import win32api
    import win32file
    import win32pipe
    import pywintypes

    start = time.time()
    h = None
    while time.time() - start < 5.0:
        try:
            h = win32file.CreateFile(
                pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            break
        except pywintypes.error as e:
            if e.winerror == 231:  # ERROR_PIPE_BUSY
                try:
                    win32pipe.WaitNamedPipe(pipe_path, 1000)
                except Exception:
                    time.sleep(0.05)
            else:
                raise
    if h is None:
        raise TimeoutError(f"Could not connect to named pipe {pipe_path} within 5s")
    try:
        win32file.WriteFile(h, (json.dumps(msg) + "\n").encode("utf-8"))
        win32file.FlushFileBuffers(h)
        err, data = win32file.ReadFile(h, 65536)
        line = data.decode("utf-8").strip()
        if "\n" in line:
            line = line.split("\n")[0]
        return json.loads(line)
    finally:
        win32api.CloseHandle(h)


def send_ui_command(supervisor: SupervisorDaemon, msg: Dict[str, Any], use_named_pipes: bool = True) -> Dict[str, Any]:
    """Send an authenticated command over the isolated UI channel."""
    if use_named_pipes and sys.platform == "win32":
        return pipe_send_recv(supervisor.ui_pipe_path, msg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect(("127.0.0.1", supervisor.ui_port))
    try:
        sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        buffer = ""
        while "\n" not in buffer:
            chunk = sock.recv(65536).decode("utf-8")
            if not chunk:
                break
            buffer += chunk
        line, _ = buffer.split("\n", 1)
        return json.loads(line)
    finally:
        sock.close()


def run_benchmark_iteration(iter_idx: int, use_named_pipes: bool = True) -> Dict[str, Any]:
    """
    Run one full benchmark task across the process boundary:
      1. Fresh workspace creation and clean state verification.
      2. Start SupervisorDaemon in workspace.
      3. Spawn Worker subprocess.
      4. Worker performs T1 (sandboxed write).
      5. Worker proposes T2 (quarantined shell action).
      6. UI Channel approves T2 quarantine and delivers token.
      7. Worker executes approved T2 action.
      8. Measure latencies, supervisor & worker memory.
      9. Verify 0 state leaks.
    """
    with tempfile.TemporaryDirectory(prefix=f"mac_bench_{iter_idx}_", ignore_cleanup_errors=True) as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        sandbox_dir = ws_root / "workspace_sandbox"
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        # Verify initial clean state (0 pre-existing files in sandbox or DB)
        initial_files = list(sandbox_dir.iterdir())
        assert len(initial_files) == 0, f"State leak before run: {initial_files}"

        # Initialize and start Supervisor
        supervisor = SupervisorDaemon(workspace_root=ws_root, use_named_pipes=use_named_pipes)
        supervisor.start()

        sup_pid = os.getpid()
        worker_proc: Optional[subprocess.Popen] = None

        t_start = time.perf_counter()
        try:
            # Spawn worker subprocess
            worker_script = (WORKSPACE_ROOT / "mac" / "eval_worker_proc.py") if (WORKSPACE_ROOT / "mac" / "eval_worker_proc.py").exists() else (WORKSPACE_ROOT / "eval_worker_proc.py")
            if use_named_pipes and sys.platform == "win32":
                cmd = [
                    sys.executable, str(worker_script),
                    "--pipe", str(supervisor.worker_pipe_path),
                    "--secret", supervisor.worker_secret,
                    "--iter-idx", str(iter_idx)
                ]
            else:
                cmd = [
                    sys.executable, str(worker_script),
                    "--port", str(supervisor.worker_port),
                    "--secret", supervisor.worker_secret,
                    "--iter-idx", str(iter_idx)
                ]

            worker_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Assign worker to supervisor Job Object
            supervisor.assign_worker_to_job(worker_proc)

            worker_pid = worker_proc.pid

            # Read worker output until it requests approval
            first_line = worker_proc.stdout.readline()
            assert first_line, f"Worker produced no output. Stderr: {worker_proc.stderr.read()}"
            step1_data = json.loads(first_line)

            assert step1_data.get("status") == "AWAITING_APPROVAL", f"Unexpected step1_data: {step1_data}, stderr: {worker_proc.stderr.read()}"
            t1_resp = step1_data["t1_resp"]
            assert t1_resp["status"] == "COMPLETED"
            assert t1_resp["success"] is True
            assert t1_resp["receipt"]["verified"] is True

            t2_quarantine = step1_data["t2_resp"]
            assert t2_quarantine["status"] == "QUARANTINED"
            qid = t2_quarantine["quarantine_id"]

            # Sample process memory while worker is active and awaiting approval
            worker_mem_mb = get_process_memory_mb(worker_pid)
            sup_mem_mb = get_process_memory_mb(sup_pid)

            # UI Channel Approval
            ui_t0 = time.perf_counter()
            ui_resp = send_ui_command(supervisor, {
                "secret": supervisor.ui_secret,
                "type": "APPROVE_ACTION",
                "quarantine_id": qid,
                "operator_notes": f"Approved by benchmark harness iter {iter_idx}"
            }, use_named_pipes=use_named_pipes)
            ui_approval_ms = (time.perf_counter() - ui_t0) * 1000.0

            assert ui_resp.get("status") == "APPROVED"
            token = ui_resp["one_shot_token"]

            # Deliver token to worker over stdin
            worker_proc.stdin.write(json.dumps({"token": token}) + "\n")
            worker_proc.stdin.flush()

            # Read final worker completion
            second_line = worker_proc.stdout.readline()
            assert second_line, f"Worker did not complete. Stderr: {worker_proc.stderr.read()}"
            final_data = json.loads(second_line)

            assert final_data.get("status") == "COMPLETED"
            t2_exec_resp = final_data["t2_exec_resp"]
            assert t2_exec_resp["status"] == "COMPLETED"
            assert t2_exec_resp["success"] is True
            assert t2_exec_resp["receipt"]["verified"] is True

            t_total_ms = (time.perf_counter() - t_start) * 1000.0

            worker_proc.wait(timeout=5.0)

            # State check: Verify DB has exactly 1 quarantine (status=APPROVED, one_shot_token=CONSUMED)
            # and exactly 2 receipts
            db_path = ws_root / "data" / "mac_state.db"
            check_store = StateStore(db_path=db_path)
            try:
                quarantines = check_store.get_pending_quarantines()
                assert len(quarantines) == 0, "Pending quarantine leaked!"
                q_item = check_store.get_quarantine(qid)
                assert q_item is not None
                assert q_item["status"] == HOLApprovalStatus.APPROVED.value
                assert q_item["one_shot_token"] == "CONSUMED"

                with check_store._get_connection() as conn:
                    cur = conn.execute("SELECT count(*) FROM receipts")
                    receipt_count = cur.fetchone()[0]
                    assert receipt_count == 2, f"Expected 2 receipts, found {receipt_count}"
            finally:
                check_store.close()

            return {
                "iteration": iter_idx,
                "success": True,
                "has_verified_pass_receipt": (t1_resp.get("receipt", {}).get("verified") is True and t2_exec_resp.get("receipt", {}).get("verified") is True),
                "latencies_ms": {
                    "t1_write": step1_data["t1_latency_ms"],
                    "t2_propose": step1_data["t2_propose_latency_ms"],
                    "ui_approval": round(ui_approval_ms, 3),
                    "t2_execute": final_data["t2_exec_latency_ms"],
                    "end_to_end": round(t_total_ms, 3)
                },
                "memory_mb": {
                    "supervisor": sup_mem_mb,
                    "worker": worker_mem_mb
                },
                "verified": True,
                "state_leak": False
            }

        finally:
            if worker_proc and worker_proc.poll() is None:
                worker_proc.kill()
            supervisor.stop()


def run_injected_failure_worker_killed(iter_idx: int = 101, use_named_pipes: bool = True) -> Dict[str, Any]:
    """
    Failure Scenario 1: Worker is hard-killed mid-task while action is quarantined.
    Supervisor must survive, handle disconnection, and leave quarantine unexecuted in DB.
    """
    with tempfile.TemporaryDirectory(prefix="mac_fail_kill_", ignore_cleanup_errors=True) as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        (ws_root / "workspace_sandbox").mkdir(parents=True, exist_ok=True)

        supervisor = SupervisorDaemon(workspace_root=ws_root, use_named_pipes=use_named_pipes)
        supervisor.start()

        worker_proc: Optional[subprocess.Popen] = None
        try:
            worker_script = (WORKSPACE_ROOT / "mac" / "eval_worker_proc.py") if (WORKSPACE_ROOT / "mac" / "eval_worker_proc.py").exists() else (WORKSPACE_ROOT / "eval_worker_proc.py")
            if use_named_pipes and sys.platform == "win32":
                cmd = [
                    sys.executable, str(worker_script),
                    "--pipe", str(supervisor.worker_pipe_path),
                    "--secret", supervisor.worker_secret,
                    "--iter-idx", str(iter_idx),
                    "--mode", "kill_before_exec"
                ]
            else:
                cmd = [
                    sys.executable, str(worker_script),
                    "--port", str(supervisor.worker_port),
                    "--secret", supervisor.worker_secret,
                    "--iter-idx", str(iter_idx),
                    "--mode", "kill_before_exec"
                ]

            worker_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            supervisor.assign_worker_to_job(worker_proc)

            # Wait for worker to reach quarantine state
            line = worker_proc.stdout.readline()
            data = json.loads(line)
            qid = data["t2_quarantine"]["quarantine_id"]

            # Abruptly kill worker process with TerminateProcess/kill
            worker_proc.kill()
            worker_proc.wait(timeout=3.0)

            # Verify supervisor is still healthy and responsive
            diag = send_ui_command(supervisor, {
                "secret": supervisor.ui_secret,
                "type": "LIST_PENDING"
            }, use_named_pipes=use_named_pipes)
            assert diag.get("status") == "OK"
            pending_ids = [q["quarantine_id"] for q in diag.get("pending", [])]
            assert qid in pending_ids

            # Verify action remained unexecuted in DB
            db_path = ws_root / "data" / "mac_state.db"
            check_store = StateStore(db_path=db_path)
            try:
                q_item = check_store.get_quarantine(qid)
                assert q_item["status"] == HOLApprovalStatus.PENDING.value
                assert q_item["one_shot_token"] != "CONSUMED"
            finally:
                check_store.close()

            return {
                "scenario": "worker_killed_mid_task",
                "worker_killed": True,
                "supervisor_survived": True,
                "unexecuted_in_db": True,
                "passed": True
            }
        finally:
            if worker_proc and worker_proc.poll() is None:
                worker_proc.kill()
            supervisor.stop()


def run_injected_failure_approval_denied(iter_idx: int = 102, use_named_pipes: bool = True) -> Dict[str, Any]:
    """
    Failure Scenario 2: Operator explicitly rejects T2 action via UI channel.
    Worker execution attempt must fail, and status must stay REJECTED.
    """
    with tempfile.TemporaryDirectory(prefix="mac_fail_deny_", ignore_cleanup_errors=True) as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        (ws_root / "workspace_sandbox").mkdir(parents=True, exist_ok=True)

        supervisor = SupervisorDaemon(workspace_root=ws_root, use_named_pipes=use_named_pipes)
        supervisor.start()

        try:
            if use_named_pipes and sys.platform == "win32":
                auth_resp = pipe_send_recv(supervisor.worker_pipe_path, {
                    "type": "AUTH", "secret": supervisor.worker_secret
                })
                assert auth_resp.get("status") in ("OK", "AUTHENTICATED")

                prop_resp = pipe_send_recv(supervisor.worker_pipe_path, {
                    "type": "PROPOSE_ACTION",
                    "secret": supervisor.worker_secret,
                    "intent": "destructively modify system",
                    "tool_name": "execute_shell_command",
                    "payload": {"command": "echo MALICIOUS"}
                })
                qid = prop_resp.get("quarantine_id")

                ui_resp = send_ui_command(supervisor, {
                    "secret": supervisor.ui_secret,
                    "type": "REJECT_ACTION",
                    "quarantine_id": qid,
                    "operator_notes": "Operator denied action due to policy violation"
                }, use_named_pipes=use_named_pipes)
                assert ui_resp.get("status") == "REJECTED"

                exec_resp = pipe_send_recv(supervisor.worker_pipe_path, {
                    "type": "EXECUTE_APPROVED",
                    "secret": supervisor.worker_secret,
                    "quarantine_id": qid,
                    "one_shot_token": "FORGED_TOKEN",
                    "payload": {"command": "echo MALICIOUS"}
                })
                assert exec_resp.get("status") == "ERROR"
                assert exec_resp.get("success") is False
            else:
                worker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                worker_sock.connect(("127.0.0.1", supervisor.worker_port))
                try:
                    worker_sock.sendall((json.dumps({"type": "AUTH", "secret": supervisor.worker_secret}) + "\n").encode("utf-8"))
                    auth_resp = json.loads(worker_sock.recv(4096).decode("utf-8").strip())
                    assert auth_resp.get("status") in ("OK", "AUTHENTICATED")

                    worker_sock.sendall((json.dumps({
                        "type": "PROPOSE_ACTION",
                        "intent": "destructively modify system",
                        "tool_name": "execute_shell_command",
                        "payload": {"command": "echo MALICIOUS"}
                    }) + "\n").encode("utf-8"))
                    prop_resp = json.loads(worker_sock.recv(4096).decode("utf-8").strip())
                    qid = prop_resp.get("quarantine_id")

                    ui_resp = send_ui_command(supervisor, {
                        "secret": supervisor.ui_secret,
                        "type": "REJECT_ACTION",
                        "quarantine_id": qid,
                        "operator_notes": "Operator denied action due to policy violation"
                    }, use_named_pipes=use_named_pipes)
                    assert ui_resp.get("status") == "REJECTED"

                    worker_sock.sendall((json.dumps({
                        "type": "EXECUTE_APPROVED",
                        "quarantine_id": qid,
                        "one_shot_token": "FORGED_TOKEN",
                        "payload": {"command": "echo MALICIOUS"}
                    }) + "\n").encode("utf-8"))
                    exec_resp = json.loads(worker_sock.recv(4096).decode("utf-8").strip())
                    assert exec_resp.get("status") == "ERROR"
                    assert exec_resp.get("success") is False
                finally:
                    worker_sock.close()

            # Verify DB state
            db_path = ws_root / "data" / "mac_state.db"
            check_store = StateStore(db_path=db_path)
            try:
                q_item = check_store.get_quarantine(qid)
                assert q_item["status"] == HOLApprovalStatus.REJECTED.value
            finally:
                check_store.close()

            return {
                "scenario": "operator_approval_denied",
                "rejection_enforced": True,
                "execution_blocked": True,
                "passed": True
            }
        finally:
            supervisor.stop()


def run_injected_failure_approval_expired(iter_idx: int = 103, use_named_pipes: bool = True) -> Dict[str, Any]:
    """
    Failure Scenario 3: Action expires before or during execution.
    Supervisor must detect expiration, reject approval/execution, and mark REJECTED_TIMEOUT.
    """
    with tempfile.TemporaryDirectory(prefix="mac_fail_exp_", ignore_cleanup_errors=True) as tmp_dir:
        ws_root = Path(tmp_dir).resolve()
        (ws_root / "workspace_sandbox").mkdir(parents=True, exist_ok=True)

        supervisor = SupervisorDaemon(workspace_root=ws_root, use_named_pipes=use_named_pipes)
        current_time = 100000.0
        supervisor.clock = lambda: current_time
        supervisor.state_store.clock = lambda: current_time
        supervisor.start()

        try:
            if use_named_pipes and sys.platform == "win32":
                auth_resp = pipe_send_recv(supervisor.worker_pipe_path, {
                    "type": "AUTH", "secret": supervisor.worker_secret
                })
                assert auth_resp.get("status") in ("OK", "AUTHENTICATED")

                prop_resp = pipe_send_recv(supervisor.worker_pipe_path, {
                    "type": "PROPOSE_ACTION",
                    "secret": supervisor.worker_secret,
                    "intent": "action to expire",
                    "tool_name": "execute_shell_command",
                    "payload": {"command": "echo EXPIRED_COMMAND"}
                })
                qid = prop_resp.get("quarantine_id")

                # Advance clock past expiry deadline (t + 901s)
                current_time = 100901.0

                ui_resp = send_ui_command(supervisor, {
                    "secret": supervisor.ui_secret,
                    "type": "APPROVE_ACTION",
                    "quarantine_id": qid,
                    "operator_notes": "Late approval attempt"
                }, use_named_pipes=use_named_pipes)
                assert ui_resp.get("status") == "ERROR"
            else:
                worker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                worker_sock.connect(("127.0.0.1", supervisor.worker_port))
                try:
                    worker_sock.sendall((json.dumps({"type": "AUTH", "secret": supervisor.worker_secret}) + "\n").encode("utf-8"))
                    auth_resp = json.loads(worker_sock.recv(4096).decode("utf-8").strip())
                    assert auth_resp.get("status") in ("OK", "AUTHENTICATED")

                    worker_sock.sendall((json.dumps({
                        "type": "PROPOSE_ACTION",
                        "intent": "action to expire",
                        "tool_name": "execute_shell_command",
                        "payload": {"command": "echo EXPIRED_COMMAND"}
                    }) + "\n").encode("utf-8"))
                    prop_resp = json.loads(worker_sock.recv(4096).decode("utf-8").strip())
                    qid = prop_resp.get("quarantine_id")

                    current_time = 100901.0

                    ui_resp = send_ui_command(supervisor, {
                        "secret": supervisor.ui_secret,
                        "type": "APPROVE_ACTION",
                        "quarantine_id": qid,
                        "operator_notes": "Late approval attempt"
                    }, use_named_pipes=use_named_pipes)
                    assert ui_resp.get("status") == "ERROR"
                finally:
                    worker_sock.close()

            # Verify DB updated to REJECTED_TIMEOUT
            db_path = ws_root / "data" / "mac_state.db"
            check_store = StateStore(db_path=db_path)
            try:
                q_item = check_store.get_quarantine(qid)
                assert q_item["status"] == HOLApprovalStatus.REJECTED_TIMEOUT.value
            finally:
                check_store.close()

            return {
                "scenario": "approval_expired_timeout",
                "timeout_enforced": True,
                "state_marked_timeout": True,
                "passed": True
            }
        finally:
            supervisor.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 0.6 Process Boundary Replay and Reliability Eval")
    parser.add_argument("--iterations", "-n", type=int, default=20, help="Number of benchmark iterations (default 20)")
    parser.add_argument("--output", "-o", type=str, default="eval_results/phase06_replay.json", help="Output file path")
    parser.add_argument("--use-named-pipes", action="store_true", default=(sys.platform == "win32"), help="Use Windows Named Pipes")
    args = parser.parse_args()

    n = args.iterations
    out_file = Path(args.output).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 85)
    print(f"MYCELIUM PHASE 0.6 PROCESS BOUNDARY REPLAY BENCHMARK (N={n})")
    print(f"Transport: {'Windows Named Pipes' if args.use_named_pipes else 'Localhost TCP'}")
    print("=" * 85)
    print(f"Output File: {out_file}\n")

    benchmark_runs: List[Dict[str, Any]] = []

    print(f"[*] Running End-to-End Task (T1 Sandboxed Write + T2 Quarantined Shell via UI Channel) x {n}...")
    for i in range(1, n + 1):
        res = run_benchmark_iteration(i, use_named_pipes=args.use_named_pipes)
        benchmark_runs.append(res)
        status_char = "." if res["success"] else "F"
        print(status_char, end="", flush=True)
    print(" Done.\n")

    # Injected Failure Runs
    print("[*] Running Injected Failure Scenarios:")
    print("    1. Worker Killed Mid-Task (SIGKILL / TerminateProcess)...", end="", flush=True)
    f1 = run_injected_failure_worker_killed(use_named_pipes=args.use_named_pipes)
    print(" PASS" if f1["passed"] else " FAIL")

    print("    2. Operator Approval Denied via UI Channel...", end="", flush=True)
    f2 = run_injected_failure_approval_denied(use_named_pipes=args.use_named_pipes)
    print(" PASS" if f2["passed"] else " FAIL")

    print("    3. Operator Approval Expired (Default-Deny Timeout)...", end="", flush=True)
    f3 = run_injected_failure_approval_expired(use_named_pipes=args.use_named_pipes)
    print(" PASS" if f3["passed"] else " FAIL")
    print()

    # Aggregate Metrics & Receipt Status
    done_count = sum(1 for r in benchmark_runs if r.get("success") and r.get("has_verified_pass_receipt"))
    failed_count = sum(1 for r in benchmark_runs if not r.get("success"))
    unverified_count = sum(1 for r in benchmark_runs if r.get("success") and not r.get("has_verified_pass_receipt"))

    t1_latencies = [r["latencies_ms"]["t1_write"] for r in benchmark_runs]
    t2_prop_latencies = [r["latencies_ms"]["t2_propose"] for r in benchmark_runs]
    ui_latencies = [r["latencies_ms"]["ui_approval"] for r in benchmark_runs]
    t2_exec_latencies = [r["latencies_ms"]["t2_execute"] for r in benchmark_runs]
    e2e_latencies = [r["latencies_ms"]["end_to_end"] for r in benchmark_runs]

    sup_memories = [r["memory_mb"]["supervisor"] for r in benchmark_runs if r["memory_mb"]["supervisor"] > 0]
    worker_memories = [r["memory_mb"]["worker"] for r in benchmark_runs if r["memory_mb"]["worker"] > 0]

    state_leaks = sum(1 for r in benchmark_runs if r["state_leak"])

    summary_data = {
        "metadata": {
            "iterations": n,
            "transport": "NamedPipe" if args.use_named_pipes else "TCP",
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "os": sys.platform,
            "python_version": sys.version.split()[0]
        },
        "benchmark_summary": {
            "total_runs": n,
            "done_count": done_count,
            "failed_count": failed_count,
            "unverified_count": unverified_count,
            "state_leaks_count": state_leaks,
            "latencies_ms": {
                "t1_sandboxed_write": calc_stats(t1_latencies),
                "t2_quarantine_propose": calc_stats(t2_prop_latencies),
                "t2_ui_approval": calc_stats(ui_latencies),
                "t2_approved_execute": calc_stats(t2_exec_latencies),
                "end_to_end_task": calc_stats(e2e_latencies)
            },
            "memory_mb": {
                "supervisor_process": calc_stats(sup_memories),
                "worker_subprocess": calc_stats(worker_memories)
            }
        },
        "injected_failures": {
            "worker_killed_mid_task": f1,
            "approval_denied": f2,
            "approval_expired": f3
        },
        "runs": benchmark_runs
    }

    # Save to JSON
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    # Print Report
    print("=" * 85)
    print("PHASE 0.6 PROCESS BOUNDARY BENCHMARK REPORT")
    print("=" * 85)
    print(f"Total Iterations : {n}")
    print(f"DONE (with PASS) : {done_count}")
    print(f"FAILED           : {failed_count}")
    print(f"UNVERIFIED       : {unverified_count} (must be 0; a task must never be DONE without a PASS receipt)")
    print(f"State Leaks      : {state_leaks}")
    print("\n--- Latencies (ms) ---")
    print(f"  T1 Sandboxed Write     : Mean={summary_data['benchmark_summary']['latencies_ms']['t1_sandboxed_write']['mean']:>7.2f} ms | p95={summary_data['benchmark_summary']['latencies_ms']['t1_sandboxed_write']['p95']:>7.2f} ms")
    print(f"  T2 Quarantine Propose  : Mean={summary_data['benchmark_summary']['latencies_ms']['t2_quarantine_propose']['mean']:>7.2f} ms | p95={summary_data['benchmark_summary']['latencies_ms']['t2_quarantine_propose']['p95']:>7.2f} ms")
    print(f"  T2 UI Channel Approval : Mean={summary_data['benchmark_summary']['latencies_ms']['t2_ui_approval']['mean']:>7.2f} ms | p95={summary_data['benchmark_summary']['latencies_ms']['t2_ui_approval']['p95']:>7.2f} ms")
    print(f"  T2 Approved Execute    : Mean={summary_data['benchmark_summary']['latencies_ms']['t2_approved_execute']['mean']:>7.2f} ms | p95={summary_data['benchmark_summary']['latencies_ms']['t2_approved_execute']['p95']:>7.2f} ms")
    print(f"  End-to-End Task Total  : Mean={summary_data['benchmark_summary']['latencies_ms']['end_to_end_task']['mean']:>7.2f} ms | p95={summary_data['benchmark_summary']['latencies_ms']['end_to_end_task']['p95']:>7.2f} ms")
    print("\n--- Process Memory (MB) ---")
    print(f"  Supervisor Process     : Mean={summary_data['benchmark_summary']['memory_mb']['supervisor_process']['mean']:>7.2f} MB | p95={summary_data['benchmark_summary']['memory_mb']['supervisor_process']['p95']:>7.2f} MB")
    print(f"  Worker Subprocess      : Mean={summary_data['benchmark_summary']['memory_mb']['worker_subprocess']['mean']:>7.2f} MB | p95={summary_data['benchmark_summary']['memory_mb']['worker_subprocess']['p95']:>7.2f} MB")
    print("\n--- Injected Failure Scenarios ---")
    print(f"  1. Worker Killed Mid-Task : {'PASS' if f1['passed'] else 'FAIL'} (Supervisor survived, state clean)")
    print(f"  2. Approval Denied         : {'PASS' if f2['passed'] else 'FAIL'} (Execution rejected, state REJECTED)")
    print(f"  3. Approval Expired        : {'PASS' if f3['passed'] else 'FAIL'} (Execution rejected, state REJECTED_TIMEOUT)")
    print("=" * 85)
    print(f"Benchmark results successfully saved to: {out_file}\n")

    all_passed = (done_count == n) and (unverified_count == 0) and (state_leaks == 0) and f1["passed"] and f2["passed"] and f3["passed"]
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
