#!/usr/bin/env python3
"""
eval_worker_proc.py - Subprocess Worker for Phase 0.5 Replay Benchmark
Connects across localhost socket IPC to privileged SupervisorDaemon.
Performs T1 and T2 actions on behalf of the agent coordinator.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from typing import Any, Dict


def send_recv(sock: socket.socket, msg: Dict[str, Any]) -> Dict[str, Any]:
    payload = json.dumps(msg) + "\n"
    sock.sendall(payload.encode("utf-8"))
    buffer = ""
    while "\n" not in buffer:
        chunk = sock.recv(65536).decode("utf-8")
        if not chunk:
            raise ConnectionResetError("Connection closed by supervisor.")
        buffer += chunk
    line, _ = buffer.split("\n", 1)
    return json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser(description="Eval Replay Worker Subprocess")
    parser.add_argument("--port", type=int, required=True, help="Supervisor worker port")
    parser.add_argument("--secret", type=str, required=True, help="Worker authentication secret")
    parser.add_argument("--iter-idx", type=int, default=1, help="Iteration index")
    parser.add_argument("--mode", type=str, default="normal", choices=["normal", "kill_before_exec"], help="Execution mode")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", args.port))

    try:
        # 1. AUTH
        auth_resp = send_recv(sock, {
            "type": "AUTH",
            "secret": args.secret
        })
        if auth_resp.get("status") not in ("OK", "AUTHENTICATED"):
            print(json.dumps({"error": f"Worker authentication failed: {auth_resp}"}))
            return 1

        # 2. T1 Sandboxed File Write
        t1_start = time.perf_counter()
        t1_filename = f"eval_worker_{args.iter_idx}.json"
        t1_content = f'{{"iteration": {args.iter_idx}, "worker_pid": {args.iter_idx}}}'
        t1_resp = send_recv(sock, {
            "type": "PROPOSE_ACTION",
            "intent": f"Write eval file {t1_filename}",
            "tool_name": "sandboxed_file_writer",
            "payload": {
                "file_path": t1_filename,
                "content": t1_content
            }
        })
        t1_latency_ms = (time.perf_counter() - t1_start) * 1000.0

        # 3. T2 Quarantined Shell Action
        t2_start = time.perf_counter()
        cmd = f"python -c \"import sys; sys.stdout.write('WORKER_RUN_{args.iter_idx}_OK')\""
        t2_resp = send_recv(sock, {
            "type": "PROPOSE_ACTION",
            "intent": f"Run worker shell command {args.iter_idx}",
            "tool_name": "execute_shell_command",
            "payload": {"command": cmd}
        })
        t2_propose_latency_ms = (time.perf_counter() - t2_start) * 1000.0

        if args.mode == "kill_before_exec":
            # Signal ready for kill
            print(json.dumps({
                "mode": "kill_before_exec",
                "t1": t1_resp,
                "t2_quarantine": t2_resp
            }))
            sys.stdout.flush()
            # Loop until killed by parent
            while True:
                time.sleep(0.1)

        # Output quarantine info for parent UI approval orchestrator
        print(json.dumps({
            "status": "AWAITING_APPROVAL",
            "t1_latency_ms": round(t1_latency_ms, 3),
            "t1_resp": t1_resp,
            "t2_propose_latency_ms": round(t2_propose_latency_ms, 3),
            "t2_resp": t2_resp
        }))
        sys.stdout.flush()

        # Read approval token from parent via stdin
        line = sys.stdin.readline().strip()
        if not line:
            return 1
        approval_data = json.loads(line)
        token = approval_data.get("token", "")
        qid = t2_resp.get("quarantine_id", "")

        # 4. Execute Approved T2
        t2_exec_start = time.perf_counter()
        t2_exec_resp = send_recv(sock, {
            "type": "EXECUTE_APPROVED",
            "quarantine_id": qid,
            "one_shot_token": token,
            "payload": {"command": cmd}
        })
        t2_exec_latency_ms = (time.perf_counter() - t2_exec_start) * 1000.0

        total_worker_latency_ms = (time.perf_counter() - t1_start) * 1000.0

        # Output final result
        print(json.dumps({
            "status": "COMPLETED",
            "t1_latency_ms": round(t1_latency_ms, 3),
            "t1_resp": t1_resp,
            "t2_propose_latency_ms": round(t2_propose_latency_ms, 3),
            "t2_resp": t2_resp,
            "t2_exec_latency_ms": round(t2_exec_latency_ms, 3),
            "t2_exec_resp": t2_exec_resp,
            "total_worker_latency_ms": round(total_worker_latency_ms, 3)
        }))
        sys.stdout.flush()
        return 0

    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
