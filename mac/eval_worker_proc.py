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


class PipeClient:
    def __init__(self, pipe_path: str):
        import time, win32file, win32pipe, pywintypes
        self.pipe_path = pipe_path
        start = time.time()
        self.h = None
        while time.time() - start < 5.0:
            try:
                self.h = win32file.CreateFile(
                    pipe_path,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )
                break
            except pywintypes.error as e:
                if e.winerror == 231:
                    try:
                        win32pipe.WaitNamedPipe(pipe_path, 1000)
                    except Exception:
                        time.sleep(0.05)
                else:
                    raise
        if self.h is None:
            raise TimeoutError(f"Failed to connect to named pipe {pipe_path}")

    def send_recv(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        import win32file
        payload = (json.dumps(msg) + "\n").encode("utf-8")
        win32file.WriteFile(self.h, payload)
        win32file.FlushFileBuffers(self.h)
        err, data = win32file.ReadFile(self.h, 65536)
        line = data.decode("utf-8").strip()
        if "\n" in line:
            line = line.split("\n")[0]
        return json.loads(line)

    def close(self):
        import win32api
        if self.h:
            try:
                win32api.CloseHandle(self.h)
            except Exception:
                pass


class SocketClient:
    def __init__(self, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(("127.0.0.1", port))

    def send_recv(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(msg) + "\n"
        self.sock.sendall(payload.encode("utf-8"))
        buffer = ""
        while "\n" not in buffer:
            chunk = self.sock.recv(65536).decode("utf-8")
            if not chunk:
                raise ConnectionResetError("Connection closed by supervisor.")
            buffer += chunk
        line, _ = buffer.split("\n", 1)
        return json.loads(line)

    def close(self):
        self.sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Eval Replay Worker Subprocess")
    parser.add_argument("--port", type=int, default=None, help="Supervisor worker port")
    parser.add_argument("--pipe", type=str, default=None, help="Supervisor worker named pipe")
    parser.add_argument("--secret", type=str, required=True, help="Worker authentication secret")
    parser.add_argument("--iter-idx", type=int, default=1, help="Iteration index")
    parser.add_argument("--mode", type=str, default="normal", choices=["normal", "kill_before_exec"], help="Execution mode")
    args = parser.parse_args()

    if args.pipe:
        client = PipeClient(args.pipe)
    elif args.port:
        client = SocketClient(args.port)
    else:
        print(json.dumps({"error": "Either --pipe or --port is required"}))
        return 1

    try:
        # 1. AUTH
        auth_resp = client.send_recv({
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
        t1_resp = client.send_recv({
            "type": "PROPOSE_ACTION",
            "secret": args.secret,
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
        t2_resp = client.send_recv({
            "type": "PROPOSE_ACTION",
            "secret": args.secret,
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
        t2_exec_resp = client.send_recv({
            "type": "EXECUTE_APPROVED",
            "secret": args.secret,
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
        client.close()


if __name__ == "__main__":
    sys.exit(main())
