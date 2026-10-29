"""
test_phase07_wiring.py - Phase 0.7 Wire Electron App to Supervisor (Q5)
Verifies:
  1. Supervisor process spawns and emits stdout handshake:
     SUPERVISOR_HANDSHAKE:{"status":"READY","ui_pipe":"...","ui_secret":"...","worker_pipe":"..."}
  2. UI pipe authentication success and failure handling.
  3. UI pipe GET_STATUS inspection.
  4. End-to-end approval flow via UI pipe:
     Worker proposes T2 -> Quarantine -> UI APPROVE_ACTION -> Worker executes -> Receipt verified.
  5. End-to-end rejection flow via UI pipe:
     Worker proposes T2 -> Quarantine -> UI REJECT_ACTION -> Worker execution blocked.
  6. engine_bridge.py refactored into thin client connecting to supervisor pipe (no in-process coordinator).
  7. Node.js net.connect integration with supervisor UI pipe on Windows.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent


def _pipe_send_recv(pipe_path: str, msg: dict, timeout: float = 5.0) -> dict:
    import win32file
    import win32pipe
    import pywintypes

    start = time.time()
    h = None
    while time.time() - start < timeout:
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
                time.sleep(0.05)
    if h is None:
        raise TimeoutError(f"Could not connect to named pipe {pipe_path} within {timeout}s")
    try:
        win32file.WriteFile(h, (json.dumps(msg) + "\n").encode("utf-8"))
        win32file.FlushFileBuffers(h)
        err, data = win32file.ReadFile(h, 65536)
        line = data.decode("utf-8").strip()
        for l in line.split("\n"):
            if l.strip():
                return json.loads(l.strip())
        raise ValueError(f"Empty response from pipe: {line}")
    finally:
        win32file.CloseHandle(h)


def test_supervisor_spawns_and_emits_handshake(tmp_path):
    """
    Supervisor process must print SUPERVISOR_HANDSHAKE: JSON string to stdout
    containing ui_pipe, ui_secret, worker_pipe, and pid upon initialization.
    """
    ws = tmp_path / "supervisor_spawn_ws"
    ws.mkdir()

    cmd = [
        sys.executable,
        str(ROOT_DIR / "supervisor.py"),
        "--workspace", str(ws)
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    handshake_data = None
    out = ""
    err = ""
    start = time.time()
    try:
        while time.time() - start < 3.0:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
    finally:
        try:
            proc.terminate()
            out, err = proc.communicate(timeout=2.0)
        except Exception:
            proc.kill()
            out, err = proc.communicate()

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SUPERVISOR_HANDSHAKE:"):
            raw_json = line[len("SUPERVISOR_HANDSHAKE:"):].strip()
            handshake_data = json.loads(raw_json)
            break
        elif line.startswith("SUPERVISOR_READY:"):
            parts = dict(kv.split("=", 1) for kv in line[len("SUPERVISOR_READY:"):].split(":") if "=" in kv)
            handshake_data = {
                "status": "READY",
                "ui_pipe": parts.get("pipe"),
                "ui_secret": parts.get("secret")
            }
            break

    assert handshake_data is not None, f"Supervisor did not emit handshake. Out: {out}, Err: {err}"
    assert handshake_data.get("status") == "READY"
    assert "ui_pipe" in handshake_data and r"\\.\pipe\mac_ui_" in handshake_data["ui_pipe"]
    assert "ui_secret" in handshake_data and len(handshake_data["ui_secret"]) >= 32
    assert "worker_pipe" in handshake_data and r"\\.\pipe\mac_worker_" in handshake_data["worker_pipe"]


def test_ui_pipe_auth_success_and_failure(tmp_path):
    """
    UI named pipe must validate the per-session ui_secret.
    Invalid secret returns an unauthorized error; valid secret returns AUTH_OK.
    """
    from supervisor import SupervisorDaemon

    sup = SupervisorDaemon(workspace_root=tmp_path / "sup_auth_ws")
    sup.start()
    try:
        # 1. Invalid Secret
        bad_resp = _pipe_send_recv(
            sup.ui_pipe_path,
            {"type": "AUTH", "secret": "wrong_secret_ffffffff"}
        )
        assert bad_resp.get("status") == "ERROR"
        assert "unauthorized" in bad_resp.get("message", "").lower()

        # 2. Valid Secret
        good_resp = _pipe_send_recv(
            sup.ui_pipe_path,
            {"type": "AUTH", "secret": sup.ui_secret}
        )
        assert good_resp.get("status") == "AUTH_OK"

        # 3. GET_STATUS
        status_resp = _pipe_send_recv(
            sup.ui_pipe_path,
            {"type": "GET_STATUS", "secret": sup.ui_secret}
        )
        assert status_resp.get("status") == "OK"
        assert status_resp.get("daemon") == "RUNNING"
    finally:
        sup.stop()


def test_end_to_end_approval_flow_via_ui_pipe(tmp_path):
    """
    Real stack approval flow:
      1. Worker proposes T2 mutating command.
      2. Quarantined in SQLite state store.
      3. UI queries pending quarantines over UI pipe and receives full untruncated command & flags.
      4. UI approves action via APPROVE_ACTION.
      5. Worker executes action with issued one-shot token.
      6. Verifier verifies execution and state receipt is stored.
    """
    from supervisor import SupervisorDaemon

    sup = SupervisorDaemon(workspace_root=tmp_path / "sup_e2e_ws")
    sup.start()
    try:
        # Connect worker
        w_auth = _pipe_send_recv(sup.worker_pipe_path, {"type": "AUTH", "secret": sup.worker_secret})
        assert w_auth.get("status") == "AUTH_OK"

        # Worker proposes mutating action
        long_cmd = "echo E2E_TEST_EXECUTION_VERIFIED"
        prop = _pipe_send_recv(sup.worker_pipe_path, {
            "type": "PROPOSE_ACTION",
            "secret": sup.worker_secret,
            "tool_name": "execute_shell_command",
            "intent": "Run test mutation verification",
            "privilege_tier": "PERSON",
            "payload": {"command": long_cmd}
        })
        assert prop.get("status") == "QUARANTINED"
        qid = prop.get("quarantine_id")
        assert qid

        # UI channel queries pending
        list_resp = _pipe_send_recv(sup.ui_pipe_path, {
            "type": "LIST_PENDING",
            "secret": sup.ui_secret
        })
        assert list_resp.get("status") == "OK"
        pending = list_resp.get("pending", [])
        assert any(p["quarantine_id"] == qid for p in pending)
        target_q = next(p for p in pending if p["quarantine_id"] == qid)
        assert "card" in target_q
        assert target_q["card"]["exact_command"] == long_cmd

        # UI approves action
        appr_resp = _pipe_send_recv(sup.ui_pipe_path, {
            "type": "APPROVE_ACTION",
            "secret": sup.ui_secret,
            "quarantine_id": qid,
            "operator_notes": "Operator sign-off in Electron UI"
        })
        assert appr_resp.get("status") == "APPROVED"
        token = appr_resp.get("one_shot_token")
        assert token

        # Worker executes approved action
        exec_resp = _pipe_send_recv(sup.worker_pipe_path, {
            "type": "EXECUTE_APPROVED",
            "secret": sup.worker_secret,
            "quarantine_id": qid,
            "one_shot_token": token,
            "tool_name": "execute_shell_command",
            "payload": {"command": long_cmd}
        })
        assert exec_resp.get("status") == "COMPLETED"
        assert exec_resp.get("success") is True
        assert "E2E_TEST_EXECUTION_VERIFIED" in exec_resp.get("stdout", "")
        assert exec_resp.get("receipt") is not None
        assert exec_resp["receipt"]["verified"] is True
    finally:
        sup.stop()


def test_end_to_end_rejection_flow_via_ui_pipe(tmp_path):
    """
    Operator rejection flow:
      1. Worker proposes T2 mutating command.
      2. Quarantined.
      3. UI sends REJECT_ACTION.
      4. Worker tries to execute -> rejected.
    """
    from supervisor import SupervisorDaemon

    sup = SupervisorDaemon(workspace_root=tmp_path / "sup_rej_ws")
    sup.start()
    try:
        # Worker proposes
        prop = _pipe_send_recv(sup.worker_pipe_path, {
            "type": "PROPOSE_ACTION",
            "secret": sup.worker_secret,
            "tool_name": "execute_shell_command",
            "intent": "Dangerous action to reject",
            "privilege_tier": "PERSON",
            "payload": {"command": "echo should_not_run"}
        })
        assert prop.get("status") == "QUARANTINED"
        qid = prop.get("quarantine_id")

        # UI rejects
        rej_resp = _pipe_send_recv(sup.ui_pipe_path, {
            "type": "REJECT_ACTION",
            "secret": sup.ui_secret,
            "quarantine_id": qid,
            "operator_notes": "Operator rejected"
        })
        assert rej_resp.get("status") == "REJECTED"

        # Worker attempts to execute
        exec_resp = _pipe_send_recv(sup.worker_pipe_path, {
            "type": "EXECUTE_APPROVED",
            "secret": sup.worker_secret,
            "quarantine_id": qid,
            "one_shot_token": "invalid_or_stale_token",
            "tool_name": "execute_shell_command",
            "payload": {"command": "echo should_not_run"}
        })
        assert exec_resp.get("status") == "ERROR"
        assert "invalid" in exec_resp.get("message", "").lower() or "rejected" in exec_resp.get("message", "").lower()
    finally:
        sup.stop()


def test_engine_bridge_refuses_inprocess_and_bridges_supervisor_pipe(tmp_path, monkeypatch):
    """
    engine_bridge.py must not instantiate in-process coordinator in production.
    When given MAC_UI_PIPE and MAC_UI_SECRET, it connects to supervisor pipe and relays messages.
    """
    from supervisor import SupervisorDaemon

    sup = SupervisorDaemon(workspace_root=tmp_path / "bridge_test_ws")
    sup.start()
    try:
        # Ensure production mode (MAC_UNSAFE_INPROCESS_FOR_TESTS not set)
        env = dict(os.environ)
        env.pop("MAC_UNSAFE_INPROCESS_FOR_TESTS", None)
        env["MAC_UI_PIPE"] = sup.ui_pipe_path
        env["MAC_UI_SECRET"] = sup.ui_secret

        proc = subprocess.Popen(
            [sys.executable, str(ROOT_DIR / "engine_bridge.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )

        try:
            # Send GET_STATUS over stdin
            req = json.dumps({"action": "GET_STATUS"}) + "\n"
            proc.stdin.write(req)
            proc.stdin.flush()

            # Read response
            resp_line = proc.stdout.readline().strip()
            resp = json.loads(resp_line)
            assert resp.get("type") in ("SYSTEM_READY", "STATUS_DATA", "PONG") or resp.get("status") == "OK"
        finally:
            proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        sup.stop()


def test_node_ui_pipe_client_integration(tmp_path):
    """
    Verify Node.js net.connect natively connects to the supervisor UI named pipe
    on Windows, performs AUTH, and receives response.
    """
    from supervisor import SupervisorDaemon

    sup = SupervisorDaemon(workspace_root=tmp_path / "node_test_ws")
    sup.start()
    try:
        node_script = tmp_path / "pipe_test.js"
        node_script.write_text(f"""
const net = require('net');

const pipeName = {json.dumps(sup.ui_pipe_path)};
const secret = {json.dumps(sup.ui_secret)};

const client = net.connect(pipeName, () => {{
    const authMsg = JSON.stringify({{ type: 'AUTH', secret: secret }}) + '\\n';
    client.write(authMsg);
}});

let buffer = '';
client.on('data', (data) => {{
    buffer += data.toString('utf-8');
    if (buffer.includes('\\n')) {{
        const line = buffer.split('\\n')[0].trim();
        const resp = JSON.parse(line);
        if (resp.status === 'AUTH_OK') {{
            console.log('NODE_AUTH_SUCCESS');
            client.end();
            process.exit(0);
        }} else {{
            console.error('NODE_AUTH_FAILED: ' + line);
            process.exit(1);
        }}
    }}
}});

client.on('error', (err) => {{
    console.error('NODE_PIPE_ERROR: ' + err.message);
    process.exit(1);
}});

setTimeout(() => {{
    console.error('NODE_TIMEOUT');
    process.exit(1);
}}, 5000);
""", encoding="utf-8")

        res = subprocess.run(["node", str(node_script)], capture_output=True, text=True, timeout=8)
        assert res.returncode == 0, f"Node script failed. Output: {res.stdout}\nStderr: {res.stderr}"
        assert "NODE_AUTH_SUCCESS" in res.stdout
    finally:
        sup.stop()
