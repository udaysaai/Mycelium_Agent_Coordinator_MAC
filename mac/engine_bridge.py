"""
US Neural - Mycelium Desktop Engine Bridge
Module: engine_bridge.py
Description: Thin client bridge connecting Electron Main process to the privileged
             SupervisorDaemon over authenticated Windows Named Pipe IPC.
             Does NOT import or instantiate MyceliumCoordinator in-process.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent


class PipeClient:
    """Synchronous helper to send and receive over a Windows Named Pipe."""

    def __init__(self, pipe_path: str, secret: str):
        self.pipe_path = pipe_path
        self.secret = secret

    def send_recv(self, msg: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        import win32file
        import win32pipe
        import pywintypes

        msg_with_secret = dict(msg)
        msg_with_secret.setdefault("secret", self.secret)

        start = time.time()
        h = None
        while time.time() - start < timeout:
            try:
                h = win32file.CreateFile(
                    self.pipe_path,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )
                break
            except pywintypes.error as e:
                if e.winerror == 231:  # ERROR_PIPE_BUSY
                    try:
                        win32pipe.WaitNamedPipe(self.pipe_path, 1000)
                    except Exception:
                        time.sleep(0.05)
                else:
                    time.sleep(0.05)

        if h is None:
            raise TimeoutError(f"Supervisor daemon not reachable on pipe: {self.pipe_path}")

        try:
            line_bytes = (json.dumps(msg_with_secret) + "\n").encode("utf-8")
            win32file.WriteFile(h, line_bytes)
            win32file.FlushFileBuffers(h)
            err, data = win32file.ReadFile(h, 65536)
            resp_str = data.decode("utf-8").strip()
            for l in resp_str.split("\n"):
                if l.strip():
                    return json.loads(l.strip())
            return {"status": "ERROR", "message": "Empty response from supervisor pipe."}
        finally:
            try:
                win32file.CloseHandle(h)
            except Exception:
                pass


class EngineBridge:
    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        pipe_path: Optional[str] = None,
        ui_secret: Optional[str] = None
    ):
        self.workspace_root = workspace_root or ((BASE_DIR.parent / "workspace_sandbox").resolve() if (BASE_DIR.parent / "workspace_sandbox").exists() else (BASE_DIR / "workspace_sandbox").resolve())
        self.workspace_root.mkdir(parents=True, exist_ok=True)

        self.pipe_path = pipe_path or os.environ.get("MAC_UI_PIPE") or ""
        self.ui_secret = ui_secret or os.environ.get("MAC_UI_SECRET") or ""

        self.pipe_client: Optional[PipeClient] = None
        if self.pipe_path and self.ui_secret:
            self.pipe_client = PipeClient(self.pipe_path, self.ui_secret)

    def _send_message(self, message: Dict[str, Any]) -> None:
        """Write JSON message to stdout terminated by newline."""
        line = json.dumps(message)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    def get_workspace_tree(self) -> Dict[str, Any]:
        """Recursively scan workspace directory to produce tree structure."""
        def scan(p: Path) -> Dict[str, Any]:
            rel = str(p.relative_to(self.workspace_root)).replace("\\", "/")
            if rel == ".":
                rel = ""
            if p.is_dir():
                children = []
                try:
                    for child in sorted(p.iterdir(), key=lambda c: (not c.is_dir(), c.name.lower())):
                        if child.name.startswith((".git", "__pycache__", ".pytest")):
                            continue
                        children.append(scan(child))
                except PermissionError:
                    pass
                return {
                    "name": p.name or "workspace",
                    "path": rel,
                    "isDir": True,
                    "children": children
                }
            else:
                return {
                    "name": p.name,
                    "path": rel,
                    "isDir": False,
                    "size": p.stat().st_size
                }

        return scan(self.workspace_root)

    def get_mesh_nodes(self) -> List[Dict[str, Any]]:
        return [
            {"id": "node-supervisor", "name": "Privileged Supervisor Daemon", "type": "SUPERVISOR_CORE", "status": "ONLINE", "pingMs": 0.05},
            {"id": "node-fs", "name": "Filesystem Sandboxed Daemon", "type": "LOCAL_EXEC", "status": "ONLINE", "pingMs": 0.12},
            {"id": "node-shell", "name": "Terminal Subshell Daemon", "type": "ISOLATED_PROC", "status": "ONLINE", "pingMs": 0.25},
            {"id": "node-verifier", "name": "Deterministic Verifier Node", "type": "OUT_OF_BAND_VERIFIER", "status": "ONLINE", "pingMs": 0.08},
        ]

    def run_stdio_loop(self) -> None:
        """Main stdio JSON-RPC listening loop."""
        # Initial system ready handshake
        self._send_message({
            "type": "SYSTEM_READY",
            "version": "1.1.0",
            "workspace": str(self.workspace_root),
            "meshNodes": self.get_mesh_nodes(),
            "supervisorConnected": bool(self.pipe_client)
        })

        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                msg_type = msg.get("action") or msg.get("type") or ""

                if msg_type == "PING":
                    self._send_message({"type": "PONG", "timestamp": time.time()})

                elif msg_type == "GET_STATUS":
                    if self.pipe_client:
                        try:
                            status_resp = self.pipe_client.send_recv({"type": "GET_STATUS"})
                            self._send_message({
                                "type": "STATUS_DATA",
                                "status": "OK",
                                "supervisor": status_resp
                            })
                        except Exception as e:
                            self._send_message({
                                "type": "STATUS_DATA",
                                "status": "ERROR",
                                "error": str(e)
                            })
                    else:
                        self._send_message({
                            "type": "STATUS_DATA",
                            "status": "OK",
                            "supervisor": "STANDALONE_OR_DIRECT"
                        })

                elif msg_type == "GET_WORKSPACE_TREE":
                    tree = self.get_workspace_tree()
                    self._send_message({"type": "WORKSPACE_TREE_DATA", "tree": tree})

                elif msg_type == "GET_MESH_NODES":
                    nodes = self.get_mesh_nodes()
                    self._send_message({"type": "MESH_NODES_DATA", "nodes": nodes})

                elif msg_type == "READ_FILE":
                    path = msg.get("filePath", "")
                    try:
                        target = (self.workspace_root / path).resolve()
                        if not str(target).startswith(str(self.workspace_root)):
                            raise PermissionError("Access denied outside workspace sandbox.")
                        content = target.read_text(encoding="utf-8")
                        self._send_message({
                            "type": "FILE_CONTENT_DATA",
                            "filePath": path,
                            "content": content,
                            "success": True
                        })
                    except Exception as err:
                        self._send_message({
                            "type": "FILE_CONTENT_DATA",
                            "filePath": path,
                            "error": str(err),
                            "success": False
                        })

                elif msg_type == "WRITE_FILE":
                    path = msg.get("filePath", "")
                    content = msg.get("content", "")
                    try:
                        target = (self.workspace_root / path).resolve()
                        if not str(target).startswith(str(self.workspace_root)):
                            raise PermissionError("Access denied outside workspace sandbox.")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(content, encoding="utf-8")
                        self._send_message({
                            "type": "FILE_WRITTEN_DATA",
                            "filePath": path,
                            "success": True
                        })
                    except Exception as err:
                        self._send_message({
                            "type": "FILE_WRITTEN_DATA",
                            "filePath": path,
                            "error": str(err),
                            "success": False
                        })

                elif msg_type == "HOL_DECISION":
                    qid = msg.get("quarantineId") or msg.get("quarantine_id")
                    approved = bool(msg.get("approved"))
                    if not self.pipe_client:
                        self._send_message({
                            "type": "ERROR",
                            "message": "Supervisor daemon not reachable on pipe"
                        })
                        continue

                    sup_cmd = {
                        "type": "APPROVE_ACTION" if approved else "REJECT_ACTION",
                        "quarantine_id": qid,
                        "operator_notes": "Decision submitted via Electron GUI"
                    }
                    try:
                        resp = self.pipe_client.send_recv(sup_cmd)
                        self._send_message({
                            "type": "HOL_DECISION_RESULT",
                            "quarantineId": qid,
                            "approved": approved,
                            "supervisorResponse": resp
                        })
                    except Exception as err:
                        self._send_message({
                            "type": "ERROR",
                            "message": f"Supervisor decision relay failed: {str(err)}"
                        })

                else:
                    self._send_message({
                        "type": "ERROR",
                        "message": f"Unknown message type: {msg_type}"
                    })

            except Exception as exc:
                self._send_message({
                    "type": "BRIDGE_EXCEPTION",
                    "error": f"{type(exc).__name__}: {str(exc)}"
                })


def main():
    parser = argparse.ArgumentParser(description="MAC Desktop Engine Bridge")
    parser.add_argument("--workspace", default=None, help="Workspace sandbox path")
    parser.add_argument("--pipe", default=None, help="Supervisor UI named pipe path")
    parser.add_argument("--secret", default=None, help="Supervisor UI per-session secret")
    args = parser.parse_args()

    ws = Path(args.workspace).resolve() if args.workspace else (BASE_DIR / "workspace_sandbox").resolve()
    bridge = EngineBridge(workspace_root=ws, pipe_path=args.pipe, ui_secret=args.secret)
    bridge.run_stdio_loop()


if __name__ == "__main__":
    main()
