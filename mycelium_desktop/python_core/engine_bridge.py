"""
US Neural - Mycelium Desktop Engine Bridge
Module: engine_bridge.py
Description: Stdio JSON-RPC bridge connecting Electron Main process to the Python
             MyceliumCoordinator, LocalExecDaemon, and HOL Guard engine.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

# Add parent directory to sys.path to ensure module imports
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
)
from local_daemon import LocalExecDaemon
from mcp_gateway import MCPGateway
from coordinator import MyceliumCoordinator
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Extra Synthetic Mesh Tools (Weather & Crypto Telemetry)
# ---------------------------------------------------------------------------

class WeatherTelemetryParams(BaseModel):
    station_id: str = Field(default="US-NEURAL-SENSOR-01", description="Telemetry sensor station identifier.")


class CryptoTelemetryParams(BaseModel):
    network: str = Field(default="mycelium-mesh-l1", description="Target cryptographic consensus network.")


def _get_weather_telemetry(station_id: str = "US-NEURAL-SENSOR-01") -> Dict[str, Any]:
    return {
        "station_id": station_id,
        "temperature_c": 21.4,
        "humidity_pct": 46.2,
        "barometric_kpa": 101.32,
        "mesh_latency_ms": 0.42,
        "sensor_health": "OPTIMAL",
        "timestamp": time.time()
    }


def _get_crypto_telemetry(network: str = "mycelium-mesh-l1") -> Dict[str, Any]:
    return {
        "network": network,
        "block_height": 9482103,
        "validator_nodes": 128,
        "tps": 4820,
        "consensus_state": "SYNCHRONIZED",
        "mesh_latency_ms": 0.58,
        "timestamp": time.time()
    }


# ---------------------------------------------------------------------------
# Engine Bridge Controller
# ---------------------------------------------------------------------------

class EngineBridge:
    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or (BASE_DIR / "workspace_sandbox").resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

        self.daemon = LocalExecDaemon(workspace_root=self.workspace_root)
        self.gateway = MCPGateway()

        # Pending HOL approvals indexed by quarantineId
        self._pending_hol: Dict[str, threading.Event] = {}
        self._hol_decisions: Dict[str, bool] = {}
        self._lock = threading.Lock()

        # Initialize coordinator with bridge confirmation hook
        self.coordinator = MyceliumCoordinator(
            local_daemon=self.daemon,
            mcp_gateway=self.gateway,
            human_confirmation_hook=self._gui_human_confirmation_hook
        )

        # Register specialized mesh nodes
        self.gateway.register_tool(
            name="weather_sensor_node",
            description="Fetch meteorological telemetry, atmospheric metrics, and sensor cluster health.",
            safety_tier=SafetyTier.READ_ONLY,
            schema_model=WeatherTelemetryParams,
            handler=_get_weather_telemetry,
            tags=["weather", "sensor", "telemetry", "temperature", "climate", "atmosphere"]
        )

        self.gateway.register_tool(
            name="crypto_telemetry_node",
            description="Query cryptographic proof-of-transit, consensus metrics, and mesh chain health.",
            safety_tier=SafetyTier.READ_ONLY,
            schema_model=CryptoTelemetryParams,
            handler=_get_crypto_telemetry,
            tags=["crypto", "chain", "consensus", "ledger", "tokens", "blockchain"]
        )

    def _gui_human_confirmation_hook(self, quarantine: HOLQuarantineEvent) -> bool:
        """
        Quarantine hook invoked by HOL Guard when a MUTATING action is requested.
        Emits quarantine payload over stdio to Electron and blocks until operator resolves.
        """
        event_obj = threading.Event()
        quarantine_id = quarantine.quarantineId

        with self._lock:
            self._pending_hol[quarantine_id] = event_obj
            self._hol_decisions[quarantine_id] = False

        # Emit quarantine notification to Electron
        self._send_message({
            "type": "HOL_QUARANTINE_TRIGGERED",
            "quarantineId": quarantine_id,
            "requestId": quarantine.request.requestId,
            "intent": quarantine.request.intent,
            "privilegeTier": quarantine.request.privilegeTier.value,
            "safetyTier": quarantine.request.safetyTier.value,
            "payload": quarantine.request.payload,
            "quarantineReason": quarantine.quarantineReason,
            "timestamp": quarantine.quarantinedAt
        })

        # Block until Electron UI resolves or timeout (120 seconds max)
        resolved = event_obj.wait(timeout=120.0)

        with self._lock:
            decision = self._hol_decisions.get(quarantine_id, False)
            self._pending_hol.pop(quarantine_id, None)
            self._hol_decisions.pop(quarantine_id, None)

        return decision if resolved else False

    def handle_hol_decision(self, quarantine_id: str, approved: bool) -> None:
        """Called when Electron GUI submits operator decision."""
        with self._lock:
            if quarantine_id in self._pending_hol:
                self._hol_decisions[quarantine_id] = approved
                self._pending_hol[quarantine_id].set()

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
                        # Ignore cache/temporary files
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

    def get_mesh_nodes(self) -> list[Dict[str, Any]]:
        """Return active Mycelium Mesh nodes with live latencies."""
        nodes = [
            {"id": "node-fs", "name": "Filesystem Sandboxed Daemon", "type": "LOCAL_EXEC", "status": "ONLINE", "pingMs": 0.12},
            {"id": "node-shell", "name": "Terminal Subshell Daemon", "type": "ISOLATED_PROC", "status": "ONLINE", "pingMs": 0.25},
            {"id": "node-weather", "name": "Weather Sensor Node", "type": "TELEMETRY_MESH", "status": "ONLINE", "pingMs": 0.42},
            {"id": "node-crypto", "name": "Crypto Telemetry Node", "type": "CONSENSUS_MESH", "status": "ONLINE", "pingMs": 0.58},
        ]
        return nodes

    def process_request(self, req_data: Dict[str, Any]) -> None:
        """Process incoming natural language intent or structured action."""
        intent = req_data.get("intent", "").strip()
        privilege_str = req_data.get("privilegeTier", "PERSON")
        privilege = PrivilegeTier(privilege_str)

        # Automatic safety inference if not specified:
        # If payload contains command or mentions write/delete/execute -> MUTATING
        payload = req_data.get("payload", {})
        safety_str = req_data.get("safetyTier")

        # Discover matching tool in sub-10ms
        match_start = time.perf_counter()
        matches = self.coordinator.route_intent(intent, top_k=2)
        match_latency = round((time.perf_counter() - match_start) * 1000.0, 3)

        best_match = matches[0] if matches else None
        inferred_safety = SafetyTier.READ_ONLY
        if safety_str:
            inferred_safety = SafetyTier(safety_str)
        elif "command" in payload:
            inferred_safety = SafetyTier.MUTATING
        elif best_match and best_match.tool.safetyTier == SafetyTier.MUTATING:
            inferred_safety = SafetyTier.MUTATING
        elif any(w in intent.lower() for w in ["write", "create", "delete", "run", "bash", "execute", "shell", "dir", "mkdir"]):
            inferred_safety = SafetyTier.MUTATING

        # Emit Semantic Discovery Event to Electron GUI
        self._send_message({
            "type": "SEMANTIC_DISCOVERY_EVENT",
            "intent": intent,
            "matchedTool": best_match.tool.name if best_match else None,
            "matchedToolSafety": best_match.tool.safetyTier.value if best_match else "UNKNOWN",
            "similarityScore": best_match.similarityScore if best_match else 0.0,
            "discoveryLatencyMs": match_latency
        })

        # Synthesize ActionRequest
        action_request = ActionRequest(
            requestId=req_data.get("requestId") or f"req-{int(time.time()*1000)}",
            intent=intent,
            privilegeTier=privilege,
            safetyTier=inferred_safety,
            payload=payload
        )

        # Dispatch via MyceliumCoordinator
        result = self.coordinator.dispatch(action_request)

        # Send response back to Electron
        self._send_message({
            "type": "EXECUTION_COMPLETE",
            "requestId": action_request.requestId,
            "intent": intent,
            "safetyTier": action_request.safetyTier.value,
            "privilegeTier": action_request.privilegeTier.value,
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exitCode": result.exitCode,
            "latencyMs": result.latencyMs,
            "matchedTool": best_match.tool.name if best_match else None
        })

    def run_stdio_loop(self) -> None:
        """Main stdio JSON-RPC listening loop."""
        # Initial ready handshake
        self._send_message({
            "type": "SYSTEM_READY",
            "version": "1.0.0",
            "workspace": str(self.workspace_root),
            "meshNodes": self.get_mesh_nodes()
        })

        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                msg_type = msg.get("action") or msg.get("type")

                if msg_type == "PING":
                    self._send_message({"type": "PONG", "timestamp": time.time()})

                elif msg_type == "GET_WORKSPACE_TREE":
                    tree = self.get_workspace_tree()
                    self._send_message({"type": "WORKSPACE_TREE_DATA", "tree": tree})

                elif msg_type == "GET_MESH_NODES":
                    nodes = self.get_mesh_nodes()
                    self._send_message({"type": "MESH_NODES_DATA", "nodes": nodes})

                elif msg_type == "READ_FILE":
                    path = msg.get("filePath", "")
                    try:
                        content = self.daemon.read_workspace_file(path)
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
                        self.daemon.write_workspace_file(path, content)
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
                    qid = msg.get("quarantineId")
                    decision = bool(msg.get("approved"))
                    self.handle_hol_decision(qid, decision)

                elif msg_type == "DISPATCH_INTENT":
                    # Run request processing in thread so stdio loop remains responsive to HOL decisions!
                    threading.Thread(
                        target=self.process_request,
                        args=(msg,),
                        daemon=True
                    ).start()

                elif msg_type == "ABORT":
                    killed = self.daemon.abort_active()
                    # Release any pending HOL decisions
                    with self._lock:
                        for qid, event_obj in list(self._pending_hol.items()):
                            self._hol_decisions[qid] = False
                            event_obj.set()
                    self._send_message({
                        "type": "EXECUTION_ABORTED",
                        "aborted": True,
                        "processKilled": killed
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
    workspace = (BASE_DIR / "workspace_sandbox").resolve()
    bridge = EngineBridge(workspace_root=workspace)
    bridge.run_stdio_loop()


if __name__ == "__main__":
    main()
