"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Comprehensive Test Suite (pytest)
Verifies:
  1. Protocol typed contracts and Pydantic schemas.
  2. LocalExecDaemon isolation, timeout protection, and sandbox containment.
  3. MCPGateway semantic vector-mesh (<15ms) and schema validation.
  4. MyceliumCoordinator HOL Guard quarantine, bypass logic, and audit trails.
"""

import time
import pytest
from pathlib import Path

from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    PrivilegeTier,
    SafetyTier,
)
from local_daemon import LocalExecDaemon, WorkspaceSecurityError
from mcp_gateway import (
    ExecuteShellCommandParams,
    MCPGateway,
    ReadWorkspaceFileParams,
    ToolValidationError,
)
from coordinator import MyceliumCoordinator


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Provide isolated temporary workspace directory."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    return sandbox


@pytest.fixture
def daemon(temp_workspace: Path) -> LocalExecDaemon:
    return LocalExecDaemon(workspace_root=temp_workspace)


@pytest.fixture
def gateway() -> MCPGateway:
    return MCPGateway()


# ============================================================================
# 1. Protocol Tests
# ============================================================================

def test_protocol_privilege_and_safety_enums():
    assert PrivilegeTier.PERSON == "PERSON"
    assert PrivilegeTier.BACKGROUND == "BACKGROUND"
    assert SafetyTier.READ_ONLY == "READ_ONLY"
    assert SafetyTier.MUTATING == "MUTATING"


def test_action_request_defaults():
    req = ActionRequest(
        intent="Check system health",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.READ_ONLY
    )
    assert req.requestId is not None
    assert len(req.requestId) > 10
    assert req.payload == {}
    assert req.timestamp <= time.time()


def test_execution_result_contract():
    res = ExecutionResult(
        requestId="req-123",
        success=True,
        stdout="operational",
        exitCode=0,
        latencyMs=4.2
    )
    assert res.requestId == "req-123"
    assert res.success is True
    assert res.stderr == ""
    assert res.latencyMs == 4.2


# ============================================================================
# 2. Local Execution Daemon Tests
# ============================================================================

def test_daemon_file_write_and_read(daemon: LocalExecDaemon):
    content = "test_payload_12345"
    file_path = "sub/dir/config.txt"
    assert daemon.write_workspace_file(file_path, content) is True
    read_back = daemon.read_workspace_file(file_path)
    assert read_back == content


def test_daemon_sandbox_escape_prevention(daemon: LocalExecDaemon):
    with pytest.raises(WorkspaceSecurityError):
        daemon.read_workspace_file("../../escaped_file.txt")

    with pytest.raises(WorkspaceSecurityError):
        daemon.write_workspace_file("../escaped_file.txt", "forbidden")


def test_daemon_file_not_found(daemon: LocalExecDaemon):
    with pytest.raises(FileNotFoundError):
        daemon.read_workspace_file("nonexistent.json")


def test_daemon_execute_command_success(daemon: LocalExecDaemon):
    res = daemon.execute_command("python -c \"print('hello from isolated subprocess')\"")
    assert res.success is True
    assert res.exitCode == 0
    assert "hello from isolated subprocess" in res.stdout
    assert res.latencyMs > 0.0


def test_daemon_execute_command_timeout(daemon: LocalExecDaemon):
    # Enforce strict 0.5s timeout on long-running process
    res = daemon.execute_command(
        "python -c \"import time; time.sleep(4)\"",
        timeout_seconds=0.5
    )
    assert res.success is False
    assert res.exitCode == -1
    assert "exceeded maximum allowed timeout" in res.stderr.lower() or "timeout" in res.stderr.lower()


# ============================================================================
# 3. MCP Gateway & Semantic Vector-Mesh Tests
# ============================================================================

def test_mcp_gateway_semantic_vector_discovery(gateway: MCPGateway, daemon: LocalExecDaemon):
    gateway.register_tool(
        name="read_workspace_file",
        description="Read file contents from workspace directory.",
        safety_tier=SafetyTier.READ_ONLY,
        schema_model=ReadWorkspaceFileParams,
        handler=daemon.read_workspace_file,
        tags=["read", "file", "inspect"]
    )
    gateway.register_tool(
        name="execute_shell_command",
        description="Run bash or command shell commands in isolated subprocess.",
        safety_tier=SafetyTier.MUTATING,
        schema_model=ExecuteShellCommandParams,
        handler=daemon.execute_command,
        tags=["bash", "shell", "run", "cmd"]
    )

    # Sub-15ms semantic matching test
    start = time.perf_counter()
    matches = gateway.discover_tools("Please read the config file contents", top_k=1)
    latency_ms = (time.perf_counter() - start) * 1000.0

    assert len(matches) > 0
    assert matches[0].tool.name == "read_workspace_file"
    assert latency_ms < 15.0  # Must complete under benchmark threshold
    assert matches[0].similarityScore > 0.1


def test_mcp_gateway_argument_validation(gateway: MCPGateway, daemon: LocalExecDaemon):
    gateway.register_tool(
        name="read_workspace_file",
        description="Read file contents from workspace directory.",
        safety_tier=SafetyTier.READ_ONLY,
        schema_model=ReadWorkspaceFileParams,
        handler=daemon.read_workspace_file
    )

    # Valid args
    val = gateway.validate_arguments("read_workspace_file", {"file_path": "valid.txt"})
    assert val.file_path == "valid.txt"

    # Missing required argument
    with pytest.raises(ToolValidationError):
        gateway.validate_arguments("read_workspace_file", {})


# ============================================================================
# 4. Coordinator & HOL Guard Tests
# ============================================================================

def test_coordinator_read_only_fast_path(daemon: LocalExecDaemon):
    coordinator = MyceliumCoordinator(local_daemon=daemon)
    req = ActionRequest(
        intent="Query real-time host node diagnostics and platform telemetry",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.READ_ONLY
    )

    res = coordinator.dispatch(req)
    assert res.success is True
    assert res.exitCode == 0
    assert res.latencyMs < 15.0  # READ_ONLY fast-path under benchmark threshold


def test_coordinator_hol_guard_approval(daemon: LocalExecDaemon):
    # Hook that approves
    hook_called = False

    def approving_hook(event):
        nonlocal hook_called
        hook_called = True
        assert event.request.safetyTier == SafetyTier.MUTATING
        return True

    coordinator = MyceliumCoordinator(
        local_daemon=daemon,
        human_confirmation_hook=approving_hook
    )

    req = ActionRequest(
        intent="Run shell process",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={"command": "python -c \"print('authorized')\""}
    )

    res = coordinator.dispatch(req)
    assert hook_called is True
    assert res.success is True
    assert "authorized" in res.stdout
    assert len(coordinator.quarantine_history) == 1
    assert coordinator.quarantine_history[0].decision == HOLApprovalStatus.APPROVED


def test_coordinator_hol_guard_rejection(daemon: LocalExecDaemon):
    # Hook that denies
    hook_called = False

    def rejecting_hook(event):
        nonlocal hook_called
        hook_called = True
        return False

    coordinator = MyceliumCoordinator(
        local_daemon=daemon,
        human_confirmation_hook=rejecting_hook
    )

    req = ActionRequest(
        intent="Delete database partition",
        privilegeTier=PrivilegeTier.BACKGROUND,
        safetyTier=SafetyTier.MUTATING,
        payload={"command": "rm -rf /"}
    )

    res = coordinator.dispatch(req)
    assert hook_called is True
    assert res.success is False
    assert res.exitCode == 403
    assert "HOL Guard Blocked" in res.stderr
    assert len(coordinator.quarantine_history) == 1
    assert coordinator.quarantine_history[0].decision == HOLApprovalStatus.REJECTED
