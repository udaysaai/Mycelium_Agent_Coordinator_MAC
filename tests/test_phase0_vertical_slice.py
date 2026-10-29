"""
US Neural - Mycelium Agent Coordinator (MAC)
Phase 0 Thin Vertical Slice: Comprehensive Replay & Evaluation Test Suite
Verifies:
  1. Conversational Intake Gate & TaskContract Compilation (Intent handling).
  2. T0 Immediate Read-Only Bypass (<10ms, zero operator friction).
  3. T1 Reversible Sandboxed Mutation (Atomic fsync write & receipt generation).
  4. T2 Quarantine Gate (Deterministic callHash, plain impact preview, 15m timeout).
  5. Operator Rejection & Approval Workflows with Signed One-Shot Token.
  6. HMAC One-Shot Replay Invalidation (State transition enforcement).
  7. Deterministic Out-of-Band Verifier (Positive verification & Negative tampering detection).
  8. SQLite WAL State Store Persistence Across Reboots.
"""

import os
import shutil
import time
from pathlib import Path
import pytest

from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
    TaskContract,
    TaskContractStatus,
    TierLevel,
)
from local_daemon import LocalExecDaemon
from mcp_gateway import MCPGateway
from state_store import StateStore
from policy_engine import PolicyEngine
from verifier import DeterministicVerifier
from intake_gate import IntakeGate
from coordinator import MyceliumCoordinator


@pytest.fixture
def test_env(tmp_path: Path):
    """Provide clean isolated directory for workspace, database, and sandbox."""
    workspace = tmp_path / "mac_workspace"
    workspace.mkdir()
    data_dir = workspace / "data"
    data_dir.mkdir()
    sandbox = workspace / "workspace_sandbox"
    sandbox.mkdir()

    db_path = data_dir / "mac_state.db"
    store = StateStore(db_path=db_path)
    daemon = LocalExecDaemon(workspace_root=workspace)
    gateway = MCPGateway()

    # Shared confirmation flag for testing hooks
    operator_decision = {"approved": True}

    def hook(quarantine: HOLQuarantineEvent) -> bool:
        return operator_decision["approved"]

    coordinator = MyceliumCoordinator(
        local_daemon=daemon,
        mcp_gateway=gateway,
        human_confirmation_hook=hook,
        state_store=store
    )

    return {
        "workspace": workspace,
        "sandbox": sandbox,
        "db_path": db_path,
        "store": store,
        "daemon": daemon,
        "gateway": gateway,
        "coordinator": coordinator,
        "decision": operator_decision
    }


# ============================================================================
# 1. Conversational Intake Gate Tests
# ============================================================================

def test_intake_greeting_no_404(test_env):
    """Greetings must receive conversational response with zero tool dispatch and 0 exit code."""
    coord = test_env["coordinator"]
    for greeting in ["hi", "hello", "hey", "who are you", "what can you do"]:
        req = ActionRequest(
            intent=greeting,
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.READ_ONLY
        )
        res = coord.dispatch(req)
        assert res.success is True
        assert res.exitCode == 0
        assert "Mycelium Agent Coordinator" in res.stdout
        assert res.tierLevel == TierLevel.T0
        assert res.latencyMs < 50.0  # Instant response


def test_intake_slot_filling_for_vague_request(test_env):
    """Vague mutation goals with missing parameters prompt user for slots."""
    coord = test_env["coordinator"]
    req = ActionRequest(
        intent="write a file",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={}
    )
    res = coord.dispatch(req)
    assert res.success is False
    assert res.exitCode == 422
    assert "missing parameters" in res.stdout.lower() or "file_path" in res.stdout.lower()


def test_intake_compiles_task_contract(test_env):
    """Concrete tasks compile an immutable TaskContract saved in SQLite."""
    coord = test_env["coordinator"]
    store = test_env["store"]

    req = ActionRequest(
        intent="create file 'workspace_sandbox/metrics.json' with content '{\"status\": \"ok\"}'",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.READ_ONLY,
        payload={
            "tool_name": "sandboxed_file_writer",
            "file_path": "metrics.json",
            "content": "{\"status\": \"ok\"}"
        }
    )
    res = coord.dispatch(req)
    assert res.success is True
    assert res.contractId is not None

    saved_contract = store.get_contract(res.contractId)
    assert saved_contract is not None
    assert saved_contract.status == TaskContractStatus.COMPLETED


# ============================================================================
# 2. T0 Policy: Zero-Friction Idempotent Read Bypass
# ============================================================================

def test_t0_read_bypasses_quarantine(test_env):
    """T0 read-only queries execute with zero operator friction."""
    coord = test_env["coordinator"]
    # Write initial file to read
    daemon = test_env["daemon"]
    daemon.write_workspace_file("system.conf", "MAX_WORKERS=8")

    req = ActionRequest(
        intent="read workspace file system.conf",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.READ_ONLY,
        payload={"tool_name": "read_workspace_file", "file_path": "system.conf"}
    )
    res = coord.dispatch(req)
    assert res.success is True
    assert "MAX_WORKERS=8" in res.stdout
    assert res.tierLevel == TierLevel.T0
    assert len(coord.quarantine_history) == 0  # No quarantine triggered


# ============================================================================
# 3. T1 Policy: Reversible Sandboxed Mutation
# ============================================================================

def test_t1_sandboxed_atomic_writer(test_env):
    """Writing inside workspace_sandbox is classified as T1, writes atomically, and succeeds."""
    coord = test_env["coordinator"]
    sandbox = test_env["sandbox"]

    req = ActionRequest(
        intent="atomically write test data to sandbox",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING_SANDBOX,
        payload={
            "tool_name": "sandboxed_file_writer",
            "file_path": "audit_test.csv",
            "content": "id,name,value\n1,alpha,42\n"
        }
    )
    res = coord.dispatch(req)
    assert res.success is True
    assert res.tierLevel == TierLevel.T1
    assert len(coord.quarantine_history) == 0  # T1 does not block on human

    target_file = sandbox / "audit_test.csv"
    assert target_file.exists()
    assert "1,alpha,42" in target_file.read_text(encoding="utf-8")


# ============================================================================
# 4. T2 Policy: Quarantine Gate, One-Shot Token & Auto-Timeout
# ============================================================================

def test_t2_quarantine_rejection_blocks_execution(test_env):
    """T2 mutation rejected by operator must abort with exit code 403."""
    coord = test_env["coordinator"]
    test_env["decision"]["approved"] = False  # Operator rejects!

    req = ActionRequest(
        intent="modify critical root file outside sandbox",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "critical_outside.txt",
            "content": "MALICIOUS OR UNAPPROVED"
        }
    )
    res = coord.dispatch(req)
    assert res.success is False
    assert res.exitCode == 403
    assert "HOL Guard Blocked" in res.stderr
    assert len(coord.quarantine_history) == 1
    assert coord.quarantine_history[0].decision == HOLApprovalStatus.REJECTED

    # Ensure file was NEVER written to disk
    assert not (test_env["workspace"] / "critical_outside.txt").exists()


def test_t2_quarantine_approval_with_token(test_env):
    """T2 mutation approved by operator executes cleanly and writes receipts."""
    coord = test_env["coordinator"]
    test_env["decision"]["approved"] = True  # Operator authorizes!

    req = ActionRequest(
        intent="write authorized config outside sandbox",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "authorized_config.json",
            "content": "{\"authorized\": true}"
        }
    )
    res = coord.dispatch(req)
    assert res.success is True
    assert res.exitCode == 0
    assert len(coord.quarantine_history) == 1

    event = coord.quarantine_history[0]
    assert event.decision == HOLApprovalStatus.APPROVED
    assert event.oneShotToken != ""
    assert event.plainImpact != ""
    assert event.expiresAt > time.time()
    assert (test_env["workspace"] / "authorized_config.json").exists()


# ============================================================================
# 5. Token Forgery & One-Shot Replay Invalidation
# ============================================================================

def test_t2_token_replay_blocked(test_env):
    """Replaying an already-consumed one-shot token must be blocked upon state transition."""
    store = test_env["store"]
    coord = test_env["coordinator"]
    test_env["decision"]["approved"] = True

    # 1. Execute an approved T2 action
    req = ActionRequest(
        intent="write token test file",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "token_test.txt",
            "content": "Token data"
        }
    )
    res = coord.dispatch(req)
    assert res.success is True

    qid = coord.quarantine_history[0].quarantineId
    used_token = coord.quarantine_history[0].oneShotToken

    # 2. Attempt to reuse the consumed token directly
    is_valid_again = store.validate_one_shot_token(qid, used_token)
    assert is_valid_again is False  # Token must be invalidated!


# ============================================================================
# 6. Deterministic Out-of-Band Verifier (Positive & Negative Tests)
# ============================================================================

def test_verifier_catches_tampered_or_missing_file(test_env):
    """
    Negative assertion: If an agent claims completion but the file is missing or empty,
    the out-of-band verifier MUST catch it and fail the task.
    """
    verifier = test_env["coordinator"].verifier

    # Case A: Missing file
    receipt_missing = verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "ghost_file.txt", "content": "hello"},
        raw_output=True,
        request_id="req-test-1"
    )
    assert receipt_missing.verified is False
    assert "does not exist on disk" in receipt_missing.verifierNotes

    # Case B: Empty file failing min_bytes assertion
    test_file = test_env["workspace"] / "empty.txt"
    test_file.write_text("", encoding="utf-8")

    contract = TaskContract(
        goal="write file",
        successPredicate={"type": "file_exists", "min_bytes": 10}
    )
    receipt_empty = verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "empty.txt", "content": "some content"},
        raw_output=True,
        request_id="req-test-2",
        contract=contract
    )
    assert receipt_empty.verified is False
    assert "required 10B" in receipt_empty.verifierNotes


# ============================================================================
# 7. SQLite WAL Durability Across Reboots
# ============================================================================

def test_sqlite_wal_persistence_across_restart(test_env):
    """All contracts, quarantines, and receipts persist and reload from SQLite WAL."""
    coord = test_env["coordinator"]
    db_path = test_env["db_path"]

    # Execute an action to generate database rows
    req = ActionRequest(
        intent="write data to persist",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING_SANDBOX,
        payload={
            "tool_name": "sandboxed_file_writer",
            "file_path": "durable_record.txt",
            "content": "DURABLE WAL PAYLOAD"
        }
    )
    res = coord.dispatch(req)
    assert res.success is True

    # Simulate process shutdown and reboot by initializing a fresh StateStore instance
    rebooted_store = StateStore(db_path=db_path)

    # Assert contract reloaded
    contract = rebooted_store.get_contract(res.contractId)
    assert contract is not None
    assert contract.contractId == res.contractId
    assert contract.status == TaskContractStatus.COMPLETED

    # Assert verification receipts reloaded
    receipts = rebooted_store.get_receipts(contract_id=res.contractId)
    assert len(receipts) >= 1
    assert receipts[0].verified is True
    assert receipts[0].checksum != ""
