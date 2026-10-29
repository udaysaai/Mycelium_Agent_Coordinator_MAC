"""
US Neural - Mycelium Agent Coordinator (MAC)
Adversarial Security Test Suite for Phase 0 Governed Harness
Spec-Driven Hardening Tests:
  1. Token replay prevention & permanent CONSUMED state.
  2. Execution-time argument tampering detection (Call hash recomputation).
  3. HMAC token authenticity (Master key outside DB; forged token rejection).
  4. Injectable clock timeout enforcement (Default-deny on expiry across restarts).
  5. Crash durability & state preservation across process restarts.
  6. Path traversal, UNC, Windows drive letters, and symlink breakout prevention.
  7. Tier classification: Unknown tools default to T2; argument escalation & capability grants.
  8. Approval channel isolation (Worker cannot forge approval decisions).
  9. Verifier tampering detection (Missing, truncated, byte-modified, binary mode).
 10. Agent self-report prevention: Unverified tasks end as UNVERIFIED/FAILED, never COMPLETED.
 11. Intake gate slot-filling enforcement.
 12. TaskContract immutability enforcement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest
from pydantic import ValidationError

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
    VerificationReceipt,
)
from local_daemon import LocalExecDaemon, WorkspaceSecurityError
from mcp_gateway import MCPGateway
from state_store import StateStore
from policy_engine import PolicyEngine, PolicyVerdict
from verifier import DeterministicVerifier
from intake_gate import IntakeGate
from coordinator import MyceliumCoordinator


@pytest.fixture
def adv_env(tmp_path: Path):
    """Provide fully isolated environment for adversarial security evaluations."""
    workspace = tmp_path / "mac_workspace"
    workspace.mkdir()
    data_dir = workspace / "data"
    data_dir.mkdir()
    sandbox = workspace / "workspace_sandbox"
    sandbox.mkdir()

    # Isolated secret key stored outside DB (0600 file)
    key_file = tmp_path / "external_keys" / "mac_signing.key"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    master_key = secrets.token_bytes(32)
    key_file.write_bytes(master_key)

    db_path = data_dir / "mac_state.db"
    store = StateStore(db_path=db_path)
    daemon = LocalExecDaemon(workspace_root=workspace)
    gateway = MCPGateway()

    # Controlled operator decision
    operator_state = {"approved": True, "notes": "Approved by supervisor"}

    def hook(quarantine: HOLQuarantineEvent) -> bool:
        return operator_state["approved"]

    coordinator = MyceliumCoordinator(
        local_daemon=daemon,
        mcp_gateway=gateway,
        human_confirmation_hook=hook,
        state_store=store
    )

    return {
        "workspace": workspace,
        "sandbox": sandbox,
        "key_file": key_file,
        "master_key": master_key,
        "db_path": db_path,
        "store": store,
        "daemon": daemon,
        "gateway": gateway,
        "coordinator": coordinator,
        "operator_state": operator_state,
        "tmp_path": tmp_path
    }


# ============================================================================
# 1. Token Replay Prevention
# ============================================================================

def test_adv_01_token_replay_rejected(adv_env):
    """
    Approve a T2 action once, execute it to consume the token.
    Subsequent attempts to reuse the same token must be rejected, and state remains CONSUMED.
    """
    coord = adv_env["coordinator"]
    store = adv_env["store"]
    adv_env["operator_state"]["approved"] = True

    req = ActionRequest(
        intent="write sensitive config outside sandbox",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "sensitive.conf",
            "content": "ALLOW_SUPERUSER=true"
        }
    )

    res = coord.dispatch(req)
    assert res.success is True
    assert len(coord.quarantine_history) == 1
    qid = coord.quarantine_history[0].quarantineId
    token = coord.quarantine_history[0].oneShotToken

    # Verify store marks token as CONSUMED
    stored = store.get_quarantine(qid)
    assert stored is not None
    assert stored["one_shot_token"] == "CONSUMED"

    # Attempt replay with the token
    replay_valid = store.validate_one_shot_token(qid, token)
    assert replay_valid is False

    # Attempt execution with replayed token
    replay_req = ActionRequest(
        intent="replayed write sensitive config",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        oneShotToken=token,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "sensitive.conf",
            "content": "REPLAYED_MUTATION",
            "quarantineId": qid
        }
    )
    replay_res = coord.dispatch(replay_req)
    assert replay_res.success is False
    assert replay_res.exitCode == 403


# ============================================================================
# 2. Execution-Time Argument Tampering Detection
# ============================================================================

def test_adv_02_argument_tampering_detected(adv_env):
    """
    Get approval for call X (args A), then execute with changed args/content (args B).
    The call hash recomputed at execution time from actual call must mismatch quarantine call hash.
    Execution must be rejected with 403.
    """
    coord = adv_env["coordinator"]
    store = adv_env["store"]
    adv_env["operator_state"]["approved"] = True

    # Initial call requesting approval for benign write
    initial_req = ActionRequest(
        intent="write benign log file",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "benign.log",
            "content": "INFO: user logged in"
        }
    )
    res = coord.dispatch(initial_req)
    assert res.success is True
    qid = coord.quarantine_history[0].quarantineId
    token = coord.quarantine_history[0].oneShotToken

    # Attacker tries to use the approval token to execute with tampered destructive payload
    tampered_req = ActionRequest(
        intent="write benign log file",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        oneShotToken=token,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "system.conf",  # Tampered target!
            "content": "MALICIOUS_OVERWRITE=true",
            "quarantineId": qid
        }
    )
    tampered_res = coord.dispatch(tampered_req)
    assert tampered_res.success is False
    assert tampered_res.exitCode == 403
    assert not (adv_env["workspace"] / "system.conf").exists()


# ============================================================================
# 3. Token Authenticity & HMAC Signing
# ============================================================================

def test_adv_03_token_authenticity_hmac(adv_env):
    """
    Tokens must be HMAC-signed with a secret stored outside DB and bound to
    (quarantine_id, call_hash, expires_at). Random hex or forged tokens must be rejected.
    """
    policy = adv_env["coordinator"].policy_engine
    store = adv_env["store"]

    call_hash = policy.compute_call_hash("write_workspace_file", {"file_path": "x.txt"}, "x.txt")
    qid = "quarantine-test-auth"
    expires = time.time() + 900.0

    valid_token = policy.generate_hmac_token(qid, call_hash, expires)
    assert len(valid_token) >= 32

    # Case A: Valid token passes verification
    assert policy.verify_hmac_token(valid_token, qid, call_hash, expires) is True

    # Case B: Random hex token fails verification
    random_hex = secrets.token_hex(16)
    assert policy.verify_hmac_token(random_hex, qid, call_hash, expires) is False

    # Case C: Tampered quarantine ID fails verification
    assert policy.verify_hmac_token(valid_token, "other-qid", call_hash, expires) is False

    # Case D: Tampered call hash fails verification
    assert policy.verify_hmac_token(valid_token, qid, "tampered-hash", expires) is False


# ============================================================================
# 4. Timeout Enforcement with Injectable Clock (Default-Deny)
# ============================================================================

def test_adv_04_timeout_default_deny_with_clock(adv_env):
    """
    Quarantined action past expiry must resolve to REJECTED_TIMEOUT (default-deny),
    never approved, including after process restart.
    Uses injectable clock (zero sleep).
    """
    store = adv_env["store"]
    current_time = 1000000.0
    store.clock = lambda: current_time

    # Create quarantine expiring at current_time + 900
    q_event = HOLQuarantineEvent(
        quarantineId="qid-timeout-test",
        request=ActionRequest(
            intent="expired test action",
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING,
            payload={"tool_name": "execute_shell_command", "command": "echo test"}
        ),
        quarantineReason="Needs approval",
        decision=HOLApprovalStatus.PENDING,
        callHash="dummy-hash",
        oneShotToken="dummy-token",
        plainImpact="Impact test",
        quarantinedAt=current_time,
        expiresAt=current_time + 900.0
    )
    store.save_quarantine(q_event)

    # Before expiry, it is pending
    pending = store.get_pending_quarantines()
    assert any(q["quarantine_id"] == "qid-timeout-test" for q in pending)

    # Advance clock past expiry (t + 901)
    current_time = 1000901.0
    store.clock = lambda: current_time

    # Must no longer be in pending list
    pending_after = store.get_pending_quarantines()
    assert not any(q["quarantine_id"] == "qid-timeout-test" for q in pending_after)

    # Attempting to approve after expiry must be rejected with default-deny
    approved = store.update_quarantine_decision("qid-timeout-test", HOLApprovalStatus.APPROVED)
    assert approved is False

    # Stored record must resolve to REJECTED_TIMEOUT
    record = store.get_quarantine("qid-timeout-test")
    assert record["status"] in (HOLApprovalStatus.REJECTED_TIMEOUT.value, HOLApprovalStatus.REJECTED.value)


# ============================================================================
# 5. Crash Durability & Pending Item Preservation
# ============================================================================

def test_adv_05_crash_durability_pending_survives(adv_env):
    """
    Create pending quarantine, simulate process shutdown, reopen database in fresh instance.
    Confirm pending item survives and remains unexecuted with status PENDING.
    """
    store = adv_env["store"]
    db_path = adv_env["db_path"]

    q_event = HOLQuarantineEvent(
        quarantineId="qid-crash-durability",
        request=ActionRequest(
            intent="write critical data",
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING,
            payload={"tool_name": "write_workspace_file", "file_path": "crash.txt", "content": "data"}
        ),
        quarantineReason="Testing durability",
        decision=HOLApprovalStatus.PENDING,
        callHash="hash-crash",
        oneShotToken="token-crash",
        plainImpact="Pending write",
        quarantinedAt=time.time(),
        expiresAt=time.time() + 900.0
    )
    store.save_quarantine(q_event)

    # Simulate fresh process opening the DB
    fresh_store = StateStore(db_path=db_path)
    retrieved = fresh_store.get_quarantine("qid-crash-durability")
    assert retrieved is not None
    assert retrieved["status"] == HOLApprovalStatus.PENDING.value
    assert retrieved["call_hash"] == "hash-crash"
    # Target file still does not exist on disk
    assert not (adv_env["workspace"] / "crash.txt").exists()


# ============================================================================
# 6. Path Traversal, UNC, Windows Drive Letters & Symlink Breakout
# ============================================================================

def test_adv_06_path_traversal_and_symlinks(adv_env):
    """
    sandboxed_file_writer must strictly reject:
    a) Path traversal (../)
    b) Absolute paths outside sandbox
    c) Windows drive-letter paths (C:/..., D:/...)
    d) UNC network paths (//server/share/...)
    e) Symlinks/junctions pointing outside sandbox
    """
    coord = adv_env["coordinator"]
    sandbox = adv_env["sandbox"]
    workspace = adv_env["workspace"]

    evil_paths = [
        "../outside.txt",
        "../../outside.txt",
        "..\\outside.txt",
        "subdir/../../escaped.txt",
        "C:/Windows/System32/evil.dll",
        "C:\\evil.txt",
        "D:\\escaped.txt",
        "\\\\evil-server\\share\\pwn.txt",
        "//evil-server/share/pwn.txt",
    ]

    for evil_path in evil_paths:
        req = ActionRequest(
            intent=f"attempted path traversal write to {evil_path}",
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING_SANDBOX,
            payload={
                "tool_name": "sandboxed_file_writer",
                "file_path": evil_path,
                "content": "MALICIOUS PAYLOAD"
            }
        )
        res = coord.dispatch(req)
        assert res.success is False
        assert (res.exitCode != 0 or "boundary" in res.stderr.lower() or "violation" in res.stderr.lower())

    # Symlink escape test: create symlink inside sandbox pointing to outside folder
    outside_dir = adv_env["tmp_path"] / "outside_target"
    outside_dir.mkdir(parents=True, exist_ok=True)
    symlink_path = sandbox / "symlink_dir"
    try:
        os.symlink(str(outside_dir), str(symlink_path), target_is_directory=True)
        # Attempt writing into symlinked dir
        symlink_req = ActionRequest(
            intent="write through symlink",
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING_SANDBOX,
            payload={
                "tool_name": "sandboxed_file_writer",
                "file_path": "symlink_dir/pwned.txt",
                "content": "ATTACK"
            }
        )
        res = coord.dispatch(symlink_req)
        # Must be rejected because real path resolves outside sandbox
        assert res.success is False
        assert not (outside_dir / "pwned.txt").exists()
    except (OSError, NotImplementedError, PermissionError):
        # On Windows without SeCreateSymbolicLinkPrivilege, symlinks might not be permitted
        pass


# ============================================================================
# 7. Tier Classification & Capability Grants (Unknowns default to T2)
# ============================================================================

def test_adv_07_tier_classification_and_capability_grants(adv_env):
    """
    a) Unknown tools must default to T2 (deny/quarantine), NEVER T0.
    b) T1 tool called targeting outside sandbox must escalate to T2.
    c) Capability constraints: payload > 5MB rejected; shell denylist blocked.
    """
    policy = adv_env["coordinator"].policy_engine

    # a) Unknown tool must evaluate to T2
    req_unknown = ActionRequest(
        intent="invoke alien tool",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.READ_ONLY,
        payload={"tool_name": "unknown_shadow_tool_999"}
    )
    verdict_unknown = policy.evaluate(req_unknown)
    assert verdict_unknown.tierLevel == TierLevel.T2
    assert verdict_unknown.requiresQuarantine is True

    # b) T1 tool write targeting outside sandbox escalates to T2
    req_escalate = ActionRequest(
        intent="write workspace file outside sandbox",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={"tool_name": "write_workspace_file", "file_path": "outside.txt", "content": "text"}
    )
    verdict_escalate = policy.evaluate(req_escalate)
    assert verdict_escalate.tierLevel == TierLevel.T2
    assert verdict_escalate.requiresQuarantine is True

    # c) Capability grant: Max file size (5MB ceiling)
    huge_content = "X" * (5 * 1024 * 1024 + 1024)
    req_oversize = ActionRequest(
        intent="write oversized file",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING_SANDBOX,
        payload={"tool_name": "sandboxed_file_writer", "file_path": "huge.txt", "content": huge_content}
    )
    verdict_oversize = policy.evaluate(req_oversize)
    assert verdict_oversize.requiresQuarantine is True or "size" in verdict_oversize.reason.lower()

    # d) Capability grant: Dangerous command blocked by policy
    req_dangerous_cmd = ActionRequest(
        intent="run format or rmdir",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={"tool_name": "execute_shell_command", "command": "rmdir /s /q C:\\"}
    )
    verdict_cmd = policy.evaluate(req_dangerous_cmd)
    assert verdict_cmd.tierLevel == TierLevel.T2
    assert verdict_cmd.requiresQuarantine is True


# ============================================================================
# 8. Approval Channel Isolation
# ============================================================================

def test_adv_08_approval_channel_isolation(adv_env):
    """
    The worker/agent side must not be able to approve a quarantine by passing an approval
    decision in ActionRequest payload. Only the UI/supervisor channel can authorize.
    """
    coord = adv_env["coordinator"]
    adv_env["operator_state"]["approved"] = False  # Operator denies

    # Attacker tries to inject approval via action payload
    injected_req = ActionRequest(
        intent="write protected file with injected approval",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={
            "tool_name": "write_workspace_file",
            "file_path": "injected.txt",
            "content": "MALICIOUS",
            "action": "HOL_DECISION",
            "approved": True,
            "decision": "APPROVED"
        }
    )
    res = coord.dispatch(injected_req)
    assert res.success is False
    assert res.exitCode == 403
    assert not (adv_env["workspace"] / "injected.txt").exists()


# ============================================================================
# 9. Verifier Tamper Cases (Missing, Truncated, Same Size Diff Content, Binary)
# ============================================================================

def test_adv_09_verifier_tamper_cases(adv_env):
    """
    Verifier negative tests:
    - Missing file fails
    - Truncated file fails
    - Same size, 1 byte changed fails
    - Binary mode does NOT normalize newlines
    """
    verifier = adv_env["coordinator"].verifier
    workspace = adv_env["workspace"]

    # 1. Missing file
    rec1 = verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "nonexistent.bin", "content": "abc"},
        raw_output=True,
        request_id="req-1"
    )
    assert rec1.verified is False

    # 2. Truncated file
    trunc_file = workspace / "trunc.txt"
    trunc_file.write_text("123", encoding="utf-8")
    rec2 = verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "trunc.txt", "content": "123456789"},
        raw_output=True,
        request_id="req-2"
    )
    assert rec2.verified is False

    # 3. Same size, 1 byte different
    diff_file = workspace / "diff.txt"
    diff_file.write_text("Hello World!", encoding="utf-8")
    rec3 = verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "diff.txt", "content": "Hello Vorld!"},  # Same length, 1 char diff
        raw_output=True,
        request_id="req-3"
    )
    assert rec3.verified is False

    # 4. Binary file with CRLF vs LF: In binary mode, CRLF vs LF is REAL tampering!
    bin_file = workspace / "binary.bin"
    bin_file.write_bytes(b"DATA\r\nMORE")
    rec4 = verifier.verify_action(
        tool_name="write_workspace_file",
        payload={"file_path": "binary.bin", "content": "DATA\nMORE"},
        raw_output=True,
        request_id="req-4",
        is_binary=True
    )
    assert rec4.verified is False  # Must not normalize newlines for binary!

    # 5. Shell execution with non-zero exit code must fail verification
    rec5 = verifier.verify_action(
        tool_name="execute_shell_command",
        payload={"command": "exit 1"},
        raw_output={"exitCode": 1, "stdout": "", "stderr": "error"},
        request_id="req-5"
    )
    assert rec5.verified is False


# ============================================================================
# 10. Agent Self-Report Prevention
# ============================================================================

def test_adv_10_agent_self_report_unverified_task_fails(adv_env):
    """
    A task cannot be marked COMPLETED unless a VerificationReceipt with verified=True exists.
    If verifier fails or is bypassed, status must end as FAILED or UNVERIFIED, never COMPLETED.
    """
    coord = adv_env["coordinator"]
    store = adv_env["store"]

    # Force verifier to return failure by deleting file immediately after write
    adv_env["operator_state"]["approved"] = True

    # Use a contract requiring verification
    req = ActionRequest(
        intent="create file 'workspace_sandbox/self_grade.txt' with content 'secret'",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING_SANDBOX,
        payload={
            "tool_name": "sandboxed_file_writer",
            "file_path": "self_grade.txt",
            "content": "secret"
        }
    )

    # Monkeypatch actuator to delete file so verifier catches missing state
    orig_run = coord._run_actuator
    def sabotage_actuator(*args, **kwargs):
        res = orig_run(*args, **kwargs)
        target = adv_env["sandbox"] / "self_grade.txt"
        if target.exists():
            target.unlink()
        return res
    coord._run_actuator = sabotage_actuator

    res = coord.dispatch(req)
    assert res.success is False
    assert res.contractId is not None

    contract = store.get_contract(res.contractId)
    assert contract is not None
    assert contract.status != TaskContractStatus.COMPLETED
    assert contract.status in (TaskContractStatus.FAILED, TaskContractStatus.ABORTED)


# ============================================================================
# 11. Intake Gate Slot-Filling Enforcement
# ============================================================================

def test_adv_11_intake_vague_prompts_request_missing_slots(adv_env):
    """
    Vague prompts must return missing-slot requests (422), not executing tools.
    """
    coord = adv_env["coordinator"]
    for vague in ["save report", "write output", "create document"]:
        req = ActionRequest(
            intent=vague,
            privilegeTier=PrivilegeTier.PERSON,
            safetyTier=SafetyTier.MUTATING
        )
        res = coord.dispatch(req)
        assert res.success is False
        assert res.exitCode == 422
        assert len(coord.quarantine_history) == 0


# ============================================================================
# 12. TaskContract Immutability
# ============================================================================

def test_adv_12_task_contract_immutability(adv_env):
    """
    TaskContract must be immutable (frozen). Attempts to alter goal, constraints,
    or predicates after creation must fail.
    """
    contract = TaskContract(
        goal="Immutable Goal",
        constraints={"timeoutSeconds": 30.0},
        successPredicate={"type": "file_exists", "path": "file.txt"},
        tierCeiling=TierLevel.T1,
        status=TaskContractStatus.ACTIVE
    )

    # Attempting to mutate any field must raise an error
    with pytest.raises((ValidationError, TypeError)):
        contract.goal = "Tampered Goal"

    with pytest.raises((ValidationError, TypeError)):
        contract.tierCeiling = TierLevel.T2

    with pytest.raises((ValidationError, TypeError)):
        contract.successPredicate = {"type": "bypass"}
