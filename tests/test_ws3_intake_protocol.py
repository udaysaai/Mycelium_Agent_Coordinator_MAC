"""
tests/test_ws3_intake_protocol.py - WS3 Step 3.1: Intake & TaskContract Verification Suite
Validates slot-filling, reconciliation parameters, capability ceiling enforcement,
and machine-checkable TaskContract synthesis.
"""

import pytest
from pathlib import Path

from protocol import (
    ActionRequest,
    PrivilegeTier,
    SafetyTier,
    TaskContract,
    TaskContractStatus,
    TierLevel,
    ReconciliationParameters,
)
from intake_gate import IntakeGate
from policy_engine import PolicyEngine


def test_reconciliation_intent_vague_triggers_slot_filling():
    gate = IntakeGate()
    outcome = gate.evaluate_intent("Please reconcile my cashbook with the bank statement.")
    assert outcome.isReadyForExecution is False
    assert len(outcome.missingSlots) >= 4
    slot_names = [s.lower() for s in outcome.missingSlots]
    assert any("cashbook" in s for s in slot_names)
    assert any("bank" in s for s in slot_names)
    assert any("period_from" in s or "period" in s for s in slot_names)
    assert any("period_to" in s or "period" in s for s in slot_names)
    assert "reconcil" in outcome.responseMessage.lower() or "missing" in outcome.responseMessage.lower()


def test_reconciliation_intent_partial_slots():
    gate = IntakeGate()
    payload = {
        "cashbook_file": "inputs/cashbook_april2026.xlsx",
        "bank_statement_file": "inputs/bank_statement_april2026.csv",
    }
    outcome = gate.evaluate_intent("Reconcile April accounts", payload=payload)
    assert outcome.isReadyForExecution is False
    slot_names = [s.lower() for s in outcome.missingSlots]
    assert not any("cashbook" in s for s in slot_names)
    assert not any("bank" in s for s in slot_names)
    assert any("period_from" in s for s in slot_names)
    assert any("period_to" in s for s in slot_names)


def test_reconciliation_complete_slots_synthesizes_contract(tmp_path):
    gate = IntakeGate()
    payload = {
        "cashbook_file": "inputs/cashbook.xlsx",
        "bank_statement_file": "inputs/bank_statement.csv",
        "period_from": "2026-04-01",
        "period_to": "2026-04-30",
        "opening_balance_source": "cashbook",
        "date_tolerance_days": 3,
        "amount_exact": True,
        "output_folder": "workspace_sandbox/recon_run_01"
    }
    outcome = gate.evaluate_intent("Execute full reconciliation", payload=payload)
    assert outcome.isReadyForExecution is True
    assert outcome.contract is not None
    contract = outcome.contract
    assert contract.status == TaskContractStatus.ACTIVE
    assert contract.tierCeiling == TierLevel.T1
    assert contract.constraints.get("networkAllowed") is False
    assert contract.constraints.get("shellAllowed") is False
    assert contract.constraints.get("readOnlyInput") is True
    assert contract.constraints.get("writeOnlyOutput") is True
    assert contract.reconciliationParameters is not None
    assert contract.reconciliationParameters.cashbook_file == "inputs/cashbook.xlsx"
    assert contract.reconciliationParameters.bank_statement_file == "inputs/bank_statement.csv"
    assert contract.reconciliationParameters.period_from == "2026-04-01"
    assert contract.reconciliationParameters.period_to == "2026-04-30"
    assert contract.reconciliationParameters.date_tolerance_days == 3


def test_reconciliation_contract_policy_ceiling():
    policy = PolicyEngine(signing_key=b"test_secret_key_reconciliation_32b")
    recon_params = ReconciliationParameters(
        cashbook_file="inputs/cashbook.xlsx",
        bank_statement_file="inputs/bank.csv",
        period_from="2026-04-01",
        period_to="2026-04-30",
        opening_balance_source="cashbook",
        date_tolerance_days=3,
        amount_exact=True,
        output_folder="workspace_sandbox/recon_out"
    )
    contract = TaskContract(
        goal="Reconcile April",
        constraints={
            "networkAllowed": False,
            "shellAllowed": False,
            "readOnlyInput": True,
            "writeOnlyOutput": True,
        },
        tierCeiling=TierLevel.T1,
        reconciliationParameters=recon_params
    )

    # Shell execution must be quarantined/blocked under T1 contract ceiling
    shell_req = ActionRequest(
        intent="Run shell command",
        privilegeTier=PrivilegeTier.PERSON,
        safetyTier=SafetyTier.MUTATING,
        payload={"command": "powershell -c whoami"}
    )
    verdict = policy.evaluate(shell_req, contract=contract, tool_name="execute_shell_command")
    assert verdict.tierLevel == TierLevel.T2
    assert verdict.requiresQuarantine is True

