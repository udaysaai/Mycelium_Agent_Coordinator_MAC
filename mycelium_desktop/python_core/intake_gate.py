"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: intake_gate.py
Description: Conversational Intake Gate & TaskContract Compiler.
             Filters greetings and conversational inquiries, fills required parameter
             slots, and compiles valid intent into immutable TaskContracts.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from protocol import TaskContract, TaskContractStatus, TierLevel


class IntakeOutcome(BaseModel):
    """
    Result of intake gate processing.
    """
    isConversational: bool = False
    responseMessage: str = ""
    isReadyForExecution: bool = False
    missingSlots: List[str] = Field(default_factory=list)
    contract: Optional[TaskContract] = None


class IntakeGate:
    """
    Plane 1: Conversational Parameter Intake & Plan Gate.
    Handles conversational greetings deterministically, guides vague user prompts
    into machine-checkable TaskContracts, and locks down execution predicates.
    """

    GREETING_PATTERNS = [
        r"^(hi|hello|hey|hola|namaste|greetings|howdy)\b",
        r"^(good morning|good afternoon|good evening|good night)\b",
        r"^(who are you|what are you|what can you do|help me|help)\b",
        r"^(kaise ho|kya hal hai|kya kar sakte ho)\b",
    ]

    MUTATION_KEYWORDS = [
        "write", "create", "save", "make", "dump", "export", "generate", "record"
    ]

    def __init__(self):
        pass

    def evaluate_intent(self, intent: str, payload: Optional[Dict[str, Any]] = None) -> IntakeOutcome:
        """
        Evaluate user intent and either respond conversationally, request missing slots,
        or synthesize a compiled TaskContract.
        """
        raw_text = (intent or "").strip()
        lower_text = raw_text.lower()
        payload = payload or {}

        # 1. Check conversational greetings & general queries
        for pattern in self.GREETING_PATTERNS:
            if re.search(pattern, lower_text):
                return IntakeOutcome(
                    isConversational=True,
                    responseMessage=(
                        "Hello! I am Mycelium Agent Coordinator (MAC)—your local-first governed execution harness. "
                        "I coordinate sandboxed code execution, local filesystem operations, and telemetry nodes under "
                        "strict out-of-band verification and Human-On-The-Loop quarantine gates. "
                        "How can I assist your workflow today?"
                    ),
                    isReadyForExecution=False
                )

        # 2. Check general conversational questions
        if lower_text.endswith("?") and not any(k in lower_text for k in ["file", "run", "write", "command", "check", "exec"]):
            return IntakeOutcome(
                isConversational=True,
                responseMessage=(
                    f"I received your inquiry: '{raw_text}'. As your local autonomous coordinator, "
                    "I can execute sandboxed filesystem mutations, introspect system telemetry, and govern multi-tier "
                    "actions. Specify a concrete task or target to compile an execution contract."
                ),
                isReadyForExecution=False
            )

        # 3. Slot-filling inspection for file creation/mutation intents
        is_mutation_intent = any(k in lower_text for k in self.MUTATION_KEYWORDS)
        if is_mutation_intent and not ("command" in payload) and payload.get("tool_name") != "execute_shell_command":
            has_path = bool(payload.get("file_path") or payload.get("filePath"))
            has_content = "content" in payload

            # Attempt regex extraction if payload is empty
            if not has_path:
                match = re.search(r"['\"]?([\w\-./\\]+\.[a-zA-Z0-9]+)['\"]?", raw_text)
                if match:
                    has_path = True
                    payload["file_path"] = match.group(1)

            missing_slots = []
            if not has_path:
                missing_slots.append("file_path (target path or filename)")

            if missing_slots:
                return IntakeOutcome(
                    isConversational=False,
                    responseMessage=(
                        f"Task intake requires missing parameters to compile execution contract: "
                        f"Please provide {', '.join(missing_slots)}."
                    ),
                    isReadyForExecution=False,
                    missingSlots=missing_slots
                )

        # 4. Synthesize valid TaskContract
        target_path = payload.get("file_path", payload.get("filePath", ""))
        predicate = {}
        if target_path:
            predicate = {
                "type": "file_exists",
                "path": target_path,
                "min_bytes": 1
            }

        contract = TaskContract(
            goal=raw_text,
            constraints={"timeoutSeconds": 30.0, "sandboxOnly": True},
            successPredicate=predicate,
            tierCeiling=TierLevel.T2,
            status=TaskContractStatus.ACTIVE
        )

        return IntakeOutcome(
            isConversational=False,
            responseMessage=f"Compiled TaskContract (ID: {contract.contractId[:8]}). Ready for policy evaluation.",
            isReadyForExecution=True,
            contract=contract
        )
