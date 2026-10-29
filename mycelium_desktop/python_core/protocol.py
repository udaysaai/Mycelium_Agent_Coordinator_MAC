"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: protocol.py
Description: Production-grade typed contracts, privilege tiers, safety classifications,
             and telemetry schemas for Split-Execution Architecture.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class PrivilegeTier(str, Enum):
    """Execution context privilege level."""
    PERSON = "PERSON"          # Foreground interactive user tasks requiring active session context
    BACKGROUND = "BACKGROUND"  # Automated background/unattended operations


class TierLevel(str, Enum):
    """Three-plane capability tier system for MAC governance."""
    T0 = "T0"  # Read-Only / Introspection / Telemetry (Zero friction, auto-approved)
    T1 = "T1"  # Reversible Sandbox Mutation (Audited, sandboxed, no blocking)
    T2 = "T2"  # Irreversible / Destructive / External Mutation (Mandatory quarantine)


class SafetyTier(str, Enum):
    """Operation risk and mutating boundary classification."""
    READ_ONLY = "READ_ONLY"                # Safe introspection, metrics, read queries (T0)
    MUTATING_SANDBOX = "MUTATING_SANDBOX"  # Sandboxed reversible file writes/computes (T1)
    MUTATING = "MUTATING"                  # State-altering operations requiring operator sign-off (T2)
    IRREVERSIBLE = "IRREVERSIBLE"          # Explicit irreversible action alias (T2)


class HOLApprovalStatus(str, Enum):
    """Human-On-The-Loop evaluation status."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REJECTED_TIMEOUT = "REJECTED_TIMEOUT"
    BYPASS_READ_ONLY = "BYPASS_READ_ONLY"


class TaskContractStatus(str, Enum):
    """Lifecycle status of a governed TaskContract."""
    INTAKE = "INTAKE"
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class TaskContract(BaseModel):
    """
    Immutable specification contract binding user goals to machine-checkable predicates.
    Enforces strict immutability (frozen=True) to prevent in-flight tampering.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True, frozen=True)

    contractId: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique TaskContract identifier."
    )
    goal: str = Field(
        ...,
        description="Primary objective or goal description."
    )
    constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Execution constraints (timeout, memory, sandbox bounds)."
    )
    successPredicate: Dict[str, Any] = Field(
        default_factory=dict,
        description="Machine-checkable success predicate (e.g. file_exists, hash_match, schema_valid)."
    )
    tierCeiling: TierLevel = Field(
        default=TierLevel.T2,
        description="Maximum privilege/safety tier permitted for this contract."
    )
    status: TaskContractStatus = Field(
        default=TaskContractStatus.INTAKE,
        description="Current contract lifecycle status."
    )
    createdAt: float = Field(
        default_factory=time.time,
        description="Timestamp when contract was synthesized."
    )
    completedAt: Optional[float] = Field(
        default=None,
        description="Timestamp when contract reached terminal state."
    )


class VerificationReceipt(BaseModel):
    """
    Deterministic, out-of-band SHA-256 proof of real-world state alteration.
    Never generated or graded by the acting agent.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    receiptId: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this proof receipt."
    )
    contractId: Optional[str] = Field(
        default=None,
        description="Associated TaskContract ID if present."
    )
    requestId: str = Field(
        ...,
        description="Correlated ActionRequest identifier."
    )
    toolName: str = Field(
        ...,
        description="Tool whose real-world effect was inspected."
    )
    verified: bool = Field(
        ...,
        description="Outcome of independent out-of-band state assertion."
    )
    predicateType: str = Field(
        default="read_back",
        description="Type of verification applied (e.g. file_exists, http_status, state_diff)."
    )
    checksum: str = Field(
        default="",
        description="SHA-256 hash of the modified resource or state."
    )
    stateDiff: Dict[str, Any] = Field(
        default_factory=dict,
        description="Deterministic state before/after diff details."
    )
    timestamp: float = Field(
        default_factory=time.time,
        description="Timestamp when verification assertion occurred."
    )
    verifierNotes: str = Field(
        default="",
        description="Diagnostic or explanatory notes from the verifier engine."
    )


class ActionRequest(BaseModel):
    """
    Standard incoming action envelope dispatched through the Mycelium Coordinator.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    requestId: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique telemetry tracking identifier."
    )
    contractId: Optional[str] = Field(
        default=None,
        description="Associated TaskContract ID."
    )
    intent: str = Field(
        ...,
        description="Natural language or semantic intent description."
    )
    privilegeTier: PrivilegeTier = Field(
        ...,
        description="Privilege level of the execution caller."
    )
    safetyTier: SafetyTier = Field(
        ...,
        description="Assigned or inferred safety classification."
    )
    tierLevel: Optional[TierLevel] = Field(
        default=None,
        description="Direct three-tier capability classification (T0, T1, T2)."
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured parameter dictionary for the action."
    )
    oneShotToken: Optional[str] = Field(
        default=None,
        description="HMAC-SHA256 signed one-shot authorization token for T2 mutations."
    )
    timestamp: float = Field(
        default_factory=time.time,
        description="Epoch timestamp when request was synthesized."
    )


class ExecutionResult(BaseModel):
    """
    Structured outcome returned by the isolated execution daemon.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    requestId: str = Field(
        ...,
        description="Correlation ID linking back to the ActionRequest."
    )
    contractId: Optional[str] = Field(
        default=None,
        description="Correlated TaskContract ID."
    )
    success: bool = Field(
        ...,
        description="Flag indicating whether execution finished cleanly."
    )
    stdout: str = Field(
        default="",
        description="Standard output stream captured from process/tool."
    )
    stderr: str = Field(
        default="",
        description="Standard error stream or failure diagnostics."
    )
    exitCode: int = Field(
        default=0,
        description="Process exit code (0 = clean, non-zero = failure, -1 = timeout)."
    )
    latencyMs: float = Field(
        default=0.0,
        description="Execution wall-clock latency in milliseconds."
    )
    tierLevel: Optional[TierLevel] = Field(
        default=None,
        description="Tier at which action was executed."
    )
    receipt: Optional[VerificationReceipt] = Field(
        default=None,
        description="Out-of-band verification receipt."
    )


class HOLQuarantineEvent(BaseModel):
    """
    Audit record generated when an action is quarantined by HOL Guard.
    """
    model_config = ConfigDict(extra="ignore")

    quarantineId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    contractId: Optional[str] = None
    request: ActionRequest
    quarantineReason: str
    decision: HOLApprovalStatus = HOLApprovalStatus.PENDING
    callHash: str = Field(
        default="",
        description="SHA-256 fingerprint of the tool, arguments, and target."
    )
    oneShotToken: str = Field(
        default="",
        description="HMAC-SHA256 signed one-time token required to unlock execution."
    )
    plainImpact: str = Field(
        default="",
        description="Plain-language human explanation of the action's real-world impact."
    )
    expiresAt: float = Field(
        default=0.0,
        description="Epoch timestamp after which quarantine auto-rejects (default 15 mins)."
    )
    operatorId: Optional[str] = None
    operatorNotes: Optional[str] = None
    quarantinedAt: float = Field(default_factory=time.time)
    reviewedAt: Optional[float] = None


class ToolDefinition(BaseModel):
    """
    Model Context Protocol (MCP) tool contract.
    """
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Canonical tool identifier.")
    description: str = Field(..., description="Semantic purpose of the tool.")
    safetyTier: SafetyTier = Field(..., description="Safety classification of the tool.")
    tierLevel: TierLevel = Field(default=TierLevel.T0, description="Capability tier (T0, T1, T2).")
    parametersSchema: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema or Pydantic field definition dict."
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Semantic keywords for vector mesh indexing."
    )


class ToolMatchResult(BaseModel):
    """
    Vector-mesh match result returned by the semantic discovery engine.
    """
    model_config = ConfigDict(extra="ignore")

    tool: ToolDefinition
    similarityScore: float = Field(..., ge=0.0, le=1.0)
    matchLatencyMs: float = Field(..., ge=0.0)
