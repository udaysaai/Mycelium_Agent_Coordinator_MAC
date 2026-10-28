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


class SafetyTier(str, Enum):
    """Operation risk and mutating boundary classification."""
    READ_ONLY = "READ_ONLY"    # Safe introspection, metrics, read queries (Auto-approved)
    MUTATING = "MUTATING"      # State-altering operations (file writes, bash commands, deletes)


class HOLApprovalStatus(str, Enum):
    """Human-On-The-Loop evaluation status."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    BYPASS_READ_ONLY = "BYPASS_READ_ONLY"


class ActionRequest(BaseModel):
    """
    Standard incoming action envelope dispatched through the Mycelium Coordinator.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    requestId: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique telemetry tracking identifier."
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
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured parameter dictionary for the action."
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


class HOLQuarantineEvent(BaseModel):
    """
    Audit record generated when an action is quarantined by HOL Guard.
    """
    model_config = ConfigDict(extra="ignore")

    quarantineId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request: ActionRequest
    quarantineReason: str
    decision: HOLApprovalStatus = HOLApprovalStatus.PENDING
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
