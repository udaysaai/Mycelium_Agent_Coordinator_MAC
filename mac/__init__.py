"""
US Neural - Mycelium Agent Coordinator (MAC) & HOL Guard
Split-Execution Architecture for Autonomous Agent Fleets.
"""

from protocol import (
    ActionRequest,
    ExecutionResult,
    HOLApprovalStatus,
    HOLQuarantineEvent,
    PrivilegeTier,
    SafetyTier,
    ToolDefinition,
    ToolMatchResult,
)
from local_daemon import LocalExecDaemon, WorkspaceSecurityError
from mcp_gateway import (
    ExecuteShellCommandParams,
    ListDirectoryParams,
    MCPGateway,
    ReadWorkspaceFileParams,
    SystemDiagnosticsParams,
    ToolExecutionError,
    ToolValidationError,
    WriteWorkspaceFileParams,
)
from coordinator import MyceliumCoordinator

__version__ = "1.0.0"
__author__ = "US Neural Systems Architecture Team"

__all__ = [
    "ActionRequest",
    "ExecutionResult",
    "HOLApprovalStatus",
    "HOLQuarantineEvent",
    "PrivilegeTier",
    "SafetyTier",
    "ToolDefinition",
    "ToolMatchResult",
    "LocalExecDaemon",
    "WorkspaceSecurityError",
    "MCPGateway",
    "ToolExecutionError",
    "ToolValidationError",
    "ReadWorkspaceFileParams",
    "WriteWorkspaceFileParams",
    "ExecuteShellCommandParams",
    "SystemDiagnosticsParams",
    "ListDirectoryParams",
    "MyceliumCoordinator",
]
