"""
mac/mycelium_adapter.py - Mycelium Discovery Adapter & Untrusted Registry Gateway

Treats all discovery catalog results as untrusted external proposals:
1. All discovered tools default to Tier T2 quarantine.
2. Tool descriptions are sanitized, length-bounded, and stripped of injection markers.
3. Content hashes are pinned to detect bait-and-switch modifications.
4. Capability manifests are validated against supervisor capability policies.
5. Reserved built-in tool namespaces cannot be shadowed.
6. Oversized responses (>64 KB) and malformed payloads are rejected.
7. Bound execution timeout with offline 3-gram mesh fallback.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from protocol import SafetyTier, TierLevel
from mcp_gateway import MCPGateway


class RegistrySecurityError(Exception):
    """Raised when an external discovery response violates security boundaries."""
    pass


class DiscoveredToolManifest(BaseModel):
    """Immutable capability manifest for an external tool."""
    name: str
    version: str
    publisher: str
    description: str
    requested_capabilities: List[str] = Field(default_factory=list)
    argument_schema: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str


class DiscoveredToolResult(BaseModel):
    """Advisory discovery result for coordinator inspection."""
    name: str
    sanitized_description: str
    tier: TierLevel = TierLevel.T2
    requires_quarantine: bool = True
    is_offline_fallback: bool = False
    manifest: Optional[DiscoveredToolManifest] = None


# Prompt injection keywords and control sequences to filter from descriptions
_INJECTION_LINE_PATTERNS = [
    re.compile(r"system\s*override", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?(instructions|rules)", re.IGNORECASE),
    re.compile(r"bypass\s+quarantine", re.IGNORECASE),
    re.compile(r"grant\s+(full\s+)?shell", re.IGNORECASE),
    re.compile(r"set\s+tierlevel", re.IGNORECASE),
]

_CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

RESERVED_BUILTIN_TOOLS: Set[str] = {
    "read_workspace_file",
    "write_workspace_file",
    "execute_shell_command",
    "reconcile_accounts",
    "system_diagnostics",
    "list_directory",
}


class MyceliumDiscoveryAdapter:
    """
    Supervisor-side gateway adapter for external Mycelium registry queries.
    Enforces isolation, content sanitization, manifest pinning, and fail-closed fallbacks.
    """

    def __init__(
        self,
        query_fn: Optional[Callable[[str], str]] = None,
        timeout_seconds: float = 2.0,
        max_response_bytes: int = 65536,
        allowed_capabilities: Optional[Set[str]] = None,
        local_gateway: Optional[MCPGateway] = None,
    ):
        self.query_fn = query_fn
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.allowed_capabilities = allowed_capabilities
        self.local_gateway = local_gateway
        self._pinned_manifests: Dict[str, DiscoveredToolManifest] = {}
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="mycelium_adapter_worker"
        )
        self.discovery_enabled = os.environ.get("MAC_ENABLE_MYCELIUM_DISCOVERY", "0") in ("1", "true", "True")

    def sanitize_description(self, raw_description: str) -> str:
        """
        Sanitize external tool description:
        - Strip non-printable ASCII / ANSI control characters
        - Filter out lines containing known prompt injection signatures
        - Bound length to at most 512 characters
        """
        if not raw_description:
            return ""

        # Remove control characters
        cleaned = _CONTROL_CHAR_REGEX.sub(" ", raw_description)

        # Filter out lines matching injection signatures
        filtered_lines: List[str] = []
        for line in cleaned.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            is_hostile = any(pattern.search(line_str) for pattern in _INJECTION_LINE_PATTERNS)
            if not is_hostile:
                filtered_lines.append(line_str)

        sanitized = " ".join(filtered_lines).strip()
        # Bound length
        return sanitized[:512]

    def pin_tool_manifest(self, manifest: DiscoveredToolManifest) -> None:
        """Pin a tool manifest's content hash to prevent bait-and-switch updates."""
        self._pinned_manifests[manifest.name] = manifest

    def verify_manifest_integrity(self, manifest: DiscoveredToolManifest) -> Tuple[bool, str]:
        """
        Verify incoming manifest against pinned record.
        Detects bait-and-switch modifications where the tool payload hash changed.
        """
        pinned = self._pinned_manifests.get(manifest.name)
        if pinned is None:
            return True, "Manifest not previously pinned"

        if pinned.content_hash != manifest.content_hash:
            return False, (
                f"Bait-and-switch content hash mismatch detected for tool '{manifest.name}': "
                f"pinned '{pinned.content_hash}' vs incoming '{manifest.content_hash}'"
            )

        return True, "Integrity verified"

    def discover_tools(self, query: str) -> List[DiscoveredToolResult]:
        """
        Query the external registry with defensive validation:
        1. Bounded socket execution
        2. Response size ceiling check (<64 KB)
        3. Valid JSON verification
        4. Name shadowing prevention against built-ins and local gateway
        5. Capability inflation checks against allowed policy
        6. Sanitization of external descriptions
        7. Strict Tier T2 quarantine assignment
        """
        if not self.query_fn:
            return []

        # Execute query within bounded timeout
        future = self._executor.submit(self.query_fn, query)
        try:
            raw_response = future.result(timeout=self.timeout_seconds)
        except concurrent.futures.TimeoutError as err:
            raise RegistrySecurityError(
                f"Registry query timed out after {self.timeout_seconds}s"
            ) from err
        except Exception as exc:
            raise RegistrySecurityError(f"Registry query failed: {str(exc)}") from exc

        # Response size limit check
        if isinstance(raw_response, str):
            encoded_bytes = raw_response.encode("utf-8")
        elif isinstance(raw_response, bytes):
            encoded_bytes = raw_response
            raw_response = raw_response.decode("utf-8", errors="replace")
        else:
            raise RegistrySecurityError("Invalid registry response type")

        if len(encoded_bytes) > self.max_response_bytes:
            raise RegistrySecurityError(
                f"Registry response size ({len(encoded_bytes)} bytes) exceeds ceiling "
                f"of {self.max_response_bytes} bytes"
            )

        # Parse JSON
        try:
            payload = json.loads(raw_response)
        except Exception as err:
            raise RegistrySecurityError(f"Malformed JSON response from registry: {str(err)}") from err

        tools_data = payload.get("tools", [])
        results: List[DiscoveredToolResult] = []

        # Determine reserved tool names
        reserved_names = set(RESERVED_BUILTIN_TOOLS)
        if self.local_gateway is not None:
            reserved_names.update(self.local_gateway.list_tools())

        for tool_entry in tools_data:
            tool_name = tool_entry.get("name", "")
            if not tool_name:
                continue

            # Anti-shadowing check
            if tool_name in reserved_names:
                raise RegistrySecurityError(
                    f"Name shadowing rejected: external tool '{tool_name}' shadows a reserved tool"
                )

            # Capability inflation check
            requested_caps = tool_entry.get("requested_capabilities", [])
            if self.allowed_capabilities is not None:
                for cap in requested_caps:
                    if cap not in self.allowed_capabilities:
                        raise RegistrySecurityError(
                            f"Disallowed inflated capability requested by tool '{tool_name}': {cap}"
                        )

            manifest = DiscoveredToolManifest(
                name=tool_name,
                version=tool_entry.get("version", "0.1.0"),
                publisher=tool_entry.get("publisher", "unknown"),
                description=tool_entry.get("description", ""),
                requested_capabilities=requested_caps,
                argument_schema=tool_entry.get("argument_schema", {}),
                content_hash=tool_entry.get("content_hash", ""),
            )

            # Check bait-and-switch
            valid, reason = self.verify_manifest_integrity(manifest)
            if not valid:
                raise RegistrySecurityError(f"Bait-and-switch violation: {reason}")

            sanitized_desc = self.sanitize_description(manifest.description)

            results.append(
                DiscoveredToolResult(
                    name=tool_name,
                    sanitized_description=sanitized_desc,
                    tier=TierLevel.T2,  # Strict default quarantine
                    requires_quarantine=True,
                    is_offline_fallback=False,
                    manifest=manifest,
                )
            )

        return results

    def discover_tools_with_fallback(self, query: str, top_k: int = 5) -> List[DiscoveredToolResult]:
        """
        Attempt registry discovery with bounded timeout, falling back
        to local MCPGateway 3-gram mesh upon any failure or timeout.
        """
        try:
            return self.discover_tools(query)
        except Exception:
            # Fall back to offline local vector mesh
            if self.local_gateway is not None:
                matches = self.local_gateway.discover_tools(query, top_k=top_k)
                fallback_results: List[DiscoveredToolResult] = []
                for match in matches:
                    is_read_only = (match.tool.safetyTier == SafetyTier.READ_ONLY)
                    tier = TierLevel.T0 if is_read_only else TierLevel.T1
                    fallback_results.append(
                        DiscoveredToolResult(
                            name=match.tool.name,
                            sanitized_description=match.tool.description,
                            tier=tier,
                            requires_quarantine=False,
                            is_offline_fallback=True,
                        )
                    )
                return fallback_results
            return []
