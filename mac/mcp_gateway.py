"""
US Neural - Mycelium Semantic Protocol & HOL Guard
Module: mcp_gateway.py
Description: Production-grade Model Context Protocol (MCP) Gateway.
             Features Mycelium's local semantic vector-mesh for tool discovery
             and strict Pydantic v2 argument validation. Zero prompt-stuffing.
"""

from __future__ import annotations

import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field, ValidationError

from protocol import SafetyTier, ToolDefinition, ToolMatchResult


class ToolExecutionError(Exception):
    """Raised when an MCP tool fails during execution."""
    pass


class ToolValidationError(ValueError):
    """Raised when incoming parameters fail Pydantic schema validation."""
    pass


class SemanticVectorMesh:
    """
    Mycelium Local Semantic Vector-Mesh.
    Provides in-memory semantic discovery (benchmarked typically <1ms)
    ranking across tool definitions without relying on external APIs or slow embedding models.
    
    Uses character 3-gram and tokenized term-frequency with sublinear scaling
    and normalized cosine dot-product indexing.
    """

    def __init__(self):
        self._tool_vectors: Dict[str, Dict[str, float]] = {}
        self._tool_norms: Dict[str, float] = {}

    @staticmethod
    def _tokenize_and_ngram(text: str) -> List[str]:
        """Generate normalized words and character 3-grams for semantic matching."""
        clean = re.sub(r"[^\w\s-]", " ", text.lower())
        tokens = [tok for tok in clean.split() if tok]
        features = list(tokens)

        # Generate character 3-grams for matching typos and inflections
        for tok in tokens:
            if len(tok) >= 3:
                for i in range(len(tok) - 2):
                    features.append(f"ng:{tok[i:i+3]}")
        return features

    def index_tool(self, tool_name: str, semantic_text: str):
        """Index a tool into the semantic mesh vector space."""
        features = self._tokenize_and_ngram(semantic_text)
        if not features:
            self._tool_vectors[tool_name] = {}
            self._tool_norms[tool_name] = 0.0
            return

        # Compute term frequency with sublinear dampening: tf = 1 + ln(count)
        counts: Dict[str, int] = {}
        for feat in features:
            counts[feat] = counts.get(feat, 0) + 1

        vec: Dict[str, float] = {}
        sum_sq = 0.0
        for feat, count in counts.items():
            weight = 1.0 + math.log(count)
            vec[feat] = weight
            sum_sq += weight * weight

        norm = math.sqrt(sum_sq)
        self._tool_vectors[tool_name] = vec
        self._tool_norms[tool_name] = norm

    def query_similarity(self, query: str) -> List[Tuple[str, float]]:
        """
        Query the vector mesh and return ranked (tool_name, similarity) pairs.
        Executes in microsecond scale.
        """
        features = self._tokenize_and_ngram(query)
        if not features:
            return []

        counts: Dict[str, int] = {}
        for feat in features:
            counts[feat] = counts.get(feat, 0) + 1

        query_vec: Dict[str, float] = {}
        sum_sq = 0.0
        for feat, count in counts.items():
            weight = 1.0 + math.log(count)
            query_vec[feat] = weight
            sum_sq += weight * weight

        query_norm = math.sqrt(sum_sq)
        if query_norm == 0.0:
            return []

        results: List[Tuple[str, float]] = []
        for tool_name, tool_vec in self._tool_vectors.items():
            tool_norm = self._tool_norms.get(tool_name, 0.0)
            if tool_norm == 0.0:
                continue

            # Dot product between sparse features
            dot_prod = 0.0
            for feat, q_w in query_vec.items():
                if feat in tool_vec:
                    dot_prod += q_w * tool_vec[feat]

            sim = dot_prod / (query_norm * tool_norm)
            results.append((tool_name, round(sim, 4)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results


class RegisteredTool:
    """Internal registry record for an MCP tool."""
    def __init__(
        self,
        definition: ToolDefinition,
        schema_model: Type[BaseModel],
        handler: Callable[..., Any]
    ):
        self.definition = definition
        self.schema_model = schema_model
        self.handler = handler


class MCPGateway:
    """
    Model Context Protocol Gateway.
    Manages tool registries, semantic discovery, and schema verification.
    """

    def __init__(self):
        self._tools: Dict[str, RegisteredTool] = {}
        self._mesh = SemanticVectorMesh()

    def register_tool(
        self,
        name: str,
        description: str,
        safety_tier: SafetyTier,
        schema_model: Type[BaseModel],
        handler: Callable[..., Any],
        tags: Optional[List[str]] = None
    ) -> None:
        """
        Register a new tool into the MCP Gateway and index it into the semantic vector mesh.
        """
        tag_list = tags or []
        parameters_schema = schema_model.model_json_schema()

        definition = ToolDefinition(
            name=name,
            description=description,
            safetyTier=safety_tier,
            parametersSchema=parameters_schema,
            tags=tag_list
        )

        record = RegisteredTool(
            definition=definition,
            schema_model=schema_model,
            handler=handler
        )
        self._tools[name] = record

        # Build composite text representation for semantic vector mesh indexing
        semantic_corpus = f"{name} {description} {' '.join(tag_list)} {' '.join(parameters_schema.get('properties', {}).keys())}"
        self._mesh.index_tool(name, semantic_corpus)

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Fetch tool definition by name."""
        record = self._tools.get(name)
        return record.definition if record else None

    def discover_tools(self, intent_or_query: str, top_k: int = 3) -> List[ToolMatchResult]:
        """
        Perform in-memory semantic matching against the registered tools mesh.
        Returns ranked tool matches with exact latency metrics.
        """
        start = time.perf_counter()
        matches = self._mesh.query_similarity(intent_or_query)
        latency_ms = round((time.perf_counter() - start) * 1000.0, 3)

        results: List[ToolMatchResult] = []
        for name, score in matches[:top_k]:
            record = self._tools.get(name)
            if record:
                results.append(
                    ToolMatchResult(
                        tool=record.definition,
                        similarityScore=score,
                        matchLatencyMs=latency_ms
                    )
                )
        return results

    def validate_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> BaseModel:
        """
        Validate incoming tool parameters against the tool's registered Pydantic v2 schema.
        :raises ToolValidationError: If parameters fail validation.
        """
        record = self._tools.get(tool_name)
        if not record:
            raise KeyError(f"Tool '{tool_name}' is not registered in MCP Gateway.")

        try:
            validated = record.schema_model.model_validate(arguments)
            return validated
        except ValidationError as err:
            raise ToolValidationError(
                f"Schema Validation Failed for tool '{tool_name}':\n{err.json(indent=2)}"
            ) from err

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Validate arguments and invoke the registered tool handler.
        """
        record = self._tools.get(tool_name)
        if not record:
            raise KeyError(f"Tool '{tool_name}' not found.")

        validated_model = self.validate_arguments(tool_name, arguments)
        try:
            return record.handler(**validated_model.model_dump())
        except Exception as exc:
            raise ToolExecutionError(
                f"Execution failed inside tool handler for '{tool_name}': {str(exc)}"
            ) from exc


# ---------------------------------------------------------------------------
# Default Core Tool Parameter Schemas (Pydantic v2)
# ---------------------------------------------------------------------------

class ReadWorkspaceFileParams(BaseModel):
    file_path: str = Field(..., description="Path to the file to read relative to workspace.")


class WriteWorkspaceFileParams(BaseModel):
    file_path: str = Field(..., description="Path to the file to write relative to workspace.")
    content: str = Field(..., description="UTF-8 text content to write into the file.")


class ExecuteShellCommandParams(BaseModel):
    command: str = Field(..., description="OS shell command line string to run.")
    timeout_seconds: float = Field(default=15.0, description="Max runtime before process termination.")


class SystemDiagnosticsParams(BaseModel):
    include_environment: bool = Field(default=False, description="Whether to include sanitized system environment variables.")


class ListDirectoryParams(BaseModel):
    directory_path: str = Field(default=".", description="Relative workspace folder path to list.")
