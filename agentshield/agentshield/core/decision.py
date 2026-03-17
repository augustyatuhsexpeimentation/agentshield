"""
agentshield.core.decision
~~~~~~~~~~~~~~~~~~~~~~~~~
Data models for tool call requests, policy results, and interception decisions.
Every action flowing through AgentShield is represented by these objects.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Action(Enum):
    """Decision made by the AgentShield security pipeline."""
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"   # Allowed, but arguments were redacted / sanitised


@dataclass
class ToolCallRequest:
    """
    Represents a single tool call issued by an AI agent.

    Attributes:
        tool_name:  Name of the tool / function being called.
        arguments:  Dict of keyword arguments passed to the tool.
        agent_id:   Identifier for the calling agent (maps to policy rules).
        session_id: Unique ID for the current conversation / session.
        timestamp:  Unix epoch when the request was created.
        metadata:   Arbitrary extra context (e.g. parent trace id).
    """
    tool_name: str
    arguments: dict[str, Any]
    agent_id: str = "default"
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        args_preview = str(self.arguments)[:80]
        return (
            f"ToolCallRequest(tool={self.tool_name!r}, "
            f"agent={self.agent_id!r}, args={args_preview})"
        )


@dataclass
class PolicyResult:
    """Outcome of evaluating a request against the YAML policy."""
    allowed: bool
    denied: bool = False
    reason: str = ""
    matched_rule: str = ""

    def __post_init__(self) -> None:
        self.denied = not self.allowed


@dataclass
class InterceptionResult:
    """
    Full result of the AgentShield interception pipeline.

    Carries the action decision, any threats detected, policy evaluation
    details, timing information, and (after execution) the tool's output.
    """
    action: Action
    original_request: ToolCallRequest
    modified_arguments: Optional[dict[str, Any]] = None
    tool_result: Any = None
    threats_detected: list[dict[str, Any]] = field(default_factory=list)
    policy_decisions: list[PolicyResult] = field(default_factory=list)
    latency_ms: float = 0.0
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def blocked(self) -> bool:
        return self.action == Action.DENY

    @property
    def was_modified(self) -> bool:
        return self.action == Action.MODIFY

    def summary(self) -> str:
        """One-line human-readable summary."""
        icon = {"allow": "✅", "deny": "🚫", "modify": "✏️"}[self.action.value]
        threats = len(self.threats_detected)
        return (
            f"{icon} {self.action.value.upper()} "
            f"tool={self.original_request.tool_name!r} "
            f"threats={threats} "
            f"latency={self.latency_ms:.1f}ms"
        )