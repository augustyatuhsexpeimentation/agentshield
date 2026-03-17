"""
agentshield.integrations.mcp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Security layer for Model Context Protocol (MCP) tool calls.

Intercepts MCP tool invocations before they reach the server,
and scans MCP tool descriptions for poisoning on registration.

Usage:
    from agentshield.integrations.mcp import MCPShield

    mcp_shield = MCPShield(policy_path="policies/default.yaml")

    # Scan a tool description when an MCP server registers it
    findings = mcp_shield.scan_tool_registration(
        tool_name="database_query",
        description=tool.description,
    )

    # Intercept a tool call before it reaches the MCP server
    result = mcp_shield.intercept_tool_call(
        tool_name="database_query",
        arguments={"sql": "SELECT * FROM users"},
    )
"""

from __future__ import annotations

from typing import Any

from agentshield.core.interceptor import AgentShield
from agentshield.core.decision import Action, InterceptionResult
from agentshield.detectors.tool_poisoning import ToolPoisoningDetector
from agentshield.detectors.base import Finding


class MCPShield:
    """
    Security wrapper for MCP (Model Context Protocol) connections.

    Provides two layers of protection:
    1. Tool registration scanning — detect poisoned tool descriptions
    2. Tool call interception — enforce policies on every invocation
    """

    def __init__(
        self,
        policy_path: str = "policies/default.yaml",
        agent_id: str = "mcp_agent",
        verbose: bool = True,
    ) -> None:
        self._shield = AgentShield.from_policy(
            policy_path, verbose=verbose,
        )
        self._agent_id = agent_id
        self._registered_tools: dict[str, dict[str, Any]] = {}
        self._blocked_tools: set[str] = set()

    def scan_tool_registration(
        self,
        tool_name: str,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Scan an MCP tool's description for poisoning attacks.
        Call this when an MCP server advertises its tools.

        Returns list of findings.  If any are CRITICAL/HIGH,
        the tool is added to the blocked list.
        """
        findings = ToolPoisoningDetector.scan_tool_description(description)

        self._registered_tools[tool_name] = {
            "description": description,
            "metadata": metadata or {},
            "findings": [f.to_dict() for f in findings],
            "blocked": any(f.level.value >= 3 for f in findings),  # HIGH+
        }

        if self._registered_tools[tool_name]["blocked"]:
            self._blocked_tools.add(tool_name)

        return findings

    def intercept_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str | None = None,
    ) -> InterceptionResult:
        """
        Intercept an MCP tool call before it reaches the server.

        If the tool was flagged during registration, it's auto-blocked.
        Otherwise, runs through the full AgentShield pipeline.
        """
        # Auto-block tools flagged during registration
        if tool_name in self._blocked_tools:
            from agentshield.core.decision import (
                InterceptionResult, Action, ToolCallRequest,
            )
            request = ToolCallRequest(
                tool_name=tool_name,
                arguments=arguments,
                agent_id=self._agent_id,
            )
            return InterceptionResult(
                action=Action.DENY,
                original_request=request,
                threats_detected=[{
                    "detector": "mcp_shield",
                    "level": "CRITICAL",
                    "description": (
                        f"Tool '{tool_name}' was flagged as poisoned "
                        f"during registration"
                    ),
                    "evidence": "",
                }],
            )

        return self._shield.intercept(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self._agent_id,
            session_id=session_id,
        )

    @property
    def blocked_tools(self) -> set[str]:
        return set(self._blocked_tools)

    @property
    def registered_tools(self) -> dict[str, dict[str, Any]]:
        return dict(self._registered_tools)