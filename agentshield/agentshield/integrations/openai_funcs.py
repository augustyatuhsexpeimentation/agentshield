"""
agentshield.integrations.openai_funcs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Intercept OpenAI function/tool calls before execution.

Usage:
    from agentshield.integrations.openai_funcs import shield_function_call

    shield = AgentShield.from_policy("policies/default.yaml")

    # When your app receives a function call from OpenAI:
    result = shield_function_call(
        shield=shield,
        function_name=tool_call.function.name,
        arguments=json.loads(tool_call.function.arguments),
    )

    if not result.blocked:
        # Safe to execute
        output = execute_function(result.modified_arguments or arguments)
"""

from __future__ import annotations

import json
from typing import Any

from agentshield.core.interceptor import AgentShield
from agentshield.core.decision import InterceptionResult


def shield_function_call(
    shield: AgentShield,
    function_name: str,
    arguments: dict[str, Any] | str,
    agent_id: str = "openai_agent",
    session_id: str | None = None,
) -> InterceptionResult:
    """
    Run an OpenAI function call through AgentShield.

    Args:
        shield:        AgentShield instance.
        function_name: Name of the function the model wants to call.
        arguments:     Arguments dict, or JSON string from the API.
        agent_id:      Agent ID for policy lookup.
        session_id:    Optional session tracking.

    Returns:
        InterceptionResult — check .blocked before executing.
    """
    # OpenAI sometimes returns arguments as a JSON string
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            arguments = {"raw_input": arguments}

    return shield.intercept(
        tool_name=function_name,
        arguments=arguments,
        agent_id=agent_id,
        session_id=session_id,
    )