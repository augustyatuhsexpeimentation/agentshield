"""
agentshield.integrations.crewai
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wrap CrewAI tools with AgentShield protection.

Usage:
    from crewai_tools import tool
    from agentshield.integrations.crewai import shield_crewai_tools

    @tool("Search")
    def search(query: str) -> str:
        return "results"

    protected = shield_crewai_tools([search], policy_path="policies/default.yaml")
"""

from __future__ import annotations

from typing import Any

from agentshield.core.interceptor import AgentShield


def shield_crewai_tools(
    tools: list[Any],
    policy_path: str = "policies/default.yaml",
    agent_id: str = "default",
    verbose: bool = True,
) -> list[Any]:
    """
    Wrap a list of CrewAI tools with AgentShield.

    Preserves tool metadata while adding security interception
    to the underlying function.
    """
    shield = AgentShield.from_policy(policy_path, verbose=verbose)
    protected: list[Any] = []

    for t in tools:
        tool_name = getattr(t, "name", None) or getattr(t, "__name__", "unknown")
        original_run = getattr(t, "_run", None) or getattr(t, "func", None)

        if original_run is None:
            protected.append(t)
            continue

        @shield.protect(agent_id=agent_id)
        def _wrapped(*args: Any, _orig=original_run, **kwargs: Any) -> Any:
            return _orig(*args, **kwargs)

        _wrapped.__name__ = tool_name

        try:
            if hasattr(t, "_run"):
                t._run = _wrapped
            elif hasattr(t, "func"):
                t.func = _wrapped
        except Exception:
            pass

        protected.append(t)

    return protected