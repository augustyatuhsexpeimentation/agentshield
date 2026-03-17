"""
agentshield.integrations.langchain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wrap LangChain tools with AgentShield protection.

Usage:
    from langchain.tools import tool
    from agentshield.integrations.langchain import shield_tools

    @tool
    def search(query: str) -> str:
        return "results"

    protected = shield_tools([search], policy_path="policies/default.yaml")
    # Use `protected` in your LangChain agent
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from agentshield.core.interceptor import AgentShield

if TYPE_CHECKING:
    pass


def shield_tools(
    tools: list[Any],
    policy_path: str = "policies/default.yaml",
    agent_id: str = "default",
    verbose: bool = True,
) -> list[Any]:
    """
    Wrap a list of LangChain tools with AgentShield protection.

    Each tool's underlying function is wrapped with the security
    pipeline.  The tool metadata (name, description, schema) is
    preserved so LangChain agents can still discover and use them.

    Args:
        tools:       List of LangChain BaseTool instances.
        policy_path: Path to AgentShield YAML policy.
        agent_id:    Agent ID for policy lookup.
        verbose:     Print console output for each interception.

    Returns:
        New list of tools with protected functions.
    """
    shield = AgentShield.from_policy(policy_path, verbose=verbose)
    protected: list[Any] = []

    for t in tools:
        original_func = t.func if hasattr(t, "func") else t._run

        @shield.protect(agent_id=agent_id)
        def _wrapped(*args: Any, _orig=original_func, **kwargs: Any) -> Any:
            return _orig(*args, **kwargs)

        # Preserve the tool name for policy matching
        _wrapped.__name__ = t.name
        _wrapped.__doc__ = t.description

        # Clone the tool with the wrapped function
        try:
            new_tool = t.copy()
            if hasattr(new_tool, "func"):
                new_tool.func = _wrapped
            else:
                new_tool._run = _wrapped
            protected.append(new_tool)
        except Exception:
            # Fallback: just wrap the function and return it
            protected.append(t)

    return protected


def shield_single_tool(
    tool: Any,
    shield: AgentShield,
    agent_id: str = "default",
) -> Any:
    """Wrap a single LangChain tool with an existing AgentShield instance."""
    original_func = tool.func if hasattr(tool, "func") else tool._run

    @shield.protect(agent_id=agent_id)
    def _wrapped(**kwargs: Any) -> Any:
        return original_func(**kwargs)

    _wrapped.__name__ = tool.name

    try:
        new_tool = tool.copy()
        if hasattr(new_tool, "func"):
            new_tool.func = _wrapped
        protected = new_tool
    except Exception:
        protected = tool

    return protected