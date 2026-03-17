"""
🛡️ AgentShield — Security firewall for AI agents.

Usage:
    from agentshield import AgentShield

    shield = AgentShield.from_policy("policies/default.yaml")

    @shield.protect
    def my_tool(query: str) -> str:
        return db.execute(query)
"""

__version__ = "0.1.0"

from agentshield.core.interceptor import AgentShield, ToolCallBlocked
from agentshield.core.decision import Action, InterceptionResult, ToolCallRequest
from agentshield.core.session import AgentSession

__all__ = [
    "AgentShield",
    "ToolCallBlocked",
    "Action",
    "InterceptionResult",
    "ToolCallRequest",
    "AgentSession",
    "__version__",
]