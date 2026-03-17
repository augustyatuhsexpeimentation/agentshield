"""
agentshield.core.session
~~~~~~~~~~~~~~~~~~~~~~~~
Per-agent, per-session state tracking.
Implements sliding-window rate limiting for tool calls.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RateLimit:
    """Rate limit rule: max N calls within a sliding window."""
    max_calls: int
    window_seconds: float


@dataclass
class AgentSession:
    """
    Tracks runtime state for a single agent session.

    Each unique (agent_id, session_id) pair gets its own session.
    Sessions are created lazily on the first intercepted call.
    """
    agent_id: str
    session_id: str
    rate_limits: dict[str, RateLimit] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    total_calls: int = 0
    allowed_calls: int = 0
    blocked_calls: int = 0
    _call_log: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def check_rate_limit(self, tool_name: str) -> bool:
        """
        Check whether a tool call is within the configured rate limits.

        Looks up a tool-specific limit first, then falls back to the
        wildcard "*" limit.  Returns True if the call is permitted.
        """
        limit = self.rate_limits.get(tool_name) or self.rate_limits.get("*")
        self.total_calls += 1

        if limit is None:
            # No rate limit configured → always allow
            self.allowed_calls += 1
            return True

        now = time.time()
        cutoff = now - limit.window_seconds

        # Prune timestamps outside the current window
        self._call_log[tool_name] = [
            ts for ts in self._call_log[tool_name] if ts > cutoff
        ]

        if len(self._call_log[tool_name]) >= limit.max_calls:
            self.blocked_calls += 1
            return False

        self._call_log[tool_name].append(now)
        self.allowed_calls += 1
        return True

    def reset(self) -> None:
        """Clear all call history (useful in tests)."""
        self._call_log.clear()
        self.total_calls = 0
        self.allowed_calls = 0
        self.blocked_calls = 0

    def get_stats(self) -> dict[str, Any]:
        """Return a snapshot of session statistics."""
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "total_calls": self.total_calls,
            "allowed_calls": self.allowed_calls,
            "blocked_calls": self.blocked_calls,
            "active_tools": list(self._call_log.keys()),
            "uptime_seconds": round(time.time() - self.created_at, 1),
        }