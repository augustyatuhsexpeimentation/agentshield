"""Tests for session management and rate limiting."""

import time
import pytest
from agentshield.core.session import AgentSession, RateLimit


class TestRateLimiting:
    def test_allows_within_limit(self):
        session = AgentSession(
            agent_id="test",
            session_id="s1",
            rate_limits={"*": RateLimit(max_calls=5, window_seconds=60)},
        )
        for _ in range(5):
            assert session.check_rate_limit("any_tool") is True

    def test_blocks_over_limit(self):
        session = AgentSession(
            agent_id="test",
            session_id="s1",
            rate_limits={"*": RateLimit(max_calls=3, window_seconds=60)},
        )
        assert session.check_rate_limit("tool") is True
        assert session.check_rate_limit("tool") is True
        assert session.check_rate_limit("tool") is True
        assert session.check_rate_limit("tool") is False

    def test_tool_specific_limit(self):
        session = AgentSession(
            agent_id="test",
            session_id="s1",
            rate_limits={
                "*": RateLimit(max_calls=100, window_seconds=60),
                "expensive_tool": RateLimit(max_calls=2, window_seconds=60),
            },
        )
        assert session.check_rate_limit("expensive_tool") is True
        assert session.check_rate_limit("expensive_tool") is True
        assert session.check_rate_limit("expensive_tool") is False
        # Other tools still work
        assert session.check_rate_limit("cheap_tool") is True

    def test_no_limit_always_allows(self):
        session = AgentSession(
            agent_id="test",
            session_id="s1",
            rate_limits={},
        )
        for _ in range(1000):
            assert session.check_rate_limit("any_tool") is True

    def test_window_expiry(self):
        session = AgentSession(
            agent_id="test",
            session_id="s1",
            rate_limits={"*": RateLimit(max_calls=2, window_seconds=0.1)},
        )
        assert session.check_rate_limit("tool") is True
        assert session.check_rate_limit("tool") is True
        assert session.check_rate_limit("tool") is False
        time.sleep(0.15)  # Wait for window to expire
        assert session.check_rate_limit("tool") is True


class TestSessionStats:
    def test_stats_tracking(self):
        session = AgentSession(
            agent_id="bot",
            session_id="s1",
            rate_limits={"*": RateLimit(max_calls=2, window_seconds=60)},
        )
        session.check_rate_limit("tool")
        session.check_rate_limit("tool")
        session.check_rate_limit("tool")  # This one blocked

        stats = session.get_stats()
        assert stats["total_calls"] == 3
        assert stats["allowed_calls"] == 2
        assert stats["blocked_calls"] == 1

    def test_reset(self):
        session = AgentSession(
            agent_id="bot",
            session_id="s1",
            rate_limits={"*": RateLimit(max_calls=1, window_seconds=60)},
        )
        session.check_rate_limit("tool")
        assert session.check_rate_limit("tool") is False
        session.reset()
        assert session.check_rate_limit("tool") is True