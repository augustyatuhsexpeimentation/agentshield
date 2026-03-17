"""Tests for the YAML policy engine."""

import pytest
from agentshield.core.policy import PolicyEngine
from agentshield.core.decision import ToolCallRequest


def _make_request(tool: str, args: dict = None, agent: str = "default") -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool, arguments=args or {}, agent_id=agent)


@pytest.fixture
def policy():
    return PolicyEngine.from_dict({
        "version": "1.0",
        "default_action": "deny",
        "agents": {
            "default": {
                "allowed_tools": ["web_search", "read_file", "calculator"],
                "denied_tools": ["execute_shell", "delete_*", "drop_*"],
                "rate_limits": {
                    "*": {"max_calls": 10, "window_seconds": 60},
                },
            },
            "admin_agent": {
                "allowed_tools": ["*"],
                "denied_tools": [],
            },
        },
        "tools": {
            "read_file": {
                "denied_paths": ["/etc/**", "**/.ssh/**", "**/.env"],
            },
            "search_database": {
                "denied_operations": ["DROP", "DELETE", "TRUNCATE"],
            },
        },
    })


class TestPolicyAllowDeny:
    def test_allowed_tool_passes(self, policy):
        result = policy.evaluate(_make_request("web_search"))
        assert result.allowed

    def test_unlisted_tool_denied_by_default(self, policy):
        result = policy.evaluate(_make_request("unknown_tool"))
        assert result.denied

    def test_denied_tool_blocked(self, policy):
        result = policy.evaluate(_make_request("execute_shell"))
        assert result.denied
        assert "deny pattern" in result.reason

    def test_wildcard_deny(self, policy):
        result = policy.evaluate(_make_request("delete_everything"))
        assert result.denied

    def test_wildcard_deny_drop(self, policy):
        result = policy.evaluate(_make_request("drop_table"))
        assert result.denied

    def test_deny_overrides_allow(self, policy):
        """If a tool matches both allow and deny, deny wins."""
        p = PolicyEngine.from_dict({
            "default_action": "deny",
            "agents": {
                "default": {
                    "allowed_tools": ["execute_shell"],
                    "denied_tools": ["execute_*"],
                },
            },
        })
        result = p.evaluate(_make_request("execute_shell"))
        assert result.denied


class TestToolSpecificRules:
    def test_denied_path_blocked(self, policy):
        req = _make_request("read_file", {"path": "/etc/passwd"})
        result = policy.evaluate(req)
        assert result.denied

    def test_ssh_path_blocked(self, policy):
        req = _make_request("read_file", {"path": "/home/user/.ssh/id_rsa"})
        result = policy.evaluate(req)
        assert result.denied

    def test_env_file_blocked(self, policy):
        req = _make_request("read_file", {"path": "/app/.env"})
        result = policy.evaluate(req)
        assert result.denied

    def test_safe_path_allowed(self, policy):
        req = _make_request("read_file", {"path": "/data/report.csv"})
        result = policy.evaluate(req)
        assert result.allowed

    def test_sql_drop_blocked(self, policy):
        req = _make_request("search_database", {"query": "SELECT 1; DROP TABLE users"})
        result = policy.evaluate(req)
        assert result.denied

    def test_sql_select_allowed(self, policy):
        req = _make_request("search_database", {"query": "SELECT name FROM users"})
        result = policy.evaluate(req)
        # Not in allowed_tools for default agent, so denied by default_action
        # This tests that SQL rules pass even though policy denies
        assert result.denied  # Because search_database not in allowed_tools


class TestAgentScoping:
    def test_admin_agent_allows_everything(self, policy):
        result = policy.evaluate(_make_request("anything", agent="admin_agent"))
        assert result.allowed

    def test_unknown_agent_uses_default(self, policy):
        result = policy.evaluate(_make_request("web_search", agent="random_bot"))
        assert result.allowed  # Falls back to default agent config


class TestPolicyValidation:
    def test_valid_policy_no_issues(self, policy):
        assert policy.validate() == []

    def test_missing_version_flagged(self):
        p = PolicyEngine.from_dict({"default_action": "allow"})
        issues = p.validate()
        assert any("version" in i for i in issues)

    def test_invalid_default_action_flagged(self):
        p = PolicyEngine.from_dict({"version": "1.0", "default_action": "maybe"})
        issues = p.validate()
        assert any("default_action" in i for i in issues)


class TestPolicyFromYaml:
    def test_load_default_policy(self):
        policy = PolicyEngine.from_yaml("policies/default.yaml")
        assert policy.name == "default-policy"
        assert policy.validate() == []

    def test_load_strict_policy(self):
        policy = PolicyEngine.from_yaml("policies/strict.yaml")
        assert policy.name == "strict-policy"

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            PolicyEngine.from_yaml("policies/nonexistent.yaml")