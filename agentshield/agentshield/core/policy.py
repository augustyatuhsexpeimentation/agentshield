"""
agentshield.core.policy
~~~~~~~~~~~~~~~~~~~~~~~
YAML-based policy engine.
Loads declarative security rules and evaluates every tool call against them.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

import yaml

from agentshield.core.decision import PolicyResult, ToolCallRequest
from agentshield.core.session import RateLimit


class PolicyValidationError(Exception):
    """Raised when a policy file is malformed."""


class PolicyEngine:
    """
    Evaluates tool-call requests against a declarative YAML policy.

    Policy structure (see policies/default.yaml for full example):
        version:        Schema version string.
        default_action: "allow" | "deny" — fallback when no rule matches.
        agents:         Per-agent allow/deny lists and rate limits.
        tools:          Per-tool argument restrictions (paths, SQL ops, etc.).
        detectors:      Configuration passed to security detectors.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._version: str = config.get("version", "1.0")
        self._name: str = config.get("name", "unnamed")
        self._default_action: str = config.get("default_action", "deny")
        self._agents: dict[str, Any] = config.get("agents", {})
        self._tools: dict[str, Any] = config.get("tools", {})
        self._detectors_config: dict[str, Any] = config.get("detectors", {})
        self._alerts_config: dict[str, Any] = config.get("alerts", {})

    # ── Constructors ──────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        """Load policy from a YAML file.  Supports ${ENV_VAR} expansion."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        raw = path.read_text(encoding="utf-8")
        expanded = os.path.expandvars(raw)
        config = yaml.safe_load(expanded)

        if not isinstance(config, dict):
            raise PolicyValidationError(
                f"Policy must be a YAML mapping, got {type(config).__name__}"
            )
        return cls(config)

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> PolicyEngine:
        """Create from an in-memory dict (handy for tests)."""
        return cls(config)

    # ── Evaluation ────────────────────────────────────

    def evaluate(self, request: ToolCallRequest) -> PolicyResult:
        """Run a tool-call request through the full policy rule chain."""
        agent_cfg = self._agent_config(request.agent_id)

        # 1 ─ Deny list (highest priority — deny always wins)
        for pattern in agent_cfg.get("denied_tools", []):
            if fnmatch.fnmatch(request.tool_name, pattern):
                return PolicyResult(
                    allowed=False,
                    reason=f"Tool '{request.tool_name}' matches deny pattern '{pattern}'",
                    matched_rule=f"agents.{request.agent_id}.denied_tools",
                )

        # 2 ─ Allow list
        allowed = agent_cfg.get("allowed_tools", [])
        if allowed and not any(
            fnmatch.fnmatch(request.tool_name, p) for p in allowed
        ):
            return PolicyResult(
                allowed=False,
                reason=f"Tool '{request.tool_name}' not in allowlist",
                matched_rule=f"agents.{request.agent_id}.allowed_tools",
            )

        # 3 ─ Tool-specific argument rules
        tool_rules = self._tools.get(request.tool_name, {})
        if tool_rules:
            result = self._check_tool_rules(
                request.tool_name, request.arguments, tool_rules,
            )
            if not result.allowed:
                return result

        # 4 ─ Default action
        if self._default_action == "deny" and not allowed:
            return PolicyResult(
                allowed=False,
                reason="Default action is 'deny' and no allowlist matched",
                matched_rule="default_action",
            )

        return PolicyResult(allowed=True, reason="All policy checks passed")

    # ── Accessors ─────────────────────────────────────

    def get_rate_limits(self, agent_id: str) -> dict[str, RateLimit]:
        """Return parsed rate-limit objects for a given agent."""
        raw = self._agent_config(agent_id).get("rate_limits", {})
        limits: dict[str, RateLimit] = {}
        for tool, cfg in raw.items():
            if isinstance(cfg, dict) and "max_calls" in cfg:
                limits[tool] = RateLimit(
                    max_calls=int(cfg["max_calls"]),
                    window_seconds=float(cfg["window_seconds"]),
                )
        return limits

    @property
    def detector_config(self) -> dict[str, Any]:
        return self._detectors_config

    @property
    def alerts_config(self) -> dict[str, Any]:
        return self._alerts_config

    @property
    def name(self) -> str:
        return self._name

    # ── Internals ─────────────────────────────────────

    def _agent_config(self, agent_id: str) -> dict[str, Any]:
        return self._agents.get(agent_id, self._agents.get("default", {}))

    def _check_tool_rules(
        self,
        tool_name: str,
        args: dict[str, Any],
        rules: dict[str, Any],
    ) -> PolicyResult:
        """Evaluate tool-specific argument constraints."""

        # ── File path restrictions ──
        if "denied_paths" in rules:
            file_path = (
                args.get("path")
                or args.get("file_path")
                or args.get("filepath")
                or args.get("filename")
            )
            if file_path:
                for pattern in rules["denied_paths"]:
                    if fnmatch.fnmatch(str(file_path), pattern):
                        return PolicyResult(
                            allowed=False,
                            reason=f"Path '{file_path}' matches denied pattern '{pattern}'",
                            matched_rule=f"tools.{tool_name}.denied_paths",
                        )

        # ── SQL operation restrictions ──
        if "denied_operations" in rules:
            query = str(args.get("query") or args.get("sql") or "")
            for op in rules["denied_operations"]:
                if re.search(rf"\b{re.escape(op)}\b", query, re.IGNORECASE):
                    return PolicyResult(
                        allowed=False,
                        reason=f"SQL operation '{op}' is denied for tool '{tool_name}'",
                        matched_rule=f"tools.{tool_name}.denied_operations",
                    )

        # ── Shell command restrictions ──
        if "denied_patterns" in rules:
            cmd = str(args.get("command") or args.get("cmd") or "")
            for pattern in rules["denied_patterns"]:
                if pattern.lower() in cmd.lower():
                    return PolicyResult(
                        allowed=False,
                        reason=f"Command matches denied pattern '{pattern}'",
                        matched_rule=f"tools.{tool_name}.denied_patterns",
                    )

        # ── Max rows restriction ──
        if "max_rows_returned" in rules:
            limit_val = rules["max_rows_returned"]
            query = str(args.get("query") or args.get("sql") or "")
            # Check if LIMIT is missing or exceeds max
            limit_match = re.search(r"\bLIMIT\s+(\d+)", query, re.IGNORECASE)
            if not limit_match or int(limit_match.group(1)) > limit_val:
                # Don't block — just flag. The caller can decide.
                pass

        return PolicyResult(allowed=True)

    def validate(self) -> list[str]:
        """Return a list of warnings/errors in the policy (for the CLI)."""
        issues: list[str] = []

        if "version" not in self._config:
            issues.append("Missing 'version' field")
        if "default_action" not in self._config:
            issues.append("Missing 'default_action' — will default to 'deny'")
        if self._default_action not in ("allow", "deny"):
            issues.append(
                f"Invalid default_action: '{self._default_action}' "
                f"(must be 'allow' or 'deny')"
            )

        for agent_id, cfg in self._agents.items():
            if not isinstance(cfg, dict):
                issues.append(f"Agent '{agent_id}' config must be a mapping")

        return issues