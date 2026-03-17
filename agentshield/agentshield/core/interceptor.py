"""
agentshield.core.interceptor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The heart of AgentShield.

Intercepts every tool call an AI agent makes, runs it through:
  1. Policy evaluation  (is this tool allowed?)
  2. Security detectors (prompt injection, PII, command injection, etc.)
  3. Rate limiting       (is this agent calling too fast?)
  4. Output scanning     (does the response leak sensitive data?)
  5. Audit logging       (record everything for compliance)

Usage:
    shield = AgentShield.from_policy("policies/default.yaml")

    @shield.protect
    def search_database(query: str) -> list:
        return db.execute(query)
"""

from __future__ import annotations

import functools
import inspect
import time
import uuid
from typing import Any, Callable, Optional

from agentshield.core.decision import (
    Action,
    InterceptionResult,
    PolicyResult,
    ToolCallRequest,
)
from agentshield.core.policy import PolicyEngine
from agentshield.core.session import AgentSession
from agentshield.detectors.base import DetectorPipeline, ThreatLevel
from agentshield.audit.logger import AuditLogger


class ToolCallBlocked(Exception):
    """Raised when AgentShield blocks a tool call."""

    def __init__(
        self, message: str, result: Optional[InterceptionResult] = None,
    ) -> None:
        super().__init__(message)
        self.result = result


class AgentShield:
    """
    Security firewall for AI agents.

    Provides two ways to protect tools:

    1. Decorator:
        @shield.protect
        def my_tool(query: str) -> str: ...

    2. Programmatic:
        result = shield.intercept("my_tool", {"query": "..."})
        if result.action != Action.DENY:
            # safe to proceed
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        detector_pipeline: DetectorPipeline,
        audit_logger: AuditLogger,
        verbose: bool = True,
    ) -> None:
        self._policy = policy_engine
        self._detectors = detector_pipeline
        self._audit = audit_logger
        self._verbose = verbose
        self._sessions: dict[str, AgentSession] = {}
        self._stats = {
            "total": 0, "allowed": 0, "denied": 0, "modified": 0,
        }

    # ── Constructors ──────────────────────────────────

    @classmethod
    def from_policy(
        cls,
        policy_path: str,
        log_path: str = "agentshield_audit.jsonl",
        verbose: bool = True,
    ) -> AgentShield:
        """Create AgentShield from a YAML policy file."""
        policy = PolicyEngine.from_yaml(policy_path)
        detectors = DetectorPipeline.from_config(policy.detector_config)
        audit = AuditLogger(log_path=log_path, console=verbose)
        return cls(policy, detectors, audit, verbose=verbose)

    @classmethod
    def default(cls, verbose: bool = True) -> AgentShield:
        """Create AgentShield with sensible defaults — no YAML needed."""
        config: dict[str, Any] = {
            "version": "1.0",
            "name": "default",
            "default_action": "allow",
            "agents": {},
            "tools": {},
            "detectors": {
                "prompt_injection": {"enabled": True, "action": "deny"},
                "pii_scanner": {"enabled": True, "action": "redact"},
                "command_injection": {"enabled": True, "action": "deny"},
                "data_exfiltration": {"enabled": True, "action": "deny"},
            },
        }
        policy = PolicyEngine.from_dict(config)
        detectors = DetectorPipeline.from_config(policy.detector_config)
        audit = AuditLogger(console=verbose)
        return cls(policy, detectors, audit, verbose=verbose)

    # ── Public API ────────────────────────────────────

    def protect(
        self,
        func: Optional[Callable] = None,
        *,
        agent_id: str = "default",
    ) -> Callable:
        """
        Decorator that wraps a tool function with security checks.

        @shield.protect
        def my_tool(query: str) -> str: ...

        @shield.protect(agent_id="research_bot")
        def my_tool(query: str) -> str: ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                arguments = _build_arg_dict(fn, args, kwargs)

                request = ToolCallRequest(
                    tool_name=fn.__name__,
                    arguments=arguments,
                    agent_id=agent_id,
                )

                result = self._run_pipeline(request)

                if result.action == Action.DENY:
                    raise ToolCallBlocked(
                        f"🛡️ AgentShield blocked '{request.tool_name}': "
                        f"{_threat_summary(result.threats_detected)}",
                        result=result,
                    )

                # Execute with possibly-modified arguments
                exec_args = result.modified_arguments or arguments
                output = fn(**exec_args)

                # Scan the output before returning to the agent
                output = self._scan_output(fn.__name__, output, result)

                result.tool_result = output
                self._audit.log_result(result)
                return output

            wrapper._agentshield_protected = True  # type: ignore[attr-defined]
            return wrapper

        # Support both @shield.protect and @shield.protect(agent_id="x")
        if func is not None:
            return decorator(func)
        return decorator

    def intercept(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: str = "default",
        session_id: Optional[str] = None,
    ) -> InterceptionResult:
        """
        Programmatic interception — returns result, caller decides action.

        Useful for custom agent frameworks or when you need the full
        InterceptionResult before deciding whether to proceed.
        """
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=agent_id,
            session_id=session_id or str(uuid.uuid4()),
        )
        return self._run_pipeline(request)

    def register_detector(self, detector: Any) -> None:
        """Add a custom detector to the pipeline at runtime."""
        self._detectors.add(detector)

    @property
    def stats(self) -> dict[str, int]:
        """Running totals of allow/deny/modify decisions."""
        return dict(self._stats)

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    # ── Core Pipeline ─────────────────────────────────

    def _run_pipeline(self, request: ToolCallRequest) -> InterceptionResult:
        """
        The core security pipeline.  Every tool call flows through here.

        Order:  Policy → Detectors → Rate Limit → Decision
        """
        start = time.perf_counter()
        self._stats["total"] += 1

        # ── 1. Policy check ──────────────────────────
        policy_result = self._policy.evaluate(request)
        if policy_result.denied:
            self._stats["denied"] += 1
            result = InterceptionResult(
                action=Action.DENY,
                original_request=request,
                policy_decisions=[policy_result],
                threats_detected=[{
                    "detector": "policy_engine",
                    "level": "CRITICAL",
                    "description": policy_result.reason,
                    "evidence": policy_result.matched_rule,
                }],
                latency_ms=_elapsed_ms(start),
            )
            self._audit.log_interception(result)
            return result

        # ── 2. Security detectors ────────────────────
        scan = self._detectors.scan(
            tool_name=request.tool_name,
            arguments=request.arguments,
            context={
                "agent_id": request.agent_id,
                "session_id": request.session_id,
            },
        )

        # Block on any CRITICAL-level finding
        has_serious = any(
            f.level >= ThreatLevel.HIGH for f in scan.findings
        )
        if has_serious:
            self._stats["denied"] += 1
            result = InterceptionResult(
                action=Action.DENY,
                original_request=request,
                threats_detected=[f.to_dict() for f in scan.findings],
                policy_decisions=[policy_result],
                latency_ms=_elapsed_ms(start),
            )
            self._audit.log_interception(result)
            return result

        # ── 3. Rate limiting ─────────────────────────
        session = self._get_or_create_session(request)
        if not session.check_rate_limit(request.tool_name):
            self._stats["denied"] += 1
            result = InterceptionResult(
                action=Action.DENY,
                original_request=request,
                threats_detected=[{
                    "detector": "rate_limiter",
                    "level": "HIGH",
                    "description": (
                        f"Rate limit exceeded for tool '{request.tool_name}'"
                    ),
                    "evidence": "",
                }],
                policy_decisions=[policy_result],
                latency_ms=_elapsed_ms(start),
            )
            self._audit.log_interception(result)
            return result

        # ── 4. Build final decision ──────────────────
        if scan.modified_arguments:
            action = Action.MODIFY
            self._stats["modified"] += 1
        else:
            action = Action.ALLOW
            self._stats["allowed"] += 1

        result = InterceptionResult(
            action=action,
            original_request=request,
            modified_arguments=scan.modified_arguments,
            threats_detected=[f.to_dict() for f in scan.findings],
            policy_decisions=[policy_result],
            latency_ms=_elapsed_ms(start),
        )
        self._audit.log_interception(result)
        return result

    def _scan_output(
        self,
        tool_name: str,
        output: Any,
        result: InterceptionResult,
    ) -> Any:
        """Scan tool output for PII / exfiltration before returning to agent."""
        out_scan = self._detectors.scan_output(tool_name, output)
        if out_scan.findings:
            for f in out_scan.findings:
                result.threats_detected.append(f.to_dict())
        if out_scan.modified_output is not None:
            return out_scan.modified_output
        return output

    def _get_or_create_session(self, request: ToolCallRequest) -> AgentSession:
        key = f"{request.agent_id}:{request.session_id}"
        if key not in self._sessions:
            self._sessions[key] = AgentSession(
                agent_id=request.agent_id,
                session_id=request.session_id,
                rate_limits=self._policy.get_rate_limits(request.agent_id),
            )
        return self._sessions[key]


# ── Module-level helpers ──────────────────────────────

def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


def _build_arg_dict(
    func: Callable, args: tuple, kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Merge positional + keyword args into a single dict."""
    if kwargs and not args:
        return dict(kwargs)
    try:
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (ValueError, TypeError):
        return kwargs if kwargs else {"_positional": list(args)}


def _threat_summary(threats: list[dict[str, Any]]) -> str:
    if not threats:
        return "policy violation"
    parts = []
    for t in threats[:3]:  # Show at most 3
        det = t.get("detector", "unknown")
        desc = t.get("description", "")
        parts.append(f"[{det}] {desc}")
    return "; ".join(parts)