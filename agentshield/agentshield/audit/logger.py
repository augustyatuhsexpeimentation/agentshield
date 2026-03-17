"""
agentshield.audit.logger
~~~~~~~~~~~~~~~~~~~~~~~~
Structured audit logging for every decision AgentShield makes.

Every tool call interception and result is logged as a JSON-lines
entry — one JSON object per line — for easy ingestion into SIEM
tools, Elasticsearch, or simple grep-based analysis.

Logs are append-only and never contain raw PII (evidence is truncated).
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from agentshield.core.decision import InterceptionResult


class AuditLogger:
    """
    Writes structured JSON-lines audit logs.

    Each log entry contains:
      - timestamp, event type, request_id
      - action taken (allow/deny/modify)
      - tool name, agent id, session id
      - threats detected (truncated evidence)
      - policy decisions
      - latency

    Usage:
        logger = AuditLogger(log_path="audit.jsonl", console=True)
        logger.log_interception(result)
    """

    def __init__(
        self,
        log_path: str = "agentshield_audit.jsonl",
        console: bool = True,
        max_evidence_length: int = 200,
    ) -> None:
        self._path = Path(log_path)
        self._console = console
        self._max_evidence = max_evidence_length
        self._count = 0

        # Set up file logger (append mode, one JSON object per line)
        self._file_logger = logging.getLogger("agentshield.audit.file")
        self._file_logger.setLevel(logging.INFO)
        self._file_logger.propagate = False

        if not self._file_logger.handlers:
            fh = logging.FileHandler(self._path, mode="a", encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._file_logger.addHandler(fh)

        # Console output (pretty, not JSON)
        if self._console:
            self._console_logger = logging.getLogger("agentshield.audit.console")
            self._console_logger.setLevel(logging.INFO)
            self._console_logger.propagate = False
            if not self._console_logger.handlers:
                ch = logging.StreamHandler(sys.stderr)
                ch.setFormatter(logging.Formatter("%(message)s"))
                self._console_logger.addHandler(ch)

    def log_interception(self, result: InterceptionResult) -> None:
        """Log a tool-call interception decision."""
        entry = {
            "timestamp": _iso_now(),
            "epoch": time.time(),
            "event": "interception",
            "request_id": result.request_id,
            "action": result.action.value,
            "tool_name": result.original_request.tool_name,
            "agent_id": result.original_request.agent_id,
            "session_id": result.original_request.session_id,
            "threats_count": len(result.threats_detected),
            "threats": _truncate_threats(
                result.threats_detected, self._max_evidence,
            ),
            "policy_decisions": [
                {"allowed": p.allowed, "reason": p.reason[:200]}
                for p in result.policy_decisions
            ],
            "arguments_modified": result.modified_arguments is not None,
            "latency_ms": result.latency_ms,
        }

        self._write_file(entry)
        self._write_console(result)
        self._count += 1

    def log_result(self, result: InterceptionResult) -> None:
        """Log that a tool call completed (after execution)."""
        entry = {
            "timestamp": _iso_now(),
            "epoch": time.time(),
            "event": "tool_result",
            "request_id": result.request_id,
            "tool_name": result.original_request.tool_name,
            "agent_id": result.original_request.agent_id,
            "has_output": result.tool_result is not None,
        }
        self._write_file(entry)

    def log_custom(self, event: str, data: dict[str, Any]) -> None:
        """Write a custom audit event."""
        entry = {
            "timestamp": _iso_now(),
            "epoch": time.time(),
            "event": event,
            **data,
        }
        self._write_file(entry)

    @property
    def log_count(self) -> int:
        return self._count

    @property
    def log_path(self) -> Path:
        return self._path

    # ── Internal ──────────────────────────────────────

    def _write_file(self, entry: dict[str, Any]) -> None:
        try:
            line = json.dumps(entry, default=str, ensure_ascii=False)
            self._file_logger.info(line)
        except Exception:
            pass  # Never crash the app because of logging

    def _write_console(self, result: InterceptionResult) -> None:
        if not self._console:
            return

        action = result.action.value
        icons = {"allow": "✅", "deny": "🚫", "modify": "✏️"}
        icon = icons.get(action, "📝")

        tool = result.original_request.tool_name
        agent = result.original_request.agent_id
        threats = len(result.threats_detected)
        ms = result.latency_ms

        line = (
            f"  {icon} [{action.upper():6s}] "
            f"tool={tool!r}  agent={agent!r}  "
            f"threats={threats}  {ms:.1f}ms"
        )

        # Add threat details for denials
        if action == "deny" and result.threats_detected:
            first = result.threats_detected[0]
            desc = first.get("description", "")[:80]
            det = first.get("detector", "")
            line += f"\n           └─ [{det}] {desc}"

        try:
            self._console_logger.info(line)
        except Exception:
            pass


# ── Module helpers ────────────────────────────────────

def _iso_now() -> str:
    """Current time as ISO-8601 string."""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _truncate_threats(
    threats: list[dict[str, Any]], max_len: int,
) -> list[dict[str, Any]]:
    """Truncate evidence fields to prevent PII leakage in logs."""
    out = []
    for t in threats:
        entry = dict(t)
        if "evidence" in entry:
            entry["evidence"] = str(entry["evidence"])[:max_len]
        out.append(entry)
    return out