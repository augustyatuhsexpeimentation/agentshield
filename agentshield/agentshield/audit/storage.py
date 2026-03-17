"""
agentshield.audit.storage
~~~~~~~~~~~~~~~~~~~~~~~~~
Query-able audit storage backed by SQLite.

Provides structured querying of the JSONL audit log — filter by
tool name, agent, action, time range, threat level, etc.

This is used by the CLI (`agentshield query`) and dashboard.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class AuditRecord:
    """A single parsed audit log entry."""
    timestamp: str
    event: str
    request_id: str
    action: str
    tool_name: str
    agent_id: str
    session_id: str
    threats_count: int
    threats: list[dict[str, Any]]
    latency_ms: float
    raw: dict[str, Any]


class AuditStorage:
    """
    Reads the JSONL audit log and provides structured queries.

    For the MVP, this reads from the JSONL file directly.
    For production, this can be backed by SQLite or Postgres.

    Usage:
        store = AuditStorage.from_jsonl("agentshield_audit.jsonl")
        denied = store.query(action="deny", limit=20)
        by_tool = store.query(tool_name="database_query")
        recent = store.query(limit=50)
    """

    def __init__(self, records: list[AuditRecord]) -> None:
        self._records = records

    @classmethod
    def from_jsonl(cls, path: str | Path) -> AuditStorage:
        """Load audit records from a JSON-lines file."""
        path = Path(path)
        records: list[AuditRecord] = []

        if not path.exists():
            return cls(records)

        with open(path, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("event") == "interception":
                        records.append(_parse_record(data))
                except json.JSONDecodeError:
                    continue  # Skip malformed lines

        return cls(records)

    def query(
        self,
        action: Optional[str] = None,
        tool_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        min_threats: Optional[int] = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """
        Filter audit records.  All filters are AND-ed together.

        Args:
            action:      Filter by action ("allow", "deny", "modify")
            tool_name:   Filter by tool name (exact match)
            agent_id:    Filter by agent ID
            min_threats: Only records with >= N threats
            limit:       Max records to return (newest first)
        """
        results = self._records

        if action:
            results = [r for r in results if r.action == action]

        if tool_name:
            results = [r for r in results if r.tool_name == tool_name]

        if agent_id:
            results = [r for r in results if r.agent_id == agent_id]

        if min_threats is not None:
            results = [r for r in results if r.threats_count >= min_threats]

        # Return newest first, limited
        return list(reversed(results[-limit:]))

    def summary(self) -> dict[str, Any]:
        """Return aggregate statistics."""
        total = len(self._records)
        if total == 0:
            return {"total": 0}

        actions = {"allow": 0, "deny": 0, "modify": 0}
        tools: dict[str, int] = {}
        detectors: dict[str, int] = {}

        for r in self._records:
            actions[r.action] = actions.get(r.action, 0) + 1
            tools[r.tool_name] = tools.get(r.tool_name, 0) + 1
            for t in r.threats:
                det = t.get("detector", "unknown")
                detectors[det] = detectors.get(det, 0) + 1

        return {
            "total": total,
            "actions": actions,
            "top_tools": dict(
                sorted(tools.items(), key=lambda x: -x[1])[:10]
            ),
            "top_detectors": dict(
                sorted(detectors.items(), key=lambda x: -x[1])[:10]
            ),
        }

    def __len__(self) -> int:
        return len(self._records)


def _parse_record(data: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        timestamp=data.get("timestamp", ""),
        event=data.get("event", ""),
        request_id=data.get("request_id", ""),
        action=data.get("action", ""),
        tool_name=data.get("tool_name", ""),
        agent_id=data.get("agent_id", ""),
        session_id=data.get("session_id", ""),
        threats_count=data.get("threats_count", 0),
        threats=data.get("threats", []),
        latency_ms=data.get("latency_ms", 0.0),
        raw=data,
    )