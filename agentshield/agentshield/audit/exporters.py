"""
agentshield.audit.exporters
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Export audit records to different formats: CSV, JSON array, and
summary reports.  Used by the CLI and dashboard.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from agentshield.audit.storage import AuditRecord


def to_csv(records: list[AuditRecord]) -> str:
    """Export audit records to CSV string."""
    if not records:
        return ""

    output = io.StringIO()
    fieldnames = [
        "timestamp",
        "action",
        "tool_name",
        "agent_id",
        "threats_count",
        "latency_ms",
        "request_id",
        "top_threat",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for r in records:
        top_threat = ""
        if r.threats:
            first = r.threats[0]
            top_threat = (
                f"[{first.get('detector', '')}] "
                f"{first.get('description', '')[:80]}"
            )

        writer.writerow({
            "timestamp": r.timestamp,
            "action": r.action,
            "tool_name": r.tool_name,
            "agent_id": r.agent_id,
            "threats_count": r.threats_count,
            "latency_ms": round(r.latency_ms, 2),
            "request_id": r.request_id,
            "top_threat": top_threat,
        })

    return output.getvalue()


def to_json(records: list[AuditRecord]) -> str:
    """Export audit records as a JSON array."""
    return json.dumps(
        [r.raw for r in records],
        indent=2,
        default=str,
        ensure_ascii=False,
    )


def to_summary_report(summary: dict[str, Any]) -> str:
    """Format a summary dict as a readable text report."""
    lines = [
        "=" * 50,
        "  AgentShield Audit Summary",
        "=" * 50,
        "",
        f"  Total interceptions:  {summary.get('total', 0)}",
        "",
    ]

    actions = summary.get("actions", {})
    if actions:
        lines.append("  Actions:")
        for action, count in actions.items():
            pct = (count / max(summary["total"], 1)) * 100
            bar = "█" * int(pct / 5)
            lines.append(f"    {action:8s}  {count:5d}  ({pct:5.1f}%)  {bar}")
        lines.append("")

    top_tools = summary.get("top_tools", {})
    if top_tools:
        lines.append("  Top tools:")
        for tool, count in list(top_tools.items())[:5]:
            lines.append(f"    {tool:30s}  {count:5d}")
        lines.append("")

    top_det = summary.get("top_detectors", {})
    if top_det:
        lines.append("  Top detectors triggered:")
        for det, count in list(top_det.items())[:5]:
            lines.append(f"    {det:30s}  {count:5d}")
        lines.append("")

    lines.append("=" * 50)
    return "\n".join(lines)