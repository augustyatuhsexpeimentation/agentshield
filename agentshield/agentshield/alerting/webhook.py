"""
agentshield.alerting.webhook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Send security alerts to any webhook endpoint (Slack, Discord, Teams, custom).
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any

logger = logging.getLogger("agentshield.alerting.webhook")


def send_webhook(
    url: str,
    payload: dict[str, Any],
    timeout: float = 5.0,
) -> bool:
    """
    POST a JSON payload to a webhook URL.
    Returns True on success, False on failure.
    Uses stdlib only — no requests dependency needed.
    """
    if not url:
        return False

    try:
        data = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.warning("Webhook alert failed: %s", e)
        return False


def format_alert(result_dict: dict[str, Any]) -> dict[str, Any]:
    """Format an InterceptionResult dict into a clean webhook payload."""
    threats = result_dict.get("threats_detected", [])
    top_threat = threats[0] if threats else {}

    return {
        "text": (
            f"🛡️ AgentShield Alert: "
            f"**{result_dict.get('action', 'unknown').upper()}** "
            f"on tool `{result_dict.get('tool_name', '?')}`"
        ),
        "action": result_dict.get("action"),
        "tool_name": result_dict.get("tool_name"),
        "agent_id": result_dict.get("agent_id"),
        "threats_count": len(threats),
        "top_threat_detector": top_threat.get("detector", ""),
        "top_threat_description": top_threat.get("description", ""),
        "request_id": result_dict.get("request_id", ""),
        "timestamp": result_dict.get("timestamp", ""),
    }