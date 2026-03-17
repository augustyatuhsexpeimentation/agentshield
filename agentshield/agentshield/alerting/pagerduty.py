"""
agentshield.alerting.pagerduty
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Send critical security alerts to PagerDuty via Events API v2.
"""

from __future__ import annotations

from typing import Any

from agentshield.alerting.webhook import send_webhook

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


def send_pagerduty_alert(
    routing_key: str,
    result_dict: dict[str, Any],
    severity: str = "critical",
    timeout: float = 5.0,
) -> bool:
    """
    Trigger a PagerDuty incident for a blocked agent action.

    Args:
        routing_key: PagerDuty integration/routing key.
        result_dict: Dict from InterceptionResult.
        severity:    "critical", "error", "warning", or "info".
        timeout:     HTTP timeout in seconds.
    """
    threats = result_dict.get("threats_detected", [])
    top_desc = threats[0].get("description", "Unknown threat") if threats else "Policy violation"
    tool = result_dict.get("tool_name", "unknown")

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": (
                f"AgentShield blocked tool '{tool}': {top_desc}"
            ),
            "severity": severity,
            "source": "agentshield",
            "component": tool,
            "group": result_dict.get("agent_id", "default"),
            "custom_details": {
                "action": result_dict.get("action"),
                "tool_name": tool,
                "agent_id": result_dict.get("agent_id"),
                "threats": threats[:5],
                "request_id": result_dict.get("request_id"),
            },
        },
    }

    return send_webhook(PAGERDUTY_EVENTS_URL, payload, timeout=timeout)