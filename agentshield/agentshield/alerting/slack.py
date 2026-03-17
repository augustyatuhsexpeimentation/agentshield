"""
agentshield.alerting.slack
~~~~~~~~~~~~~~~~~~~~~~~~~~
Send security alerts to Slack via incoming webhooks.
"""

from __future__ import annotations

from typing import Any

from agentshield.alerting.webhook import send_webhook


def send_slack_alert(
    webhook_url: str,
    result_dict: dict[str, Any],
    timeout: float = 5.0,
) -> bool:
    """
    Send a formatted Slack message for a security event.

    Expects a Slack incoming webhook URL.
    See: https://api.slack.com/messaging/webhooks
    """
    threats = result_dict.get("threats_detected", [])
    action = result_dict.get("action", "unknown").upper()
    tool = result_dict.get("tool_name", "?")
    agent = result_dict.get("agent_id", "?")

    # Build threat lines
    threat_lines = []
    for t in threats[:5]:
        det = t.get("detector", "?")
        desc = t.get("description", "?")
        lvl = t.get("level", "?")
        threat_lines.append(f"• `[{lvl}]` *{det}*: {desc}")

    threat_text = "\n".join(threat_lines) if threat_lines else "_No details_"

    # Slack Block Kit payload
    color = {"DENY": "#e74c3c", "MODIFY": "#f39c12", "ALLOW": "#2ecc71"}.get(
        action, "#95a5a6"
    )

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🛡️ AgentShield: {action}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Tool:*\n`{tool}`"},
                            {"type": "mrkdwn", "text": f"*Agent:*\n`{agent}`"},
                            {
                                "type": "mrkdwn",
                                "text": f"*Threats:*\n{len(threats)}",
                            },
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Details:*\n{threat_text}",
                        },
                    },
                ],
            }
        ]
    }

    return send_webhook(webhook_url, payload, timeout=timeout)