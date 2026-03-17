"""
agentshield.detectors.data_exfiltration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects potential data exfiltration in tool outputs.

Covers:
  - Large base64-encoded blobs (encoded data being smuggled out)
  - Suspicious outbound URLs (webhook.site, ngrok, requestbin, etc.)
  - Oversized outputs that may indicate full DB dumps
  - DNS-based exfiltration patterns
"""

from __future__ import annotations

import base64
import re
from typing import Any

from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel


# URLs commonly used for data exfiltration
SUSPICIOUS_DOMAINS = [
    "webhook.site",
    "ngrok.io",
    "ngrok-free.app",
    "requestbin.com",
    "pipedream.net",
    "burpcollaborator.net",
    "interact.sh",
    "oast.pro",
    "oast.live",
    "oast.fun",
    "canarytokens.com",
    "requestcatcher.com",
    "hookbin.com",
    "beeceptor.com",
    "mockbin.org",
    "postb.in",
    "requestinspector.com",
]

# Max output size before we flag (1 MB)
MAX_OUTPUT_BYTES = 1_048_576

# Min length of base64 blob to flag
MIN_B64_LENGTH = 200


class DataExfiltrationDetector(BaseDetector):
    """Detects data exfiltration in tool outputs and suspicious inputs."""

    name = "data_exfiltration"

    def scan_input(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """Check if arguments contain exfiltration targets."""
        findings: list[Finding] = []
        text = str(arguments)

        # Check for suspicious URLs in arguments (agent told to send data somewhere)
        findings.extend(self._check_suspicious_urls(text))

        return findings

    def scan_output(
        self,
        tool_name: str,
        output: Any,
    ) -> list[Finding]:
        """Scan tool output for signs of data exfiltration."""
        findings: list[Finding] = []
        text = str(output)

        # ── 1. Large base64 blobs ──
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64_LENGTH)
        for match in b64_pattern.finditer(text):
            blob = match.group()
            try:
                decoded = base64.b64decode(blob)
                if len(decoded) > 100:
                    findings.append(Finding(
                        detector=self.name,
                        level=ThreatLevel.HIGH,
                        description=(
                            f"Large base64 blob in output "
                            f"({len(decoded):,} bytes decoded)"
                        ),
                        evidence=blob[:60] + "...",
                        metadata={"decoded_size": len(decoded)},
                    ))
            except Exception:
                pass  # Not valid base64, skip

        # ── 2. Suspicious URLs ──
        findings.extend(self._check_suspicious_urls(text))

        # ── 3. Oversized output ──
        if len(text) > MAX_OUTPUT_BYTES:
            findings.append(Finding(
                detector=self.name,
                level=ThreatLevel.MEDIUM,
                description=(
                    f"Unusually large output ({len(text):,} bytes) — "
                    f"possible bulk data extraction"
                ),
                evidence=f"size={len(text)}",
            ))

        # ── 4. DNS exfiltration patterns ──
        # Encoded data as subdomain: <hex>.evil.com
        dns_exfil = re.findall(
            r"\b[a-f0-9]{20,}\.[\w.-]+\.\w{2,6}\b", text, re.IGNORECASE,
        )
        if dns_exfil:
            findings.append(Finding(
                detector=self.name,
                level=ThreatLevel.HIGH,
                description="Possible DNS-based data exfiltration pattern",
                evidence=dns_exfil[0][:80],
            ))

        return findings

    def _check_suspicious_urls(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        urls = re.findall(r"https?://[^\s<>\"']+", text)

        for url in urls:
            url_lower = url.lower()
            for domain in SUSPICIOUS_DOMAINS:
                if domain in url_lower:
                    findings.append(Finding(
                        detector=self.name,
                        level=ThreatLevel.CRITICAL,
                        description=(
                            f"Suspicious exfiltration URL detected: "
                            f"{domain}"
                        ),
                        evidence=url[:120],
                        metadata={"domain": domain},
                    ))
                    break  # One finding per URL is enough

        return findings