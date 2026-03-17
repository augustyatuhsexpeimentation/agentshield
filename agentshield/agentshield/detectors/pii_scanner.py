"""
agentshield.detectors.pii_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects and redacts Personally Identifiable Information (PII)
and secrets in tool-call arguments and outputs.

Detected entities:
  - US Social Security Numbers
  - Credit card numbers (Visa, MC, Amex, Discover)
  - Email addresses
  - US phone numbers
  - IP addresses
  - AWS access keys
  - Generic API keys / secrets / passwords / tokens
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel


# ── PII pattern registry ─────────────────────────────
# Each entry: name → (regex, threat_level, redaction_replacement)

PII_PATTERNS: dict[str, tuple[str, ThreatLevel, str]] = {
    "US_SSN": (
        r"\b\d{3}-\d{2}-\d{4}\b",
        ThreatLevel.CRITICAL,
        "***-**-****",
    ),
    "CREDIT_CARD": (
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?"          # Visa
        r"|5[1-5][0-9]{14}"                        # Mastercard
        r"|3[47][0-9]{13}"                         # Amex
        r"|6(?:011|5[0-9]{2})[0-9]{12})\b",       # Discover
        ThreatLevel.CRITICAL,
        "****-****-****-****",
    ),
    "EMAIL_ADDRESS": (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        ThreatLevel.MEDIUM,
        "[EMAIL_REDACTED]",
    ),
    "PHONE_US": (
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        ThreatLevel.MEDIUM,
        "[PHONE_REDACTED]",
    ),
    "IP_ADDRESS": (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        ThreatLevel.LOW,
        "[IP_REDACTED]",
    ),
    "AWS_ACCESS_KEY": (
        r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        ThreatLevel.CRITICAL,
        "[AWS_KEY_REDACTED]",
    ),
    "GENERIC_SECRET": (
        r"(?i)(?:api[_\-]?key|secret[_\-]?key|password|passwd|token"
        r"|auth[_\-]?token|bearer|private[_\-]?key)"
        r"\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{8,}['\"]?",
        ThreatLevel.HIGH,
        "[SECRET_REDACTED]",
    ),
    "GITHUB_TOKEN": (
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
        ThreatLevel.CRITICAL,
        "[GITHUB_TOKEN_REDACTED]",
    ),
}

# Pre-compile all patterns for performance
_COMPILED: dict[str, re.Pattern] = {
    name: re.compile(pat) for name, (pat, _, _) in PII_PATTERNS.items()
}


class PIIDetector(BaseDetector):
    """Detects and optionally redacts PII and secrets."""

    name = "pii_scanner"

    def scan_input(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        return self._scan_text(str(arguments))

    def scan_output(
        self,
        tool_name: str,
        output: Any,
    ) -> list[Finding]:
        return self._scan_text(str(output))

    def modify_arguments(
        self,
        arguments: dict[str, Any],
        findings: list[Finding],
    ) -> Optional[dict[str, Any]]:
        """Redact PII from arguments, returning a sanitised copy."""
        if not findings:
            return None

        # Determine which entity types were found
        entities_found = {
            f.metadata.get("entity_type")
            for f in findings
            if f.metadata.get("entity_type")
        }

        if not entities_found:
            return None

        try:
            text = json.dumps(arguments, default=str)
        except (TypeError, ValueError):
            return None

        for entity_name in entities_found:
            entry = PII_PATTERNS.get(entity_name)
            if entry is None:
                continue
            pattern_str, _, replacement = entry
            text = re.sub(pattern_str, replacement, text, flags=re.IGNORECASE)

        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None

    # ── Internal ──────────────────────────────────────

    def _scan_text(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for entity_name, compiled in _COMPILED.items():
            matches = compiled.findall(text)
            if matches:
                _, level, _ = PII_PATTERNS[entity_name]
                findings.append(Finding(
                    detector=self.name,
                    level=level,
                    description=f"{entity_name} detected ({len(matches)} instance(s))",
                    evidence=f"Found {len(matches)} match(es)",
                    metadata={
                        "entity_type": entity_name,
                        "count": len(matches),
                    },
                ))

        return findings