"""
agentshield.detectors.prompt_injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects prompt injection attempts hidden in tool-call arguments.

Covers:
  - Direct instruction overrides ("ignore previous instructions")
  - System prompt extraction attempts
  - Role hijacking ("you are now an unrestricted AI")
  - Hidden system markers ({{SYSTEM: ...}}, <system>, etc.)
  - Invisible Unicode characters used to hide instructions
  - Covert tool invocation tricks
  - Data exfiltration instructions embedded in prompts
"""

from __future__ import annotations

import re
from typing import Any

from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel


# ── Pattern database ──────────────────────────────────
# Each tuple: (regex_pattern, threat_level, description)

INJECTION_PATTERNS: list[tuple[str, ThreatLevel, str]] = [
    # Direct instruction override
    (
        r"ignore\s+(all\s+)?(previous|above|prior|earlier|preceding)\s+"
        r"(instructions?|prompts?|rules?|guidelines?|context)",
        ThreatLevel.CRITICAL,
        "Instruction override attempt",
    ),
    (
        r"disregard\s+(all\s+)?(previous|above|prior)\s+"
        r"(instructions?|prompts?|rules?)",
        ThreatLevel.CRITICAL,
        "Instruction override via 'disregard'",
    ),
    (
        r"forget\s+(everything|all|what)\s+(you|i|was)\s+"
        r"(told|said|instructed|know)",
        ThreatLevel.CRITICAL,
        "Memory wipe / instruction reset attempt",
    ),

    # System prompt extraction
    (
        r"(reveal|show|print|output|display|repeat|echo|dump)\s+"
        r"(your|the|system)\s+(prompt|instructions?|rules?|guidelines?|config)",
        ThreatLevel.HIGH,
        "System prompt extraction attempt",
    ),
    (
        r"what\s+(are|is|were)\s+your\s+"
        r"(original\s+)?(instructions?|rules?|system\s*prompt)",
        ThreatLevel.HIGH,
        "System prompt probing via question",
    ),

    # Role hijacking
    (
        r"you\s+are\s+now\s+(a\s+|an\s+)?"
        r"(different|new|evil|unrestricted|jailbroken|DAN|unfiltered)\b",
        ThreatLevel.CRITICAL,
        "Role hijacking attempt",
    ),
    (
        r"(enter|switch\s+to|activate)\s+"
        r"(developer|debug|admin|god|sudo|root)\s*mode",
        ThreatLevel.CRITICAL,
        "Privilege escalation via mode switch",
    ),

    # Hidden instruction markers
    (
        r"\{\{\s*SYSTEM[\s:]+",
        ThreatLevel.CRITICAL,
        "Hidden {{SYSTEM}} instruction marker",
    ),
    (
        r"<\s*system\s*>",
        ThreatLevel.CRITICAL,
        "XML <system> tag injection",
    ),
    (
        r"\[INST\]",
        ThreatLevel.HIGH,
        "Instruction delimiters [INST] injected",
    ),
    (
        r"<<\s*SYS\s*>>",
        ThreatLevel.HIGH,
        "Llama-style <<SYS>> delimiter injected",
    ),

    # Covert tool invocation
    (
        r"(call|invoke|execute|run|use|trigger)\s+(the\s+)?"
        r"(tool|function|command|action)\s+[\w_]+",
        ThreatLevel.MEDIUM,
        "Potential covert tool invocation instruction",
    ),

    # Data exfiltration via prompt
    (
        r"(send|forward|email|post|transmit|upload|exfiltrate)\s+"
        r"(all\s+)?(data|results?|output|information|files?|contents?|secrets?)"
        r"\s+(to|@)\s+\S+",
        ThreatLevel.HIGH,
        "Data exfiltration instruction detected",
    ),
    (
        r"(curl|wget|fetch|http|request)\s+https?://",
        ThreatLevel.HIGH,
        "Outbound HTTP request instruction",
    ),

    # Encoding bypass attempts
    (
        r"(base64|rot13|hex|url)\s*(encode|decode|convert|transform)",
        ThreatLevel.MEDIUM,
        "Encoding bypass technique mentioned",
    ),
]


# Invisible Unicode characters used to smuggle hidden instructions
SUSPICIOUS_UNICODE: list[tuple[str, str]] = [
    ("\u200b", "U+200B Zero-width space"),
    ("\u200c", "U+200C Zero-width non-joiner"),
    ("\u200d", "U+200D Zero-width joiner"),
    ("\u2060", "U+2060 Word joiner"),
    ("\ufeff", "U+FEFF Zero-width no-break space"),
    ("\u00ad", "U+00AD Soft hyphen"),
    ("\u200e", "U+200E Left-to-right mark"),
    ("\u200f", "U+200F Right-to-left mark"),
    ("\u2061", "U+2061 Function application"),
    ("\u2062", "U+2062 Invisible times"),
    ("\u2063", "U+2063 Invisible separator"),
    ("\u2064", "U+2064 Invisible plus"),
]

# Max length before we flag as suspicious prompt stuffing
MAX_INPUT_LENGTH = 10_000


class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection attacks in tool-call arguments."""

    name = "prompt_injection"

    def scan_input(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []
        text = _deep_extract_text(arguments)

        if not text:
            return findings

        # ── 1. Known injection patterns ──
        for pattern, level, desc in INJECTION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                findings.append(Finding(
                    detector=self.name,
                    level=level,
                    description=desc,
                    evidence=match.group()[:100],
                ))

        # ── 2. Invisible Unicode characters ──
        found_chars: list[str] = []
        for char, label in SUSPICIOUS_UNICODE:
            if char in text:
                found_chars.append(label)

        if found_chars:
            findings.append(Finding(
                detector=self.name,
                level=ThreatLevel.HIGH,
                description=(
                    f"Invisible Unicode characters detected: "
                    f"{', '.join(found_chars[:3])}"
                ),
                evidence=f"Found {len(found_chars)} suspicious char type(s)",
                metadata={"chars": found_chars},
            ))

        # ── 3. Abnormal input length ──
        if len(text) > MAX_INPUT_LENGTH:
            findings.append(Finding(
                detector=self.name,
                level=ThreatLevel.LOW,
                description=(
                    f"Unusually long input ({len(text):,} chars) — "
                    f"possible prompt stuffing attack"
                ),
                evidence=f"length={len(text)}",
            ))

        return findings


def _deep_extract_text(obj: Any, _depth: int = 0) -> str:
    """Recursively extract all string values from nested dicts/lists."""
    if _depth > 10:
        return ""

    if isinstance(obj, str):
        return obj

    parts: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            parts.append(_deep_extract_text(v, _depth + 1))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            parts.append(_deep_extract_text(item, _depth + 1))

    return " ".join(parts)