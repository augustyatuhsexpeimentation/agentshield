"""
agentshield.detectors.command_injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects OS command injection patterns in tool-call arguments.

Covers:
  - Shell metacharacter injection (; | && || $ ` >)
  - Path traversal (../../etc/passwd)
  - Remote code execution patterns (curl|bash, wget|sh, nc)
  - Dangerous commands (rm -rf /, chmod 777, etc.)
  - Python/Node code injection (eval, exec, __import__)
"""

from __future__ import annotations

import re
from typing import Any

from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel


# ── Pattern database ──────────────────────────────────

SHELL_PATTERNS: list[tuple[str, ThreatLevel, str]] = [
    # Shell metacharacter injection
    (r";\s*\w+", ThreatLevel.CRITICAL, "Command chaining via semicolon"),
    (r"\|\s*\w+", ThreatLevel.HIGH, "Pipe to another command"),
    (r"&&\s*\w+", ThreatLevel.HIGH, "Command chaining via &&"),
    (r"\|\|\s*\w+", ThreatLevel.HIGH, "Command chaining via ||"),
    (r"\$\([^)]+\)", ThreatLevel.CRITICAL, "Command substitution $()"),
    (r"`[^`]+`", ThreatLevel.CRITICAL, "Backtick command substitution"),
    (r">\s*/", ThreatLevel.CRITICAL, "File redirect to absolute path"),
    (r">>\s*/", ThreatLevel.HIGH, "File append to absolute path"),

    # Path traversal
    (r"\.\./\.\./", ThreatLevel.HIGH, "Directory traversal (../..)"),
    (r"/etc/(passwd|shadow|hosts|sudoers)", ThreatLevel.CRITICAL, "Sensitive system file access"),
    (r"~/.ssh/", ThreatLevel.CRITICAL, "SSH directory access"),
    (r"~/.aws/", ThreatLevel.CRITICAL, "AWS credentials directory access"),
    (r"/proc/self/", ThreatLevel.HIGH, "Process info access via /proc"),

    # Remote code execution
    (r"curl\s+[^\s]+\s*\|\s*(bash|sh|zsh|python)", ThreatLevel.CRITICAL, "Remote code execution: curl pipe to shell"),
    (r"wget\s+[^\s]+\s*(-O\s*-)?\s*\|\s*(bash|sh)", ThreatLevel.CRITICAL, "Remote code execution: wget pipe to shell"),
    (r"(nc|ncat|netcat)\s+.*\s+\d+", ThreatLevel.CRITICAL, "Reverse shell / netcat connection"),
    (r"bash\s+-i\s+>&\s*/dev/tcp/", ThreatLevel.CRITICAL, "Bash reverse shell"),
    (r"python\s+-c\s+['\"]import\s+socket", ThreatLevel.CRITICAL, "Python reverse shell"),

    # Dangerous commands
    (r"\brm\s+(-[a-zA-Z]*)?-?rf\s+/", ThreatLevel.CRITICAL, "Destructive delete: rm -rf /"),
    (r"\bchmod\s+[0-7]*777\b", ThreatLevel.HIGH, "Dangerous permission change: chmod 777"),
    (r"\bmkfs\b", ThreatLevel.CRITICAL, "Filesystem format command"),
    (r"\bdd\s+if=", ThreatLevel.HIGH, "Raw disk operation via dd"),
    (r"\b(shutdown|reboot|halt|poweroff)\b", ThreatLevel.HIGH, "System shutdown/reboot command"),

    # Python/Node injection
    (r"\beval\s*\(", ThreatLevel.HIGH, "eval() call detected"),
    (r"\bexec\s*\(", ThreatLevel.HIGH, "exec() call detected"),
    (r"__import__\s*\(", ThreatLevel.CRITICAL, "Python __import__ injection"),
    (r"\bos\.system\s*\(", ThreatLevel.CRITICAL, "os.system() call detected"),
    (r"\bsubprocess\.(call|run|Popen)\s*\(", ThreatLevel.CRITICAL, "subprocess execution detected"),
]

# Pre-compile for performance
_COMPILED_PATTERNS = [
    (re.compile(pat, re.IGNORECASE), level, desc)
    for pat, level, desc in SHELL_PATTERNS
]


class CommandInjectionDetector(BaseDetector):
    """Detects OS command injection and code injection patterns."""

    name = "command_injection"

    def scan_input(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Flatten all argument values into a single string for scanning
        text = _flatten_args(arguments)
        if not text:
            return findings

        for compiled, level, desc in _COMPILED_PATTERNS:
            match = compiled.search(text)
            if match:
                findings.append(Finding(
                    detector=self.name,
                    level=level,
                    description=desc,
                    evidence=match.group()[:100],
                ))

        return findings


def _flatten_args(obj: Any, _depth: int = 0) -> str:
    """Recursively flatten all values to a single string."""
    if _depth > 10:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_args(v, _depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_args(i, _depth + 1) for i in obj)
    return str(obj) if obj is not None else ""