"""
agentshield.detectors.base
~~~~~~~~~~~~~~~~~~~~~~~~~~
Abstract base class for all security detectors, and the pipeline
that chains them together.

To create a custom detector:
    from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel

    class MyDetector(BaseDetector):
        name = "my_detector"

        def scan_input(self, tool_name, arguments, context):
            if something_bad(arguments):
                return [Finding(
                    detector=self.name,
                    level=ThreatLevel.HIGH,
                    description="Something bad detected",
                )]
            return []
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class ThreatLevel(IntEnum):
    """Severity of a detected threat.  CRITICAL triggers automatic blocking."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    """A single security finding produced by a detector."""
    detector: str
    level: ThreatLevel
    description: str
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "level": self.level.name,
            "description": self.description,
            "evidence": self.evidence[:200],
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return (
            f"Finding({self.level.name} from {self.detector}: "
            f"{self.description[:60]})"
        )


@dataclass
class ScanResult:
    """Aggregated result from running all detectors."""
    findings: list[Finding] = field(default_factory=list)
    modified_arguments: Optional[dict[str, Any]] = None
    modified_output: Any = None

    @property
    def max_threat_level(self) -> ThreatLevel:
        if not self.findings:
            return ThreatLevel.NONE
        return max(f.level for f in self.findings)

    @property
    def has_threats(self) -> bool:
        return len(self.findings) > 0


class BaseDetector(ABC):
    """
    Abstract base class for security detectors.

    Every detector must implement `scan_input`.
    Optionally override `scan_output` and `modify_arguments`.
    """

    name: str = "base"

    @abstractmethod
    def scan_input(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        """
        Scan tool-call arguments for threats.
        Return a list of Finding objects (empty list = clean).
        """
        ...

    def scan_output(
        self,
        tool_name: str,
        output: Any,
    ) -> list[Finding]:
        """Scan tool output.  Override if your detector checks responses."""
        return []

    def modify_arguments(
        self,
        arguments: dict[str, Any],
        findings: list[Finding],
    ) -> Optional[dict[str, Any]]:
        """
        Optionally transform arguments (e.g. redact PII).
        Return None to leave arguments unchanged.
        """
        return None


class DetectorPipeline:
    """
    Runs all registered detectors in sequence on every tool call.

    The pipeline:
      1. Runs each detector's scan_input()
      2. Collects all findings
      3. If a detector provides modify_arguments(), applies it
      4. Returns aggregated ScanResult
    """

    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        self._detectors: list[BaseDetector] = detectors or []

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> DetectorPipeline:
        """
        Build the pipeline from detector configuration.
        Only enables detectors whose config has enabled=True.
        """
        detectors: list[BaseDetector] = []

        # Import here to avoid circular imports
        from agentshield.detectors.prompt_injection import PromptInjectionDetector
        from agentshield.detectors.pii_scanner import PIIDetector
        from agentshield.detectors.command_injection import CommandInjectionDetector
        from agentshield.detectors.data_exfiltration import DataExfiltrationDetector
        from agentshield.detectors.tool_poisoning import ToolPoisoningDetector

        registry: dict[str, type[BaseDetector]] = {
            "prompt_injection": PromptInjectionDetector,
            "pii_scanner": PIIDetector,
            "command_injection": CommandInjectionDetector,
            "data_exfiltration": DataExfiltrationDetector,
            "tool_poisoning": ToolPoisoningDetector,
        }

        for det_name, det_cls in registry.items():
            det_cfg = config.get(det_name, {})
            if det_cfg.get("enabled", True):
                detectors.append(det_cls())

        return cls(detectors)

    @classmethod
    def default(cls) -> DetectorPipeline:
        """All detectors enabled with default settings."""
        return cls.from_config({
            "prompt_injection": {"enabled": True},
            "pii_scanner": {"enabled": True},
            "command_injection": {"enabled": True},
            "data_exfiltration": {"enabled": True},
            "tool_poisoning": {"enabled": True},
        })

    def add(self, detector: BaseDetector) -> None:
        """Register a custom detector at runtime."""
        self._detectors.append(detector)

    def scan(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Run all detectors on tool-call arguments."""
        all_findings: list[Finding] = []
        modified_args: Optional[dict[str, Any]] = None
        current_args = dict(arguments)

        for detector in self._detectors:
            findings = detector.scan_input(
                tool_name, current_args, context or {},
            )
            all_findings.extend(findings)

            # Let the detector modify/redact arguments
            if findings:
                mod = detector.modify_arguments(current_args, findings)
                if mod is not None:
                    modified_args = mod
                    current_args = mod  # Chain: next detector sees modified args

        return ScanResult(
            findings=all_findings,
            modified_arguments=modified_args,
        )

    def scan_output(self, tool_name: str, output: Any) -> ScanResult:
        """Run all detectors on tool output."""
        all_findings: list[Finding] = []
        for detector in self._detectors:
            findings = detector.scan_output(tool_name, output)
            all_findings.extend(findings)

        return ScanResult(findings=all_findings)

    @property
    def detector_names(self) -> list[str]:
        return [d.name for d in self._detectors]