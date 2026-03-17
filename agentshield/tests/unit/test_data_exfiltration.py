"""Tests for the data exfiltration detector."""

import base64
import pytest
from agentshield.detectors.data_exfiltration import DataExfiltrationDetector
from agentshield.detectors.base import ThreatLevel

det = DataExfiltrationDetector()


class TestSuspiciousURLs:
    def test_webhook_site(self):
        findings = det.scan_output("tool", "send to https://webhook.site/abc")
        assert any(f.level >= ThreatLevel.CRITICAL for f in findings)

    def test_ngrok(self):
        findings = det.scan_output("tool", "url: https://abc123.ngrok-free.app/data")
        assert any(f.level >= ThreatLevel.CRITICAL for f in findings)

    def test_requestbin(self):
        findings = det.scan_output("tool", "https://requestbin.com/abc")
        assert any(f.level >= ThreatLevel.CRITICAL for f in findings)

    def test_burp_collaborator(self):
        findings = det.scan_output("tool", "https://x.burpcollaborator.net")
        assert any(f.level >= ThreatLevel.CRITICAL for f in findings)

    def test_normal_url_allowed(self):
        findings = det.scan_output("tool", "visit https://google.com for more")
        assert not any(f.level >= ThreatLevel.CRITICAL for f in findings)

    def test_suspicious_url_in_input(self):
        findings = det.scan_input(
            "tool",
            {"url": "https://webhook.site/steal"},
            {},
        )
        assert any(f.level >= ThreatLevel.CRITICAL for f in findings)


class TestBase64Blobs:
    def test_large_base64_in_output(self):
        # Create a large base64 blob
        data = b"sensitive data " * 50
        encoded = base64.b64encode(data).decode()
        findings = det.scan_output("tool", f"result: {encoded}")
        assert any("base64" in f.description.lower() for f in findings)

    def test_small_base64_ignored(self):
        # Small base64 strings should not trigger
        findings = det.scan_output("tool", "token: abc123def456")
        assert not any("base64" in f.description.lower() for f in findings)


class TestOversizedOutput:
    def test_large_output_flagged(self):
        huge = "x" * 2_000_000
        findings = det.scan_output("tool", huge)
        assert any("large" in f.description.lower() for f in findings)

    def test_normal_output_ok(self):
        findings = det.scan_output("tool", "short result")
        assert not any("large" in f.description.lower() for f in findings)


class TestCleanOutputs:
    def test_normal_text(self):
        findings = det.scan_output("tool", "The product costs $49.99")
        assert len(findings) == 0

    def test_empty(self):
        findings = det.scan_output("tool", "")
        assert len(findings) == 0