"""Tests for the PII scanner detector."""

import pytest
from agentshield.detectors.pii_scanner import PIIDetector
from agentshield.detectors.base import ThreatLevel

det = PIIDetector()


def _scan(text: str):
    return det.scan_input("test_tool", {"query": text}, {})


class TestSSN:
    def test_detects_ssn(self):
        findings = _scan("my SSN is 123-45-6789")
        assert any(f.metadata.get("entity_type") == "US_SSN" for f in findings)

    def test_ssn_is_critical(self):
        findings = _scan("SSN: 999-88-7777")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)


class TestCreditCard:
    def test_detects_visa(self):
        findings = _scan("card 4532015112830366")
        assert any(f.metadata.get("entity_type") == "CREDIT_CARD" for f in findings)

    def test_detects_mastercard(self):
        findings = _scan("pay with 5425233430109903")
        assert any(f.metadata.get("entity_type") == "CREDIT_CARD" for f in findings)

    def test_detects_amex(self):
        findings = _scan("amex 378282246310005")
        assert any(f.metadata.get("entity_type") == "CREDIT_CARD" for f in findings)


class TestEmail:
    def test_detects_email(self):
        findings = _scan("contact john@example.com")
        assert any(f.metadata.get("entity_type") == "EMAIL_ADDRESS" for f in findings)


class TestPhone:
    def test_detects_us_phone(self):
        findings = _scan("call me at 555-123-4567")
        assert any(f.metadata.get("entity_type") == "PHONE_US" for f in findings)

    def test_detects_phone_with_country_code(self):
        findings = _scan("reach me at +1-555-123-4567")
        assert any(f.metadata.get("entity_type") == "PHONE_US" for f in findings)


class TestSecrets:
    def test_detects_aws_key(self):
        findings = _scan("key is AKIAIOSFODNN7EXAMPLE")
        assert any(f.metadata.get("entity_type") == "AWS_ACCESS_KEY" for f in findings)

    def test_detects_generic_api_key(self):
        findings = _scan("api_key=sk_live_abc123def456ghi")
        assert any(f.metadata.get("entity_type") == "GENERIC_SECRET" for f in findings)

    def test_detects_github_token(self):
        findings = _scan("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert any(f.metadata.get("entity_type") == "GITHUB_TOKEN" for f in findings)


class TestRedaction:
    def test_redacts_ssn(self):
        args = {"query": "my SSN is 123-45-6789"}
        findings = det.scan_input("tool", args, {})
        modified = det.modify_arguments(args, findings)
        assert modified is not None
        assert "123-45-6789" not in str(modified)
        assert "***-**-****" in str(modified)

    def test_redacts_credit_card(self):
        args = {"query": "card 4532015112830366"}
        findings = det.scan_input("tool", args, {})
        modified = det.modify_arguments(args, findings)
        assert modified is not None
        assert "4532015112830366" not in str(modified)

    def test_no_modification_when_clean(self):
        args = {"query": "normal text"}
        findings = det.scan_input("tool", args, {})
        modified = det.modify_arguments(args, findings)
        assert modified is None


class TestOutputScanning:
    def test_detects_pii_in_output(self):
        findings = det.scan_output("tool", "User SSN: 123-45-6789")
        assert len(findings) > 0

    def test_clean_output(self):
        findings = det.scan_output("tool", "Product: Widget, Price: $10")
        assert len(findings) == 0


class TestCleanInputs:
    def test_normal_text(self):
        assert len(_scan("what is the price of apples?")) == 0

    def test_numbers_that_look_like_pii(self):
        # Short numbers shouldn't trigger
        assert len(_scan("I have 3 items")) == 0

    def test_empty(self):
        assert len(_scan("")) == 0