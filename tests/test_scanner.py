"""Tests for the secrets scanner."""
from secretscanner.scanner import redact, scan_text


def _rules(text):
    return {f.rule for f in scan_text(text)}


def test_detects_aws_access_key():
    assert "AWS Access Key ID" in _rules("key = AKIAIOSFODNN7EXAMPLE")


def test_detects_private_key_header():
    assert "Private Key" in _rules("-----BEGIN RSA PRIVATE KEY-----")


def test_detects_github_token():
    assert "GitHub Token" in _rules("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz")


def test_clean_text_has_no_findings():
    assert scan_text("just some normal config\nname = service\n") == []


def test_placeholder_is_ignored():
    assert scan_text('password = "your_password_here"') == []


def test_allowlist_marker_skips_line():
    line = 'api_key = "a1b2c3d4e5f6g7h8"  # pragma: allowlist secret'
    assert scan_text(line) == []


def test_redact_hides_value():
    out = redact("AKIAIOSFODNN7EXAMPLE")
    assert "IOSFODNN" not in out
    assert out.startswith("AKIA")
