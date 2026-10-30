"""Tests del redactor."""

from bazzingakit.ai.context import Redactor


def test_redacts_home_paths():
    text = "Error at /home/juan/project/file.py"
    result = Redactor.clean(text)
    assert "/home/USER" in result
    assert "juan" not in result


def test_redacts_private_ips():
    text = "Connected to 192.168.1.50 and 10.0.0.1"
    result = Redactor.clean(text)
    assert "192.168" not in result
    assert "10.0" not in result


def test_redacts_api_keys():
    text = 'api_key="sk-abc123def456ghi789"'
    result = Redactor.clean(text)
    assert "sk-abc123def456ghi789" not in result
    assert "REDACTED" in result


def test_redacts_jwt():
    text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4f"
    result = Redactor.clean(text)
    assert "JWT_REDACTED" in result


def test_preserves_safe_text():
    text = "This is a normal log message about network events."
    result = Redactor.clean(text)
    assert result == text


def test_clean_if_enabled_respects_flag():
    text = "/home/juan/foo"
    assert Redactor.clean_if_enabled(text, enabled=False) == text
    assert "/home/USER" in Redactor.clean_if_enabled(text, enabled=True)
