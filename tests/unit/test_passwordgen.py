"""
Unit tests for password generation and clipboard operations.

This module tests:
- Password generation with configurable character sets
- Character set building and validation
- Length enforcement and character class requirements
- Cross-platform clipboard operations (with fallbacks)
- Auto-clear clipboard functionality for security
"""

import pytest

from pulseguard.passwordgen import (
    DEFAULT_LEN,
    GenOptions,
    build_charset,
    clear_clipboard,
    copy_to_clipboard,
    copy_to_clipboard_with_autoclear,
    enforce_limits,
    generate_password,
)


class TestCharsetBuilding:
    """Test character set construction for password generation."""

    def test_builds_all_character_types(self):
        """Charset should include all enabled character types."""
        opts = GenOptions(length=12, lower=True, upper=True, digits=True, symbols=True)
        charset = build_charset(opts)

        assert any(c.islower() for c in charset), "Should contain lowercase"
        assert any(c.isupper() for c in charset), "Should contain uppercase"
        assert any(c.isdigit() for c in charset), "Should contain digits"
        assert any(
            c in "!@#$%^&*()-_=+[]{};:,.?/" for c in charset
        ), "Should contain symbols"

    def test_respects_disabled_character_types(self):
        """Charset should exclude disabled character types."""
        opts = GenOptions(
            length=12, lower=False, upper=True, digits=False, symbols=True
        )
        charset = build_charset(opts)

        assert not any(c.islower() for c in charset), "Should not contain lowercase"
        assert any(c.isupper() for c in charset), "Should contain uppercase"
        assert not any(c.isdigit() for c in charset), "Should not contain digits"
        assert any(
            c in "!@#$%^&*()-_=+[]{};:,.?/" for c in charset
        ), "Should contain symbols"

    def test_raises_error_when_all_types_disabled(self):
        """Must have at least one character type enabled."""
        with pytest.raises(ValueError, match="No character classes selected"):
            build_charset(
                GenOptions(lower=False, upper=False, digits=False, symbols=False)
            )


class TestLengthEnforcement:
    """Test password length validation and requirements."""

    def test_rejects_zero_length(self):
        """Password must be at least 1 character."""
        opts = GenOptions(length=0, lower=True)
        with pytest.raises(ValueError, match="at least 1"):
            enforce_limits(0, opts)

    def test_accepts_any_positive_length(self):
        """Any positive length should be valid if character classes fit."""
        opts_single = GenOptions(
            length=1, lower=True, upper=False, digits=False, symbols=False
        )
        assert enforce_limits(1, opts_single) == 1

        opts_default = GenOptions(length=DEFAULT_LEN)
        assert enforce_limits(DEFAULT_LEN, opts_default) == DEFAULT_LEN

        opts_long = GenOptions(length=100)
        assert enforce_limits(100, opts_long) == 100

    def test_requires_minimum_for_all_character_classes(self):
        """Length must accommodate one char from each enabled class."""
        # 4 classes enabled, but only 3 chars requested
        opts = GenOptions(length=3, lower=True, upper=True, digits=True, symbols=True)
        with pytest.raises(ValueError, match="at least 4"):
            enforce_limits(3, opts)

        # 4 classes enabled, 4 chars is ok
        opts_ok = GenOptions(
            length=4, lower=True, upper=True, digits=True, symbols=True
        )
        assert enforce_limits(4, opts_ok) == 4

        # 2 classes enabled, but only 1 char requested
        opts_two = GenOptions(
            length=1, lower=True, upper=True, digits=False, symbols=False
        )
        with pytest.raises(ValueError, match="at least 2"):
            enforce_limits(1, opts_two)


class TestPasswordGeneration:
    """Test actual password generation logic."""

    def test_generates_correct_length(self):
        """Generated password should match requested length."""
        opts = GenOptions(length=16, lower=True, upper=True, digits=True, symbols=True)
        password = generate_password(opts)
        assert len(password) == 16

    def test_includes_all_required_character_classes(self):
        """Password must contain at least one from each enabled class."""
        opts = GenOptions(length=16, lower=True, upper=True, digits=True, symbols=True)
        password = generate_password(opts)

        import re

        assert re.search(r"[a-z]", password), "Should contain lowercase"
        assert re.search(r"[A-Z]", password), "Should contain uppercase"
        assert re.search(r"[0-9]", password), "Should contain digit"
        assert re.search(
            r"[!@#$%^&*()\-\_=+\[\]{};:,.?/]", password
        ), "Should contain symbol"

    def test_generates_only_selected_character_types(self):
        """Password should only contain enabled character types."""
        opts = GenOptions(
            length=10, lower=False, upper=True, digits=False, symbols=False
        )
        password = generate_password(opts)

        assert len(password) == 10
        assert all(c.isupper() for c in password), "Should only contain uppercase"

    def test_generates_numeric_only_password(self):
        """Should generate valid numeric-only passwords (PINs)."""
        opts = GenOptions(
            length=8, lower=False, upper=False, digits=True, symbols=False
        )
        password = generate_password(opts)

        assert len(password) == 8
        assert password.isdigit(), "Should be all digits"


class TestClipboardOperations:
    """Test clipboard copy/paste functionality across platforms."""

    def test_copy_uses_pyperclip_when_available(self, monkeypatch):
        """Should prefer pyperclip library when available."""
        # Mock pyperclip module
        fake_pyperclip = type("FakePyperclip", (), {})()
        call_tracker = {"called": False, "text": None}

        def mock_copy(text):
            call_tracker["called"] = True
            call_tracker["text"] = text

        fake_pyperclip.copy = mock_copy

        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", fake_pyperclip)

        result = copy_to_clipboard("test_text")

        assert result is True, "Should return True on success"
        assert call_tracker["called"], "Should call pyperclip.copy"
        assert call_tracker["text"] == "test_text", "Should pass correct text"

    def test_falls_back_when_pyperclip_fails(self, monkeypatch):
        """Should try fallback methods when pyperclip raises exception."""
        fake_pyperclip = type("FakePyperclip", (), {})()

        def failing_copy(text):
            raise Exception("Clipboard error")

        fake_pyperclip.copy = failing_copy

        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", fake_pyperclip)
        monkeypatch.setattr(pg.sys, "platform", "unsupported_platform")

        result = copy_to_clipboard("test")
        assert result is False, "Should return False when all methods fail"

    def test_linux_xclip_fallback(self, monkeypatch):
        """Should use xclip on Linux when pyperclip unavailable."""
        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", None)
        monkeypatch.setattr(pg.sys, "platform", "linux")

        class MockPopen:
            def __init__(self, cmd, stdin=None, stderr=None):
                self.returncode = 0

            def communicate(self, input=None, timeout=None):
                return (b"", b"")

        monkeypatch.setattr(pg.subprocess, "Popen", MockPopen)

        result = copy_to_clipboard("test")
        assert result is True, "Should succeed with xclip"

    def test_linux_all_tools_missing(self, monkeypatch):
        """Should fail gracefully when no clipboard tools available on Linux."""
        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", None)
        monkeypatch.setattr(pg.sys, "platform", "linux")

        class MockPopenMissing:
            def __init__(self, cmd, stdin=None, stderr=None):
                raise FileNotFoundError("Tool not found")

        monkeypatch.setattr(pg.subprocess, "Popen", MockPopenMissing)

        result = copy_to_clipboard("test")
        assert result is False, "Should return False when tools missing"

    def test_clear_clipboard(self):
        """Clear clipboard should attempt to copy empty string."""
        result = clear_clipboard()
        assert isinstance(result, bool), "Should return boolean"

    def test_autoclear_with_zero_timeout(self):
        """Auto-clear with timeout=0 should not start background thread."""
        result = copy_to_clipboard_with_autoclear("test", timeout=0)
        assert isinstance(result, bool), "Should return boolean"


class TestClipboardAutoClear:
    """Test automatic clipboard clearing for security."""

    def test_clears_when_content_matches(self, monkeypatch):
        """Should clear clipboard if content hasn't changed."""
        import pulseguard.passwordgen as pg

        fake_pyperclip = type("FakePyperclip", (), {})()
        fake_pyperclip.paste = lambda: "test_content"
        fake_pyperclip.copy = lambda x: None

        monkeypatch.setattr(pg, "pyperclip", fake_pyperclip)

        notify_called = {"called": False}

        def notify():
            notify_called["called"] = True

        pg._clipboard_clear_worker(0, "test_content", notify)

        assert notify_called["called"], "Should call notify callback"

    def test_does_not_clear_when_content_changed(self, monkeypatch):
        """Should not clear clipboard if user copied something else."""
        import pulseguard.passwordgen as pg

        fake_pyperclip = type("FakePyperclip", (), {})()
        fake_pyperclip.paste = lambda: "different_content"

        monkeypatch.setattr(pg, "pyperclip", fake_pyperclip)

        notify_called = {"called": False}

        def notify():
            notify_called["called"] = True

        pg._clipboard_clear_worker(0, "original_content", notify)

        assert not notify_called["called"], "Should not clear if content differs"

    def test_handles_paste_exceptions_gracefully(self, monkeypatch):
        """Should not crash if clipboard paste fails."""
        import pulseguard.passwordgen as pg

        fake_pyperclip = type("FakePyperclip", (), {})()

        def failing_paste():
            raise Exception("Clipboard read error")

        fake_pyperclip.paste = failing_paste

        monkeypatch.setattr(pg, "pyperclip", fake_pyperclip)

        # Should not raise exception
        try:
            pg._clipboard_clear_worker(0, "test", None)
        except Exception as e:
            pytest.fail(f"Should handle exceptions gracefully, got: {e}")
