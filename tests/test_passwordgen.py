"""Comprehensive tests for passwordgen module.

Tests all generation handlers including:
- checks charset construction
- ensures ValueError on empty charset
- validates password length boundaries
- ensures mixed-char passwords of correct length
- tests specific character sets
- Clipboard tests
"""

import re

import pytest

from pulseguard.passwordgen import (
    DEFAULT_LEN,
    GenOptions,
    build_charset,
    copy_to_clipboard,
    enforce_limits,
    generate_password,
)


class TestCharsetAndLimits:
    def test_build_charset_all_true(self):
        opts = GenOptions(length=12, lower=True, upper=True, digits=True, symbols=True)
        cs = build_charset(opts)
        assert any(c.islower() for c in cs)
        assert any(c.isupper() for c in cs)
        assert any(c.isdigit() for c in cs)
        assert any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in cs)

    def test_build_charset_some_false(self):
        opts = GenOptions(
            length=12, lower=False, upper=True, digits=False, symbols=True
        )
        cs = build_charset(opts)
        assert not any(c.islower() for c in cs)
        assert any(c.isupper() for c in cs)
        assert not any(c.isdigit() for c in cs)
        assert any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in cs)

    def test_build_charset_raises_when_empty(self):
        with pytest.raises(ValueError):
            build_charset(
                GenOptions(lower=False, upper=False, digits=False, symbols=False)
            )

    def test_enforce_limits_min(self):
        """Test that passwords with length < 1 raise an error."""
        opts = GenOptions(length=0, lower=True)
        with pytest.raises(ValueError, match="at least 1"):
            enforce_limits(0, opts)

    def test_enforce_limits_allows_any_positive(self):
        """Test that any positive length is allowed when >= required chars."""
        opts_one = GenOptions(
            length=1, lower=True, upper=False, digits=False, symbols=False
        )
        assert enforce_limits(1, opts_one) == 1

        opts_default = GenOptions(length=DEFAULT_LEN)
        assert enforce_limits(DEFAULT_LEN, opts_default) == DEFAULT_LEN

        opts_long = GenOptions(length=100)
        assert enforce_limits(100, opts_long) == 100

    def test_enforce_limits_requires_min_for_all_classes(self):
        """Test that length must be >= number of enabled character classes."""
        # All 4 classes enabled, need at least 4 chars
        opts_all = GenOptions(
            length=3, lower=True, upper=True, digits=True, symbols=True
        )
        with pytest.raises(ValueError, match="at least 4"):
            enforce_limits(3, opts_all)

        # Should work with length=4
        opts_all_ok = GenOptions(
            length=4, lower=True, upper=True, digits=True, symbols=True
        )
        assert enforce_limits(4, opts_all_ok) == 4

        # Only 2 classes enabled, need at least 2 chars
        opts_two = GenOptions(
            length=1, lower=True, upper=True, digits=False, symbols=False
        )
        with pytest.raises(ValueError, match="at least 2"):
            enforce_limits(1, opts_two)


class TestGeneratePassword:
    def test_generate_respects_length_and_classes(self):
        # require all classes to appear at least once
        opts = GenOptions(length=16, lower=True, upper=True, digits=True, symbols=True)
        pw = generate_password(opts)
        assert len(pw) == 16
        assert re.search(r"[a-z]", pw)
        assert re.search(r"[A-Z]", pw)
        assert re.search(r"[0-9]", pw)
        assert re.search(r"[!@#$%^&*()\-\_=+\[\]{};:,.?/]", pw)

    def test_generate_only_upper(self):
        opts = GenOptions(
            length=10, lower=False, upper=True, digits=False, symbols=False
        )
        pw = generate_password(opts)
        assert len(pw) == 10
        assert all(c.isupper() for c in pw)

    def test_generate_only_digits(self):
        opts = GenOptions(
            length=8, lower=False, upper=False, digits=True, symbols=False
        )
        pw = generate_password(opts)
        assert len(pw) == 8
        assert pw.isdigit()


class TestClipboard:
    def test_copy_to_clipboard_uses_pyperclip_when_available(self, monkeypatch):
        # pretend pyperclip.copy works
        fake_mod = type("P", (), {})()
        called = {"ok": False}

        def _copy(x):
            called["ok"] = x == "abc"

        fake_mod.copy = _copy
        # Inject into module
        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", fake_mod, raising=True)
        assert copy_to_clipboard("abc") is True
        assert called["ok"]

    def test_copy_to_clipboard_linux_xclip_ok(self, monkeypatch):
        # simulate no pyperclip, but xclip works
        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", None, raising=True)
        monkeypatch.setattr(pg.sys, "platform", "linux", raising=True)

        class PopenOK:
            def __init__(self, cmd, stdin=None):
                self.returncode = 0
                self.cmd = cmd

            def communicate(self, input=None, timeout=None):
                self.returncode = 0

        monkeypatch.setattr(pg.subprocess, "Popen", PopenOK, raising=True)
        assert copy_to_clipboard("hello") is True

    def test_copy_to_clipboard_linux_all_fail(self, monkeypatch):
        # no pyperclip; xclip/xsel missing => FileNotFoundError; returns False
        import pulseguard.passwordgen as pg

        monkeypatch.setattr(pg, "pyperclip", None, raising=True)
        monkeypatch.setattr(pg.sys, "platform", "linux", raising=True)

        class PopenMissing:
            def __init__(self, cmd, stdin=None):
                raise FileNotFoundError

        monkeypatch.setattr(pg.subprocess, "Popen", PopenMissing, raising=True)
        assert copy_to_clipboard("nope") is False
