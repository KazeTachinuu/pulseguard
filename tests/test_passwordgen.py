"""Comprehensive tests for passwordgen module.

Tests all generation handlers including:
- checks charset construction
- ensures ValueError on empty charset
- validates password length boundarie
- ensures mixed-char passwords of correct length
- tests specific character sets
- Clipboard tests
"""

import re

import pytest

from pulseguard.passwordgen import (
    DEFAULT_LEN,
    MAX_LEN,
    MIN_LEN,
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
        with pytest.raises(ValueError):
            enforce_limits(MIN_LEN - 1)

    def test_enforce_limits_max(self):
        with pytest.raises(ValueError):
            enforce_limits(MAX_LEN + 1)

    def test_enforce_limits_ok(self):
        assert enforce_limits(DEFAULT_LEN) == DEFAULT_LEN


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

            def communicate(self, input=None):
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
