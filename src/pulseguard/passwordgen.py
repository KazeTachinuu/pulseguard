"""Secure password generator and clipboard utilities."""

import secrets
import string
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Optional

try:
    import pyperclip as _pyperclip

    pyperclip: Optional[Any] = _pyperclip
except Exception:
    pyperclip = None


SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
MAX_LEN = 25
DEFAULT_LEN = 16
MIN_LEN = 8


@dataclass
class GenOptions:
    length: int = DEFAULT_LEN
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = False


def build_charset(opts: GenOptions) -> str:
    charset = ""
    if opts.lower:
        charset += string.ascii_lowercase
    if opts.upper:
        charset += string.ascii_uppercase
    if opts.digits:
        charset += string.digits
    if opts.symbols:
        # Symbols available for rand gen
        charset += SYMBOLS

    if not charset:
        raise ValueError("No character classes selected (lower/upper/digits/symbols).")
    return charset


def enforce_limits(length: int, opts: GenOptions) -> int:
    """Validate password length against enabled character classes."""
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    # Count required characters (one per enabled class)
    required_chars = sum([opts.lower, opts.upper, opts.digits, opts.symbols])

    if length < required_chars:
        raise ValueError(
            f"Password length ({length}) must be at least {required_chars} "
            f"to include one character from each enabled character class."
        )

    return length


def generate_password(opts: GenOptions) -> str:
    enforce_limits(opts.length, opts)
    charset = build_charset(opts)

    required = []
    if opts.lower:
        required.append(secrets.choice(string.ascii_lowercase))
    if opts.upper:
        required.append(secrets.choice(string.ascii_uppercase))
    if opts.digits:
        required.append(secrets.choice(string.digits))
    if opts.symbols:
        required.append(secrets.choice(SYMBOLS))

    while len(required) < opts.length:
        required.append(secrets.choice(charset))

    pw_chars = required[:]
    for i in range(len(pw_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]

    return "".join(pw_chars)


def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to clipboard. Returns True on success, False on failure.

    Tries multiple methods in order:
    1. pyperclip library (cross-platform)
    2. Platform-specific command-line tools via subprocess

    Supports: macOS, Windows, Linux (X11 and Wayland), BSD
    """
    # Preferred: pyperclip (cross-platform library)
    if pyperclip:
        try:
            pyperclip.copy(text)
            return True
        except Exception:
            # pyperclip failed, try subprocess fallback
            pass

    # Fallback: platform-specific command-line tools
    p = None
    try:
        if sys.platform == "darwin":
            # macOS
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"), timeout=5)
            return p.returncode == 0

        elif sys.platform.startswith("linux") or sys.platform.startswith("freebsd"):
            # Linux/BSD: Try Wayland (wl-copy), then X11 (xclip, xsel) clipboard tools
            for cmd in (
                ["wl-copy"],  # Wayland
                ["xclip", "-selection", "clipboard"],  # X11
                ["xsel", "--clipboard", "--input"],  # X11
            ):
                try:
                    p = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL
                    )
                    p.communicate(input=text.encode("utf-8"), timeout=5)
                    if p.returncode == 0:
                        return True
                except FileNotFoundError:
                    # Tool not installed, try next one
                    continue
                except subprocess.TimeoutExpired:
                    if p is not None:
                        p.kill()
                        p.wait()
                    continue

        elif sys.platform.startswith("win"):
            # Windows
            p = subprocess.Popen(
                ["clip"], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            p.communicate(input=text.encode("utf-8"), timeout=5)
            return p.returncode == 0

    except subprocess.TimeoutExpired:
        # Cleanup timed-out process
        if p is not None:
            p.kill()
            p.wait()
    except Exception:
        # Catch any other unexpected errors (permission issues, etc.)
        pass

    return False
