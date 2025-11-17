"""Secure password generator and clipboard utilities."""

import secrets
import string
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

try:
    import pyperclip as _pyperclip

    pyperclip: Optional[Any] = _pyperclip
except Exception:
    pyperclip = None


SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
MAX_LEN = 128  # Maximum password length (aligned with Config.MAX_PASSWORD_LENGTH)
DEFAULT_LEN = 16
CLIPBOARD_TIMEOUT_SECONDS = 30
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

    if length > MAX_LEN:
        raise ValueError(
            f"Password length ({length}) exceeds maximum allowed length ({MAX_LEN} characters)."
        )

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


def clear_clipboard() -> bool:
    """
    Clear clipboard by copying empty string.
    Returns True on success, False on failure.
    """
    return copy_to_clipboard("")


def _clipboard_clear_worker(
    timeout: int, clipboard_content: str, notify_callback=None
) -> None:
    """
    Background worker that clears clipboard after timeout.
    Only clears if clipboard still contains the original content (not modified by user).

    Args:
        timeout: Seconds to wait before clearing
        clipboard_content: Original content that was copied
        notify_callback: Optional function to call after clearing
    """
    time.sleep(timeout)

    # Try to verify clipboard hasn't been modified by user before clearing
    # This is best-effort - not all platforms support clipboard reading
    try:
        if pyperclip:
            current = pyperclip.paste()
            # Only clear if clipboard still contains what we copied
            if current == clipboard_content:
                clear_clipboard()
                if notify_callback:
                    notify_callback()
    except Exception:
        # If we can't read clipboard, don't clear (user may have copied something else)
        pass


def copy_to_clipboard_with_autoclear(
    text: str, timeout: int = CLIPBOARD_TIMEOUT_SECONDS, notify_callback=None
) -> bool:
    """
    Copy text to clipboard and automatically clear after timeout.

    Args:
        text: Text to copy
        timeout: Seconds before auto-clearing (default: 30)
        notify_callback: Optional function to call when clipboard is cleared

    Returns:
        True if copy successful, False otherwise
    """
    success = copy_to_clipboard(text)

    if success and timeout > 0:
        # Start background thread to clear clipboard
        thread = threading.Thread(
            target=_clipboard_clear_worker,
            args=(timeout, text, notify_callback),
            daemon=True,
        )
        thread.start()

    return success
