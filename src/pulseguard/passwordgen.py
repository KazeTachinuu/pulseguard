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
    """Copy text to clipboard. Returns True on success."""
    # Preferred: pyperclip
    if pyperclip:
        try:
            pyperclip.copy(text)
            return True
        except Exception:
            pass

    # in case it failed give more info and add fallback
    try:
        if sys.platform == "darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"), timeout=5)
            return p.returncode == 0
        elif sys.platform.startswith("linux"):
            # Requires xclip or xsel installed
            for cmd in (
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
            ):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    p.communicate(input=text.encode("utf-8"), timeout=5)
                    if p.returncode == 0:
                        return True
                except FileNotFoundError:
                    continue
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                    continue
        elif sys.platform.startswith("win"):
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"), timeout=5)
            return p.returncode == 0
    except subprocess.TimeoutExpired:
        if "p" in locals():
            p.kill()
            p.wait()
    except Exception:
        pass
    return False
