"""Secure password generator and clipboard utilities."""

from dataclasses import dataclass
import secrets
import string
import subprocess
import sys

try:
    import pyperclip
except Exception:
    pyperclip = None


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
        charset += "!@#$%^&*()-_=+[]{};:,.?/"

    if not charset:
        raise ValueError("No character classes selected (lower/upper/digits/symbols).")
    return charset


def enforce_limits(length: int) -> int:
    if length < MIN_LEN:
        raise ValueError(f"Password length must be >= {MIN_LEN}.")
    if length > MAX_LEN:
        raise ValueError(f"Password length must be <= {MAX_LEN}.")
    return length


def generate_password(opts: GenOptions) -> str:
    enforce_limits(opts.length)
    charset = build_charset(opts)

    required = []
    if opts.lower:
        required.append(secrets.choice(string.ascii_lowercase))
    if opts.upper:
        required.append(secrets.choice(string.ascii_uppercase))
    if opts.digits:
        required.append(secrets.choice(string.digits))
    if opts.symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.?/"))

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
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
        elif sys.platform.startswith("linux"):
            # Requires xclip or xsel installed
            for cmd in (["xclip", "-selection", "clipboard"],
                        ["xsel", "--clipboard", "--input"]):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    p.communicate(input=text.encode("utf-8"))
                    if p.returncode == 0:
                        return True
                except FileNotFoundError:
                    continue
        elif sys.platform.startswith("win"):
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
    except Exception:
        pass
    return False
