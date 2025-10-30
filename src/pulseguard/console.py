"""Interactive console for PulseGuard."""

import cmd
from typing import Any, List

from .commands import (
    generate_console_help,
    get_command_args,
    get_command_handler,
    resolve_command_name,
)
from .messages import (
    CONSOLE_INTRO,
    CONSOLE_PROMPT,
    ERROR_MUTUALLY_EXCLUSIVE_GEN,
    ERROR_USAGE_ADD,
    INFO_GOODBYE,
)
from .vault import Vault


class Console(cmd.Cmd):
    """Interactive console for password management."""

    def __init__(self, vault: Vault):
        """Initialize console with vault instance."""
        super().__init__()
        self.vault = vault
        self.intro = CONSOLE_INTRO
        self.prompt = CONSOLE_PROMPT

    def default(self, line: str) -> None:
        """Handle all commands and aliases through dynamic resolution."""
        if not line.strip():
            return

        parts = line.split()
        command_name = parts[0]
        args = " ".join(parts[1:]) if len(parts) > 1 else ""

        resolved_name = resolve_command_name(command_name)
        if not resolved_name:
            print(f"*** Unknown syntax: {command_name}")
            return

        handler = get_command_handler(resolved_name)
        if not handler:
            print(f"*** Unknown syntax: {command_name}")
            return

        cmd_args = get_command_args(resolved_name)
        handler_args: List[Any] = [self.vault]

        if resolved_name == "add":
            parts = args.split()
            if not parts:
                print(ERROR_USAGE_ADD)
                return

            gen = False
            length = 16
            lower = True
            upper = True
            digits = True
            symbols = False

            cleaned = []
            i = 0
            while i < len(parts):
                tok = parts[i]
                nxt = parts[i + 1] if i + 1 < len(parts) else ""
                if tok == "--gen":
                    gen = True
                    i += 1
                elif tok == "--length" and nxt:
                    try:
                        length = int(nxt)
                    except ValueError:
                        pass
                    i += 2
                elif tok == "--lower" and nxt:
                    lower = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--upper" and nxt:
                    upper = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--digits" and nxt:
                    digits = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--symbols" and nxt:
                    symbols = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--url" and nxt:
                    # on garde --url et son argument pour la passe 2
                    cleaned.extend([tok, nxt])
                    i += 2
                elif tok == "--notes" and nxt:
                    cleaned.extend([tok, nxt])
                    i += 2
                else:
                    cleaned.append(tok)
                    i += 1

            parts = cleaned

            if len(parts) < 2:
                print(ERROR_USAGE_ADD)
                return

            name = parts[0]
            username = parts[1]

            password = ""
            idx = 2
            if idx < len(parts) and not parts[idx].startswith("--"):
                password = parts[idx]
                idx += 1

            url = ""
            notes = ""
            while idx < len(parts):
                tok = parts[idx]
                nxt = parts[idx + 1] if idx + 1 < len(parts) else ""
                if tok == "--url" and nxt:
                    url = nxt
                    idx += 2
                elif tok == "--notes" and nxt:
                    notes = nxt
                    idx += 2
                else:
                    idx += 1

            if not gen and not password:
                print(ERROR_USAGE_ADD)
                return

            if gen and password:
                print(ERROR_MUTUALLY_EXCLUSIVE_GEN)
                return

            handler_args.extend(
                [
                    name,
                    username,
                    password,
                    url,
                    notes,
                    gen,
                    length,
                    lower,
                    upper,
                    digits,
                    symbols,
                ]
            )
            try:
                handler(*handler_args)
            except Exception as e:
                print(f"Error executing command: {e}")
            return

        elif resolved_name == "genpass":
            gp_parts = args.split() if args else []
            length = 16
            lower = True
            upper = True
            digits = True
            symbols = False
            i = 0
            while i < len(gp_parts):
                tok = gp_parts[i]
                nxt = gp_parts[i + 1] if i + 1 < len(gp_parts) else ""
                if tok == "--length" and nxt:
                    try:
                        length = int(nxt)
                    except ValueError:
                        pass
                    i += 2
                elif tok == "--lower" and nxt:
                    lower = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--upper" and nxt:
                    upper = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--digits" and nxt:
                    digits = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                elif tok == "--symbols" and nxt:
                    symbols = nxt.lower() in ("1", "true", "yes", "y")
                    i += 2
                else:
                    i += 1
            handler_args.extend([length, lower, upper, digits, symbols])

        else:
            for arg in cmd_args:
                arg_name = arg["name"].lstrip("-")
                if arg_name in ["name", "query"] and args.strip():
                    handler_args.append(args.strip())
                    break

        try:
            handler(*handler_args)
        except Exception as e:
            print(f"Error executing command: {e}")

    def do_help(self, args: str) -> None:
        """Show help information for commands and aliases."""
        if args.strip():
            super().do_help(args)
        else:
            print(generate_console_help())

    def do_quit(self, args: str) -> bool:
        """Quit the console."""
        print(INFO_GOODBYE)
        return True

    def do_exit(self, args: str) -> bool:
        """Exit the console - alias for quit."""
        return self.do_quit(args)

    def emptyline(self) -> bool:
        """Handle empty input lines gracefully."""
        return False
