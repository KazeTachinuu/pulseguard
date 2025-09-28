"""Interactive console - discoverable, user-friendly interface.

Why: Helps users discover commands, uses same system as CLI, handles aliases.
Stays in sync with CLI automatically - no duplication.
"""

import cmd

from .commands import (
    COMMANDS,
    generate_console_help,
    get_command_handler,
    get_command_args,
    resolve_command_name,
)
from .config import config
from .messages import (
    CONSOLE_INTRO,
    CONSOLE_PROMPT,
    ERROR_USAGE_ADD,
    INFO_GOODBYE,
)
from .vault import Vault


class Console(cmd.Cmd):
    """Interactive console for discoverable password management.
    
    Why: cmd.Cmd provides robust parsing, dynamic resolution enables aliases.
    Users can type 'list' or 'ls' - both work identically.
    """

    def __init__(self, vault: Vault = None):
        """Initialize console with optional vault instance.
        
        Why: Optional vault enables testing, default provides zero-config experience.
        """
        super().__init__()
        self.vault = vault or Vault()
        self.intro = CONSOLE_INTRO
        self.prompt = CONSOLE_PROMPT

    def default(self, line: str) -> None:
        """Handle all commands and aliases through dynamic resolution.
        
        Why: Single method handles all commands, enables aliases, uses same system as CLI.
        """
        if not line.strip():
            return

        # Parse command and arguments from user input
        parts = line.split()
        command_name = parts[0]
        args = " ".join(parts[1:]) if len(parts) > 1 else ""

        # Resolve command name or alias to canonical name
        # This enables users to type either 'list' or 'ls'
        resolved_name = resolve_command_name(command_name)
        if not resolved_name:
            print(f"*** Unknown syntax: {command_name}")
            return

        # Get the handler function for this command
        handler = get_command_handler(resolved_name)
        if not handler:
            print(f"*** Unknown syntax: {command_name}")
            return

        # Build argument list for handler function
        cmd_args = get_command_args(resolved_name)
        handler_args = [self.vault]  # All handlers expect vault as first argument

        if resolved_name == "add":
            # Special handling for add command - it has complex optional arguments
            # This is the only command that needs custom argument parsing
            add_parts = args.split()
            if len(add_parts) < 3:
                print(ERROR_USAGE_ADD)
                return

            name, username, password = add_parts[0], add_parts[1], add_parts[2]
            url, notes = "", ""

            # Parse optional --url and --notes arguments
            i = 3
            while i < len(add_parts):
                if add_parts[i] == "--url" and i + 1 < len(add_parts):
                    url = add_parts[i + 1]
                    i += 2
                elif add_parts[i] == "--notes" and i + 1 < len(add_parts):
                    notes = add_parts[i + 1]
                    i += 2
                else:
                    i += 1

            handler_args.extend([name, username, password, url, notes])
        else:
            # For other commands, pass arguments in order
            # Most commands take a single argument (name or query)
            for arg in cmd_args:
                arg_name = arg["name"].lstrip("-")
                if arg_name in ["name", "query"] and args.strip():
                    handler_args.append(args.strip())
                    break

        # Execute the command handler
        # This provides the same behavior as CLI mode
        try:
            handler(*handler_args)
        except Exception as e:
            print(f"Error executing command: {e}")

    def do_help(self, args: str) -> None:
        """Show help information for commands and aliases.
        
        Why: Uses cmd.Cmd's built-in help for specific commands, custom help for general.
        """
        if args.strip():
            # Show help for specific command using cmd.Cmd's built-in help
            super().do_help(args)
        else:
            # Show general help with aliases
            print(generate_console_help())

    def do_quit(self, args: str) -> bool:
        """Quit the console with friendly goodbye message.
        
        Why: Clear exit mechanism, friendly message, returns True to signal exit.
        """
        print(INFO_GOODBYE)
        return True

    def do_exit(self, args: str) -> bool:
        """Exit the console - alias for quit command.
        
        Why: Some users expect 'exit', others 'quit' - provides flexibility.
        """
        return self.do_quit(args)

    def emptyline(self) -> None:
        """Handle empty input lines gracefully.
        
        Why: Prevents cmd.Cmd from repeating last command, clean behavior.
        """
        pass
