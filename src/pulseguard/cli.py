"""Modern CLI using Typer framework."""

import os
import sys
from typing import Optional

import typer
from typing_extensions import Annotated

from . import ui
from .cli_helpers import (
    COMMAND_ALIASES,
    display_security_health_check,
    display_vault_stats,
    get_help_with_aliases,
    get_vault,
    interactive_mode,
    prompt_and_generate_password,
)
from .cli_operations import (
    core_add_entry,
    core_delete_entry,
    core_edit_entry,
    core_get_entry,
    core_list_categories,
    core_list_entries,
    core_move_entries_to_category,
    core_rename_category,
)
from .config import config

app = typer.Typer(
    name="pulseguard",
    help="Secure password manager with modern CLI",
    add_completion=True,
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    vault: Annotated[
        Optional[str],
        typer.Option(
            "--vault",
            "-v",
            help="Path to vault file (default: ~/.pulseguard/vault.json)",
        ),
    ] = None,
):
    """PulseGuard password manager - runs interactive mode if no command given."""
    if vault:
        config.vault_path = os.path.expanduser(vault)

    if ctx.invoked_subcommand is None:
        interactive_mode()
        raise typer.Exit(0)


@app.command("list", help=get_help_with_aliases("List all password entries", "list"))
def list_entries():
    """List all password entries."""
    vault = get_vault()
    core_list_entries(vault)


@app.command("add", help=get_help_with_aliases("Add a new password entry", "add"))
def add_entry():
    """Add a new password entry interactively."""
    vault = get_vault()
    core_add_entry(vault)


@app.command("get", help=get_help_with_aliases("Get password details", "get"))
def get_entry():
    """Get password details with interactive selection."""
    vault = get_vault()
    core_get_entry(vault)


@app.command("edit", help=get_help_with_aliases("Edit an existing entry", "edit"))
def edit_entry():
    """Edit an existing entry interactively."""
    vault = get_vault()
    core_edit_entry(vault)


@app.command("delete", help=get_help_with_aliases("Delete an entry", "delete"))
def delete_entry():
    """Delete an entry with confirmation."""
    vault = get_vault()
    core_delete_entry(vault)


@app.command("search", help=get_help_with_aliases("Search entries", "search"))
def search_entries():
    """Search entries interactively."""
    vault = get_vault()
    # Use select_entry which has autocomplete search built-in
    from .ui import select_entry

    entry = select_entry(vault, "Type to search, or select entry")
    if entry:
        from .passwordgen import copy_to_clipboard

        if copy_to_clipboard(entry.password):
            ui.success("Password copied to clipboard")
        from .cli_operations import show_entry_with_quick_actions

        show_entry_with_quick_actions(vault, entry)


@app.command("genpass", help=get_help_with_aliases("Generate a password", "genpass"))
def generate_standalone_password():
    """Generate a password interactively."""
    prompt_and_generate_password()


@app.command("stats", help="Show vault statistics")
def show_stats():
    """Display vault statistics and health check."""
    vault = get_vault()
    display_vault_stats(vault)
    ui.console.print()


@app.command("check", help="Security health check")
def health_check():
    """Run security health check on vault."""
    vault = get_vault()
    display_security_health_check(vault)
    ui.console.print()


@app.command("categories", help="List all categories")
def list_categories():
    """List all categories with entry counts."""
    vault = get_vault()
    core_list_categories(vault)


@app.command("rename-category", help="Rename a category")
def rename_category():
    """Rename a category interactively."""
    vault = get_vault()
    core_rename_category(vault)


@app.command("move-category", help="Move entries between categories")
def move_category():
    """Move entries between categories interactively."""
    vault = get_vault()
    core_move_entries_to_category(vault)


# ============================================================================
# Auto-register command aliases from COMMAND_ALIASES mapping
# ============================================================================

# Map command names to their handler functions for dynamic alias registration
_COMMAND_HANDLERS = {
    "list": list_entries,
    "add": add_entry,
    "get": get_entry,
    "edit": edit_entry,
    "delete": delete_entry,
    "search": search_entries,
    "genpass": generate_standalone_password,
}

# Auto-register all aliases
for command_name, aliases in COMMAND_ALIASES.items():
    handler = _COMMAND_HANDLERS.get(command_name)
    if handler:
        for alias in aliases:
            app.command(alias, help=f"Alias for '{command_name}'", hidden=True)(handler)  # type: ignore[type-var]


def main() -> None:
    """Main entry point."""
    try:
        app()
    except KeyboardInterrupt:
        ui.error("Operation cancelled")
        sys.exit(1)
    except typer.Exit:
        # Let Typer handle its own exit codes
        raise


if __name__ == "__main__":
    main()
