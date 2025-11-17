"""CLI using Typer."""

import os
import sys
from typing import Optional

import typer
from typing_extensions import Annotated

from . import __version__, ui
from .cli_helpers import (
    COMMAND_ALIASES,
    display_security_health_check,
    display_vault_stats,
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
    help="Secure password manager with encryption",
    add_completion=True,
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        typer.echo(f"pulseguard {__version__}")
        raise typer.Exit()


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
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
):
    """Runs interactive mode if no command given."""
    if vault:
        config.vault_path = os.path.expanduser(vault)

    if ctx.invoked_subcommand is None:
        interactive_mode()
        raise typer.Exit(0)


@app.command(
    "list",
    help="List all password entries (ls)",
    rich_help_panel="Entry Management",
)
def list_entries(
    category: Annotated[
        Optional[str],
        typer.Option("--category", "-c", help="Filter by category"),
    ] = None,
):
    """List all password entries, optionally filtered by category."""
    vault = get_vault()
    if category:
        entries = vault.get_by_category(category)
        if not entries:
            ui.warning(f"No entries found in category '{category}'")
            return
        ui.show_entries_table(entries, title=f"Entries in '{category}'")
    else:
        core_list_entries(vault)


@app.command(
    "add",
    help="Add a new password entry (a)",
    rich_help_panel="Entry Management",
)
def add_entry():
    """Add a new password entry."""
    vault = get_vault()
    core_add_entry(vault)


@app.command(
    "get",
    help="Get password details (g)",
    rich_help_panel="Entry Management",
)
def get_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    show_password: Annotated[
        bool, typer.Option("--show-password", "-p", help="Show password in output")
    ] = False,
):
    """Get password details. If name is provided, retrieves that entry directly."""
    vault = get_vault()

    if name:
        # Direct retrieval by name
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            raise typer.Exit(1)

        ui.copy_password_with_feedback(entry.password)
        ui.show_entry_panel(entry, show_password=show_password)
    else:
        # Interactive selection
        core_get_entry(vault)


@app.command(
    "edit",
    help="Edit an existing entry (e)",
    rich_help_panel="Entry Management",
)
def edit_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
):
    """Edit an existing entry. If name is provided, edits that entry directly."""
    from .cli_operations import edit_existing_entry

    vault = get_vault()

    if name:
        # Direct edit by name
        entry = vault.get(name, track_access=False)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            raise typer.Exit(1)

        edit_existing_entry(vault, entry)
    else:
        # Interactive selection
        core_edit_entry(vault)


@app.command(
    "delete",
    help="Delete an entry (d, del)",
    rich_help_panel="Entry Management",
)
def delete_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt")
    ] = False,
):
    """Delete an entry with confirmation. If name is provided, deletes that entry directly."""
    vault = get_vault()

    if name:
        # Direct deletion by name
        entry = vault.get(name, track_access=False)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            raise typer.Exit(1)

        if not force and not ui.confirm(f"Delete '{name}'?", default=False):
            ui.info("Cancelled")
            return

        vault.remove(name)
        ui.success(f"Deleted entry '{name}'")
    else:
        # Interactive selection
        core_delete_entry(vault)


@app.command(
    "search",
    help="Search entries (s)",
    rich_help_panel="Entry Management",
)
def search_entries():
    """Search entries."""
    vault = get_vault()
    from .cli_operations import select_and_show_entry

    select_and_show_entry(vault, "Type to search, or select entry")


@app.command(
    "genpass",
    help="Generate a password (gen)",
    rich_help_panel="Utilities",
)
def generate_standalone_password(
    length: Annotated[
        Optional[int],
        typer.Option("--length", "-l", help="Password length (default: 16)"),
    ] = None,
):
    """Generate a password. Optionally specify length via --length."""
    # Validate length if provided
    if length is not None and (length < 4 or length > 128):
        ui.error("Password length must be between 4 and 128 characters")
        raise typer.Exit(1)

    # If no length specified, use interactive mode
    if length is None:
        prompt_and_generate_password()
        return

    # Non-interactive mode with length only
    from .passwordgen import (
        GenOptions,
        copy_to_clipboard_with_autoclear,
        generate_password,
    )

    # Use secure defaults: lowercase, uppercase, digits (no symbols by default)
    opts = GenOptions(length=length, lower=True, upper=True, digits=True, symbols=False)
    password = generate_password(opts)
    copied = copy_to_clipboard_with_autoclear(password)
    ui.show_password_generated(password, copied)


@app.command("stats", help="Show vault statistics", rich_help_panel="Utilities")
def show_stats():
    """Display vault statistics and health check."""
    vault = get_vault()
    display_vault_stats(vault)
    ui.console.print()


@app.command("check", help="Security health check", rich_help_panel="Utilities")
def health_check():
    """Run security health check on vault."""
    vault = get_vault()
    display_security_health_check(vault)
    ui.console.print()


@app.command(
    "categories", help="List all categories", rich_help_panel="Category Management"
)
def list_categories():
    """List all categories with entry counts."""
    vault = get_vault()
    core_list_categories(vault)


@app.command(
    "rename-category",
    help="Rename a category",
    rich_help_panel="Category Management",
)
def rename_category():
    """Rename a category."""
    vault = get_vault()
    core_rename_category(vault)


@app.command(
    "move-category",
    help="Move entries between categories",
    rich_help_panel="Category Management",
)
def move_category():
    """Move entries between categories."""
    vault = get_vault()
    core_move_entries_to_category(vault)


@app.command("export", help="Export vault to a file", rich_help_panel="Vault Backup")
def export_vault(
    output: Annotated[str, typer.Argument(help="Output file path")],
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing file")
    ] = False,
):
    """Export encrypted vault to a backup file."""
    import shutil
    from pathlib import Path

    vault = get_vault()
    output_path = Path(output).expanduser()

    # Check if output file exists
    if output_path.exists() and not force:
        ui.error(f"File '{output}' already exists. Use --force to overwrite.")
        raise typer.Exit(1)

    try:
        # Copy vault file to output
        shutil.copy2(vault.file_path, output_path)
        ui.success(f"Vault exported to '{output}' ({vault.count()} entries)")
    except Exception as e:
        ui.error(f"Export failed: {e}")
        raise typer.Exit(1)


@app.command("import", help="Import vault from a file", rich_help_panel="Vault Backup")
def import_vault(
    input_file: Annotated[str, typer.Argument(help="Input file path")],
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing vault")
    ] = False,
):
    """Import encrypted vault from a backup file."""
    import shutil
    from pathlib import Path

    input_path = Path(input_file).expanduser()

    if not input_path.exists():
        ui.error(f"File '{input_file}' not found")
        raise typer.Exit(1)

    vault_path = Path(config.vault_path)

    # Check if vault exists
    if vault_path.exists() and not force:
        ui.error(
            f"Vault already exists at '{config.vault_path}'. Use --force to overwrite."
        )
        raise typer.Exit(1)

    try:
        # Ensure vault directory exists
        config.ensure_vault_dir()

        # Copy input file to vault location
        shutil.copy2(input_path, vault_path)
        ui.success(f"Vault imported from '{input_file}'")
    except Exception as e:
        ui.error(f"Import failed: {e}")
        raise typer.Exit(1)


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
