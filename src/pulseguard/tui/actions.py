"""@brief Action handlers for the PulseGuard TUI panels."""

from __future__ import annotations


def refresh_overview(panel_id: str) -> str:
    """@brief Keep the overview panel reactive without wiring real services yet."""

    return "Overview refreshed: metrics are up to date."


def open_vault(panel_id: str) -> str:
    """@brief Reserve a hook where the vault workflow will plug in."""

    return "Vault panel ready: hook in credential browsing next."


def inspect_activity(panel_id: str) -> str:
    """@brief Keep room for an audit log viewer without implementing it yet."""

    return "Activity audit opened: attach log viewer implementation."


def adjust_settings(panel_id: str) -> str:
    """@brief Stand in for the eventual configuration editor launch."""

    return "Settings dialog planned: wire to configuration editor."
