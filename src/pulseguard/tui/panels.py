"""@brief Panel definitions and registry helpers for the PulseGuard TUI."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class PanelAction:
    """@brief Describe why a panel exposes a specific action."""

    label: str
    description: str
    handler: str


@dataclass(frozen=True)
class PanelDefinition:
    """@brief Capture panel intent so the UI can stay declarative."""

    identifier: str
    title: str
    summary: str
    description: str
    actions: tuple[PanelAction, ...] = ()


class PanelRegistry:
    """@brief Provide lookup helpers so panels evolve without touching the UI."""

    def __init__(self, panels: Sequence[PanelDefinition]) -> None:
        self._panels: Mapping[str, PanelDefinition] = {
            panel.identifier: panel for panel in panels
        }

    def identifiers(self) -> tuple[str, ...]:
        """@brief Preserve author-defined ordering for the navigation list."""

        return tuple(self._panels.keys())

    def get(self, identifier: str) -> PanelDefinition:
        """@brief Fetch panel metadata when the UI needs context."""

        return self._panels[identifier]

    def actions_for(self, identifier: str) -> tuple[PanelAction, ...]:
        """@brief Surface available actions so the view can describe them."""

        return self.get(identifier).actions

    def run_action(self, identifier: str, label: str) -> str:
        """@brief Resolve and execute the handler so behaviour stays modular."""

        panel = self.get(identifier)
        for action in panel.actions:
            if action.label == label:
                handler = _load_callable(action.handler)
                return handler(identifier)
        raise KeyError(f"Unknown action '{label}' for panel '{identifier}'")


def build_default_registry() -> PanelRegistry:
    """@brief Construct the default registry used by the PulseGuard TUI."""

    panels: list[PanelDefinition] = [
        PanelDefinition(
            identifier="overview",
            title="Overview",
            summary="System status and quick actions",
            description=(
                "Stay on top of vault activity at a glance."
                "\n- Pending approvals\n- Recent edits\n- Sync status"
            ),
            actions=(
                PanelAction(
                    label="Refresh",
                    description="Update health indicators and announcements",
                    handler="pulseguard.tui.actions.refresh_overview",
                ),
            ),
        ),
        PanelDefinition(
            identifier="vault",
            title="Vault",
            summary="Browse and manage saved credentials",
            description=(
                "Group entries, search instantly, and organise secrets without "
                "leaving the keyboard."
            ),
            actions=(
                PanelAction(
                    label="Open",
                    description="Launch the vault management workflow",
                    handler="pulseguard.tui.actions.open_vault",
                ),
            ),
        ),
        PanelDefinition(
            identifier="activity",
            title="Activity",
            summary="Audit trail and session details",
            description=(
                "Trace changes, inspect sessions, and export reports to share "
                "with auditors."
            ),
            actions=(
                PanelAction(
                    label="Inspect",
                    description="Review recent events and anomalies",
                    handler="pulseguard.tui.actions.inspect_activity",
                ),
            ),
        ),
        PanelDefinition(
            identifier="settings",
            title="Settings",
            summary="Profile, encryption, and sync configuration",
            description=(
                "Adjust security parameters, rotation cadence, and remote storage "
                "targets."
            ),
            actions=(
                PanelAction(
                    label="Adjust",
                    description="Prepare configuration editor",
                    handler="pulseguard.tui.actions.adjust_settings",
                ),
            ),
        ),
    ]

    return PanelRegistry(panels)


def _load_callable(dotted_path: str) -> Callable[[str], str]:
    """@brief Import and return the callable designated by dotted_path."""

    module_path, _, attr = dotted_path.rpartition(".")
    module = import_module(module_path)
    return getattr(module, attr)
