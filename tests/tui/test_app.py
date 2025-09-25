"""Tests for the Textual scaffold."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from textual.widgets import Static

from pulseguard.tui.app import PulseGuardApp
from pulseguard.tui.panels import (
    PanelAction,
    PanelDefinition,
    PanelRegistry,
    build_default_registry,
)


def test_panels_are_defined() -> None:
    registry = build_default_registry()
    identifiers = set(registry.identifiers())
    assert {"overview", "vault", "activity", "settings"}.issubset(identifiers)


@pytest.mark.asyncio
async def test_app_selects_first_panel_on_mount() -> None:
    app = PulseGuardApp()
    async with app.run_test() as pilot:  # type: ignore[call-arg]
        registry = build_default_registry()
        first = registry.get(registry.identifiers()[0])

        assert app.query_one("#detail-title", Static).renderable == first.title
        assert app.query_one("#detail-summary", Static).renderable == first.summary
        assert (
            app.query_one("#detail-description", Static).renderable == first.description
        )

        await pilot.press("down")
        second = registry.get(registry.identifiers()[1])
        assert app.query_one("#detail-title", Static).renderable == second.title


@pytest.mark.asyncio
async def test_trigger_primary_runs_first_action() -> None:
    app = PulseGuardApp()
    async with app.run_test() as pilot:  # type: ignore[call-arg]
        await pilot.press("enter")
        status = app.query_one("#status", Static).renderable
        assert "refreshed" in str(status).lower()


@pytest.mark.asyncio
async def test_trigger_primary_handles_missing_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    panels = [
        PanelDefinition(
            identifier="empty",
            title="Empty",
            summary="No actions wired yet",
            description="Stub panel without behaviour.",
            actions=(),
        ),
        PanelDefinition(
            identifier="action",
            title="Action",
            summary="Has a primary action",
            description="Used to verify the trigger hook.",
            actions=(
                PanelAction(
                    label="Refresh",
                    description="Refresh state",
                    handler="pulseguard.tui.actions.refresh_overview",
                ),
            ),
        ),
    ]

    monkeypatch.setattr(
        "pulseguard.tui.app.build_default_registry",
        lambda: PanelRegistry(panels),
    )

    app = PulseGuardApp()
    async with app.run_test() as pilot:  # type: ignore[call-arg]
        await pilot.press("enter")
        status = str(app.query_one("#status", Static).renderable).lower()
        assert "no actions" in status

        await pilot.press("down")
        await pilot.press("enter")
        status = str(app.query_one("#status", Static).renderable).lower()
        assert "refreshed" in status
