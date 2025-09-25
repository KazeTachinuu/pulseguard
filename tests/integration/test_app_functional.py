"""Functional flow tests for the PulseGuard Textual app."""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from textual.widgets import Static

from pulseguard.tui.app import PulseGuardApp
from pulseguard.tui.panels import build_default_registry


@pytest.mark.asyncio
async def test_navigation_and_primary_action() -> None:
    registry = build_default_registry()
    app = PulseGuardApp()

    async with app.run_test() as pilot:  # type: ignore[call-arg]
        first = registry.get(registry.identifiers()[0])
        title = app.query_one("#detail-title", Static).renderable
        status = str(app.query_one("#status", Static).renderable).lower()
        assert title == first.title
        assert "ready" in status

        await pilot.press("down")
        second = registry.get(registry.identifiers()[1])
        assert app.query_one("#detail-title", Static).renderable == second.title

        await pilot.press("enter")
        status = str(app.query_one("#status", Static).renderable).lower()
        assert "vault" in status

        await pilot.press("up")
        await pilot.press("enter")
        status = str(app.query_one("#status", Static).renderable).lower()
        assert "overview" in status
