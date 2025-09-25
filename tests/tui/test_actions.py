"""Tests for PulseGuard action handlers."""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from pulseguard.tui import actions


@pytest.mark.parametrize(
    ("func", "expected"),
    [
        (actions.refresh_overview, "refreshed"),
        (actions.open_vault, "vault"),
        (actions.inspect_activity, "activity"),
        (actions.adjust_settings, "settings"),
    ],
)
def test_action_handlers_return_intent(func, expected: str) -> None:
    message = func("panel")
    assert expected.lower() in message.lower()
    assert message.endswith(".")
