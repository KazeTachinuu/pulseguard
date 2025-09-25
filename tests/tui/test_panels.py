"""Tests for the panel registry infrastructure."""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from pulseguard.tui.panels import PanelRegistry, build_default_registry


def test_registry_returns_known_identifiers() -> None:
    registry = build_default_registry()
    ids = registry.identifiers()
    assert ids[0] == "overview"
    assert "settings" in ids


def test_run_action_executes_handler() -> None:
    registry = build_default_registry()
    message = registry.run_action("overview", "Refresh")
    assert "Overview" in message


def test_run_action_unknown_panel_raises() -> None:
    registry = build_default_registry()
    with pytest.raises(KeyError):
        registry.run_action("unknown", "Refresh")


def test_run_action_unknown_label_raises() -> None:
    registry = build_default_registry()
    with pytest.raises(KeyError):
        registry.run_action("overview", "DoesNotExist")
