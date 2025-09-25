"""Tests for the theme helpers."""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from pulseguard.tui.theme import MONOKAI_THEME, Theme, build_css


def test_build_css_includes_palette_values() -> None:
    css = build_css(MONOKAI_THEME)
    assert MONOKAI_THEME.screen_background in css
    assert MONOKAI_THEME.border_detail in css


def test_custom_theme_overrides_colors() -> None:
    custom_theme = Theme(
        screen_background="#000000",
        body_background="#111111",
        nav_background="#222222",
        detail_background="#333333",
        border_nav="#444444",
        border_detail="#555555",
        text_default="#aaaaaa",
        text_title="#bbbbbb",
        text_summary="#cccccc",
        text_actions="#dddddd",
        text_hint="#eeeeee",
        text_status="#ffffff",
        list_item_highlight="#123456",
    )
    css = build_css(custom_theme)
    assert "#000000" in css
    assert "#123456" in css
