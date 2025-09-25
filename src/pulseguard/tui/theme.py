"""@brief Theme definitions and helpers for the PulseGuard TUI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Theme:
    """@brief Capture palette values so styling stays centralized."""

    screen_background: str
    body_background: str
    nav_background: str
    detail_background: str
    border_nav: str
    border_detail: str
    text_default: str
    text_title: str
    text_summary: str
    text_actions: str
    text_hint: str
    text_status: str
    list_item_highlight: str


MONOKAI_THEME = Theme(
    screen_background="#272822",
    body_background="#1e1f1c",
    nav_background="#3e3d32",
    detail_background="#2d2e27",
    border_nav="#66d9ef",
    border_detail="#a6e22e",
    text_default="#f8f8f2",
    text_title="#a6e22e",
    text_summary="#fd971f",
    text_actions="#66d9ef",
    text_hint="#75715e",
    text_status="#a6e22e",
    list_item_highlight="#49483e",
)


def build_css(theme: Theme) -> str:
    """@brief Generate a Textual CSS string from the provided theme."""

    return f"""
    Screen {{
        layout: vertical;
        background: {theme.screen_background};
        color: {theme.text_default};
    }}

    #body {{
        height: 1fr;
        padding: 1 2;
        background: {theme.body_background};
    }}

    #nav-pane, #detail-pane {{
        padding: 1 2;
    }}

    #nav-pane {{
        width: 32;
        min-width: 28;
        max-width: 38;
        margin-right: 1;
        background: {theme.nav_background};
        border: round {theme.border_nav};
    }}

    #panel-list {{
        height: 1fr;
        background: transparent;
    }}

    #detail-pane {{
        width: 1fr;
        background: {theme.detail_background};
        border: round {theme.border_detail};
    }}

    .panel-title {{
        text-style: bold;
        margin-bottom: 1;
        color: {theme.text_title};
    }}

    .panel-summary {{
        color: {theme.text_summary};
        margin-bottom: 1;
    }}

    .actions {{
        color: {theme.text_actions};
        margin-top: 1;
    }}

    .hint {{
        color: {theme.text_hint};
        margin-top: 1;
    }}

    .status {{
        color: {theme.text_status};
        margin-top: 1;
    }}

    ListView > ListItem {{
        color: {theme.text_default};
    }}

    ListView > ListItem.--highlight {{
        background: {theme.list_item_highlight};
    }}
    """
