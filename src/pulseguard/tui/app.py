"""@brief Textual application wiring for the modular PulseGuard TUI."""

from __future__ import annotations

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, ListItem, ListView, Static

from pulseguard.tui.panels import PanelAction, PanelRegistry, build_default_registry
from pulseguard.tui.theme import MONOKAI_THEME, build_css


class PulseGuardApp(App[None]):
    """@brief Lazygit-inspired split view backed by a panel registry."""

    CSS = build_css(MONOKAI_THEME)

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
        ("enter", "trigger_primary", "Run primary action"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._panel_registry: PanelRegistry = build_default_registry()
        self._active_panel: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="body"):
            with Vertical(id="nav-pane"):
                yield Static("Panels", classes="panel-title")
                yield ListView(
                    *[
                        ListItem(
                            Static(self._panel_registry.get(identifier).title),
                            id=identifier,
                        )
                        for identifier in self._panel_registry.identifiers()
                    ],
                    id="panel-list",
                )
            with Vertical(id="detail-pane"):
                yield Static("", id="detail-title", classes="panel-title")
                yield Static("", id="detail-summary", classes="panel-summary")
                yield Static("", id="detail-description")
                yield Static("", id="detail-actions", classes="actions")
                yield Static(
                    "Use ↑/↓ to navigate. Press Enter to trigger the primary action.",
                    id="detail-hint",
                    classes="hint",
                )
                yield Static("", id="status", classes="status")
        yield Footer()

    def on_mount(self) -> None:
        """@brief Seed the initial selection so navigation reads context instantly."""

        list_view = self.query_one("#panel-list", ListView)
        if not list_view.children:
            return
        list_view.index = 0
        first_identifier = self._panel_registry.identifiers()[0]
        self._select_panel(first_identifier)
        self.set_focus(list_view)

    @on(ListView.Highlighted, "#panel-list")
    def handle_panel_highlight(self, event: ListView.Highlighted) -> None:
        """@brief Sync the detail pane whenever the user moves in the list."""

        item = event.item
        if item is None or item.id is None:
            return
        self._select_panel(item.id)

    def action_trigger_primary(self) -> None:
        """@brief Invoke the primary action for the selected panel if available."""

        if self._active_panel is None:
            self._set_status("Select a panel to trigger actions.")
            return

        actions = self._panel_registry.actions_for(self._active_panel)
        if not actions:
            self._set_status("No actions available for this panel.")
            return

        result = self._panel_registry.run_action(self._active_panel, actions[0].label)
        self._set_status(result)

    def _select_panel(self, identifier: str) -> None:
        """@brief Update detail content so it reflects the newly active panel."""

        if identifier == self._active_panel:
            return

        panel = self._panel_registry.get(identifier)
        self._active_panel = identifier

        self.query_one("#detail-title", Static).update(panel.title)
        self.query_one("#detail-summary", Static).update(panel.summary)
        self.query_one("#detail-description", Static).update(panel.description)
        self.query_one("#detail-actions", Static).update(
            self._format_actions(panel.actions)
        )
        self._set_status("Ready.")

    def _set_status(self, message: str) -> None:
        """@brief Centralised status updates keep future messaging consistent."""

        self.query_one("#status", Static).update(message)

    @staticmethod
    def _format_actions(actions: tuple[PanelAction, ...]) -> str:
        """@brief Render action summaries so authors see how panels behave."""

        if not actions:
            return "Actions: none yet."
        lines = ["Actions:"]
        for action in actions:
            lines.append(f"- {action.label}: {action.description}")
        return "\n".join(lines)

    def action_quit(self) -> None:
        self.exit()


def run() -> None:
    """@brief Launch the Textual application."""

    PulseGuardApp().run()
