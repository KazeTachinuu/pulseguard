"""@brief Console entrypoint wiring Textual application launch."""

from __future__ import annotations

from pulseguard.tui.app import run


def main() -> None:
    """Launch the PulseGuard TUI."""

    run()


if __name__ == "__main__":  # pragma: no cover
    main()
