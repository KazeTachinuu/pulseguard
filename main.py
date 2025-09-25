"""@brief Wrapper so `python main.py` mirrors the console entrypoint."""

from __future__ import annotations

from pulseguard.cli import main


if __name__ == "__main__":  # pragma: no cover
    main()
