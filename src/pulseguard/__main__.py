"""Module entrypoint to run PulseGuard via `python -m pulseguard`."""

from pulseguard.cli import main


def run() -> None:
    """Dispatch to the console script handler."""

    main()


if __name__ == "__main__":  # pragma: no cover
    run()
