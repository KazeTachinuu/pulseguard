"""Basic smoke tests for the PulseGuard scaffold."""

import importlib


def test_package_imports() -> None:
    pkg = importlib.import_module("pulseguard")
    assert pkg.__version__ == "0.1.0"
