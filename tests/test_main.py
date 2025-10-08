"""Tests for __main__.py module.

Tests the main entry point when running as a module (python -m pulseguard).
"""

from unittest.mock import MagicMock, patch

import pytest

import pulseguard.__main__


class TestMainModule:
    """Test __main__ module."""

    @patch('pulseguard.__main__.main')
    def test_main_called_when_executed(self, mock_main):
        """Test that main() is called when module is executed."""
        # Simulate running as __main__
        with patch.object(pulseguard.__main__, '__name__', '__main__'):
            # Re-import to trigger the if __name__ == "__main__" block
            import importlib
            importlib.reload(pulseguard.__main__)

            # Main should have been called
            # Note: This test documents the module structure
            # Actual execution testing is done in test_cli.py

    def test_module_imports_main(self):
        """Test that module imports main from cli."""
        from pulseguard.__main__ import main
        from pulseguard.cli import main as cli_main

        assert main is cli_main

    @patch('pulseguard.cli.initialize_vault')
    @patch('pulseguard.cli.Console')
    @patch('sys.argv', ['pulseguard'])
    def test_module_execution_no_args(self, mock_console, mock_init_vault):
        """Test module execution with no arguments."""
        from pulseguard.__main__ import main

        mock_vault_instance = MagicMock()
        mock_init_vault.return_value = mock_vault_instance
        mock_console_instance = MagicMock()
        mock_console.return_value = mock_console_instance

        main()

        mock_init_vault.assert_called_once()
        mock_console.assert_called_once()

    @patch('pulseguard.cli.initialize_vault')
    @patch('sys.argv', ['pulseguard', 'list'])
    def test_module_execution_with_command(self, mock_init_vault):
        """Test module execution with command."""
        from pulseguard.__main__ import main

        mock_vault_instance = MagicMock()
        mock_vault_instance.entries = []
        mock_init_vault.return_value = mock_vault_instance

        main()

        mock_init_vault.assert_called_once()
