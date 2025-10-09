# tests/test_auth.py
import builtins
import pytest
from unittest.mock import patch
from pulseguard.auth import get_master_password, prompt_create_master_password, prompt_unlock_vault

@patch("getpass.getpass", side_effect=["Secret!"])
def test_get_master_password_basic(mock_gp):
    assert get_master_password() == "Secret!"

@patch("getpass.getpass", side_effect=["Pass1", "Pass1"])
def test_prompt_create_master_password_ok(mock_gp):
    assert prompt_create_master_password() == "Pass1"

@patch("getpass.getpass", side_effect=["Pass1", "Other"])
def test_prompt_create_master_password_mismatch(mock_gp):
    with pytest.raises(ValueError):
        prompt_create_master_password()

@patch("getpass.getpass", side_effect=KeyboardInterrupt)
def test_get_master_password_cancelled(mock_gp, capsys):
    with pytest.raises(KeyboardInterrupt):
        get_master_password()
    # message d’annulation bien imprimé
    assert "Password prompt cancelled" in capsys.readouterr().err

@patch("getpass.getpass", return_value="OpenSesame")
def test_prompt_unlock_vault(mock_gp):
    assert prompt_unlock_vault() == "OpenSesame"
