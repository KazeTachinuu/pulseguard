# PulseGuard

Terminal password manager with encryption and interactive CLI.

## Features

- AES-128 (Fernet) + Argon2id key derivation
- Password generation with `secrets` module
- Categories, tags, favorites
- Duplicate and reused password detection
- Cross-platform clipboard support
- Access tracking

## Installation

```bash
uv sync
```

## Usage

```bash
pulseguard          # Interactive mode
pulseguard list     # List entries
pulseguard add      # Add entry
pulseguard get      # Get entry
pulseguard search   # Search entries
pulseguard genpass  # Generate password
pulseguard stats    # Vault stats
pulseguard check    # Security check
```

## Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `list` | `ls` | List entries |
| `add` | `a` | Add entry |
| `get` | `g` | Get entry |
| `edit` | `e` | Edit entry |
| `delete` | `d`, `del` | Delete entry |
| `search` | `s` | Search entries |
| `genpass` | `gen` | Generate password |
| `stats` | | Vault statistics |
| `check` | | Security check |
| `categories` | | List categories |
| `rename-category` | | Rename category |
| `move-category` | | Move entries |

## Configuration

```bash
export PULSEGUARD_VAULT_PATH="/path/to/vault.json"
```

Default: `~/.pulseguard/vault.json`

## Security

- Argon2id: 2 iterations, 64 MiB memory, 4 parallelism
- File permissions: 0600
- Master password always required
- AES-128 (Fernet) encryption for all vault data

## Python API

```python
from pulseguard import Vault, PasswordEntry

# Create encrypted vault (master password required)
vault = Vault(master_password="your-master-password")
entry = PasswordEntry("name", "user", "pass")
vault.add(entry)

# Search and retrieve
results = vault.search("query")
entries = vault.get_all()
```

**Note**: All vaults are encrypted with AES-128 (Fernet) + Argon2id. Master password is required for all operations.

## Development

```bash
uv sync
./setup-hooks.sh    # Git hooks for auto-format
uv run pytest       # Tests
uv run ruff check src tests
uv run black src tests
uv run mypy src
```

## Structure

```
src/pulseguard/
├── cli.py              # Typer CLI
├── cli_helpers.py      # Interactive mode
├── cli_operations.py   # Command logic
├── config.py           # Config
├── crypto.py           # Argon2id + Fernet
├── models.py           # PasswordEntry
├── passwordgen.py      # Password generation
├── ui.py               # Rich UI
└── vault.py            # Storage
```

## Dependencies

- Python >=3.11
- cryptography, argon2-cffi
- typer, rich, questionary, inquirer
- pyperclip
