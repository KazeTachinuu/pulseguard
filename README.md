# PulseGuard

A simple password manager with CLI and interactive console.

## Installation

```bash
uv sync
```

## Usage

### Command Line

```bash
pulseguard list                           # List passwords
pulseguard add Gmail user@example.com pwd # Add password
pulseguard get Gmail                      # Get password details
pulseguard edit Gmail                     # Edit password
pulseguard delete Gmail                   # Delete password
pulseguard search gmail                   # Search passwords
pulseguard demo                           # Add sample data
pulseguard                               # Interactive console
```

### Python API

```python
from pulseguard import Vault, PasswordEntry

vault = Vault()
entry = PasswordEntry("Gmail", "user@gmail.com", "password")
vault.add(entry)

# Get all entries
entries = vault.get_all()

# Search
results = vault.search("gmail")
```

## Configuration

Set vault file location:
```bash
export PULSEGUARD_VAULT_PATH="/path/to/vault.json"
```

Default: `~/.pulseguard/vault.json`

## Development

```bash
uv sync

# Install git hooks (auto-format on commit)
./setup-hooks.sh

# Add pytest
uv add pytest

# Run tests
uv run pytest

# Manual formatting
uv run ruff check src tests
uv run black src tests
```

## Project Structure

```
src/pulseguard/
├── cli.py          # CLI interface
├── console.py      # Interactive console
├── config.py       # Configuration
├── models.py       # Data models
├── vault.py        # Vault management
├── operations.py   # CLI operations
└── messages.py     # User messages
```