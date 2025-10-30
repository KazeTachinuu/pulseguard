# PulseGuard

A simple password manager with CLI and interactive console.

## Installation

```bash
uv pip install -e .
```

## Usage

### Command Line

```bash
pulseguard list                           # List passwords
pulseguard add Gmail user@example.com pwd # Add password
pulseguard genpass --length 20 --symbols true --upper true --lower true --digits true # genPass
pulseguard get Gmail                      # Get password details
pulseguard edit Gmail                     # Edit password
pulseguard delete Gmail                   # Delete password
pulseguard search gmail                   # Search passwords
pulseguard demo                           # Add sample data
pulseguard                               # Interactive console
```

#### Add new entry and generate password

When `--gen` is provided, PulseGuard generates the password. All generation flags are optional:
- `--length <int>` (required only if provided, must be a valid integer)
- `--symbols true|false` (default: true)
- `--upper true|false` (default: true)
- `--lower true|false` (default: true)
- `--digits true|false` (default: true)

Examples:
```bash
pulseguard add Gmail user@example.com dummy --gen
pulseguard add Gmail user@example.com dummy --gen --length 18
pulseguard add Gmail user@example.com dummy --gen --length 20 --symbols false --upper true --lower true --digits true


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
uv pip install -e .[dev,test]

# Install git hooks (auto-format on commit)
./setup-hooks.sh

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