# PulseGuard

Terminal password manager with encryption and interactive CLI.

[![PyPI version](https://badge.fury.io/py/pulseguard.svg)](https://badge.fury.io/py/pulseguard)
[![Python](https://img.shields.io/pypi/pyversions/pulseguard.svg)](https://pypi.org/project/pulseguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


## Docs

Docs available at [./docs/]

## Features

- Argon2 key derivation with AES-256 encryption
- Interactive terminal UI with search
- Password generator
- Categories, tags, and favorites
- Security audit (duplicates, reuse detection)
- Clipboard support
- CLI and Python API

## Installation

```bash
pip install pulseguard
```

Or from source:

```bash
git clone https://github.com/KazeTachinuu/pulseguard.git
cd pulseguard
uv sync
```

## Usage

### Interactive Mode

```bash
pulseguard
```

### Command Line

```bash
pulseguard list                  # List passwords
pulseguard add                   # Add password
pulseguard get                   # Get password
pulseguard edit                  # Edit password
pulseguard delete                # Delete password
pulseguard search                # Search passwords
pulseguard genpass               # Generate password
pulseguard stats                 # Vault statistics
pulseguard check                 # Security health check
pulseguard --version             # Show version
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

```bash
export PULSEGUARD_VAULT_PATH="/path/to/vault.json"
```

Default: `~/.pulseguard/vault.json`

## Security

- Argon2id: 2 iterations, 64 MiB memory, 4 parallelism
- File permissions: 0600
- Master password always required
- AES-128 (Fernet) encryption for all vault data

## Development

```bash
uv sync                          # Install dependencies
./setup-hooks.sh                 # Install git hooks
uv run pytest                    # Run tests
uv run ruff check src tests      # Lint
uv run black src tests           # Format
```

## License

MIT
