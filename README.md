# PulseGuard

A simple password vault manager for storing and managing password entries.

## Features

- **Password Storage**: Store passwords with usernames, URLs, and notes
- **Simple API**: Easy-to-use vault management
- **CLI Demo**: Command-line interface with sample data

## Installation

```bash
# Install with uv
uv pip install -e .

# Or with pip
pip install -e .
```

## Usage

### Command Line

```bash
# Show help
pulseguard --help

# List all passwords
pulseguard list

# Add a new password
pulseguard add "Gmail" "user@example.com" "password123" --url "https://gmail.com" --notes "Personal email"

# Get password details
pulseguard get "Gmail"

# Edit password (interactive)
pulseguard edit "Gmail"

# Delete password
pulseguard delete "Gmail"

# Search passwords
pulseguard search "gmail"

# Run demo with sample data
pulseguard demo
```

### Python API

```python
from pulseguard import Vault, PasswordEntry

# Create a vault
vault = Vault()

# Add a password entry
entry = PasswordEntry(
    name="Gmail",
    username="user@gmail.com",
    password="mypassword",
    url="https://gmail.com",
    notes="Personal email"
)
vault.add(entry)

# Get all entries
entries = vault.get_all()

# Get specific entry
gmail = vault.get("Gmail")

# Remove entry
vault.remove("Gmail")

# Search entries
results = vault.search("gmail")

# Count entries
count = vault.count()
```

## Development

```bash
# Install development dependencies
uv pip install -e .[dev,test]

# Run tests
uv run pytest

# Format code
uv run black src tests

# Lint code
uv run ruff check src tests
```

## Project Structure

```
src/pulseguard/
├── __init__.py          # Main exports
├── cli.py              # CLI interface
├── core/
│   ├── password_entry.py  # PasswordEntry dataclass
│   └── vault.py          # Vault management
└── config/
    └── settings.py       # Configuration
```

## License

MIT