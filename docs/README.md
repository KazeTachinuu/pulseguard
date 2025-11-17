# PulseGuard

Terminal password manager with encryption and interactive CLI.

[![PyPI version](https://badge.fury.io/py/pulseguard.svg)](https://badge.fury.io/py/pulseguard)
[![Python](https://img.shields.io/pypi/pyversions/pulseguard.svg)](https://pypi.org/project/pulseguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


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
pipx install pulseguard
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

------------------------------------------------------------------------

#### `list` - Lister les mots de passe enregistrés

**Description**

Affiche toutes les entrées enregistrées dans le coffre, avec leur nom et leur identifiant (username).

**Utilisation**

```bash
pulseguard list
```

#### `add` - Ajouter une nouvelle entrée
**Description**

Crée une nouvelle entrée dans le coffre avec un nom, un identifiant (username) et un mot de passe.
Il est possible d’ajouter en option une URL et une note.

**Options**
- `<name>`  
  Nom de l’entrée (identifiant du service).
- `<username>`  
  Identifiant ou email associé à l’entrée.
- `<password>`  
  Mot de passe associé à l’entrée.
- `--url <URL>`  
  URL du service (optionnelle).
- `--notes <texte>`  
  Notes ou informations complémentaires (optionnelles).
---

**Utilisation**

```bash
pulseguard add <name> <username> <password> [--url URL] [--notes NOTES]

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
