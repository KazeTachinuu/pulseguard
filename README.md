# PulseGuard

A minimalist password manager with TUI interface.

## Project Structure

```
PulseGuard/
├── cmd/pulseguard/          # Main application entry point
├── core/
│   ├── password/            # Password management
│   ├── auth/                # Authentication
│   ├── storage/             # Data storage
│   └── tui/                 # Terminal UI with gocui
├── go.mod
├── Makefile
└── README.md
```

## Development

```bash
# Install dependencies
make deps

# Run tests
make test

# Build application
make build

# Run application
make run
```
