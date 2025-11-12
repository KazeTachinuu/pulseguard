"""User messages and help text for PulseGuard."""

# Success messages
SUCCESS_ADDED = "Added entry '{name}' successfully."
SUCCESS_DELETED = "Deleted entry '{name}' successfully."
SUCCESS_UPDATED = "Updated entry '{name}' successfully."

# Error messages
ERROR_NOT_FOUND = "Entry '{name}' not found."
ERROR_USAGE_ADD = "Usage: add <name> <username> <password> [--url URL] [--notes NOTES]"
ERROR_USAGE_GET = "Usage: get <name>"
ERROR_USAGE_DELETE = "Usage: delete <name>"
ERROR_USAGE_SEARCH = "Usage: search <query>"
ERROR_USAGE_EDIT = "Usage: edit <name>"
ERROR_UNKNOWN_COMMAND = "Unknown command: {command}"
ERROR_OPERATION_CANCELLED = "Operation cancelled."
ERROR_GENERIC = "Error: {error}"
ERROR_MUTUALLY_EXCLUSIVE_GEN = (
    "Cannot use --gen together with a manual password."
    "Provide either a password or --gen."
)


# Info messages
INFO_NO_ENTRIES = "No entries found."
INFO_FOUND_COUNT = "Found {count} entry(ies):"
INFO_FOUND_MATCHING = "Found {count} entry(ies) matching '{query}':"
INFO_NO_MATCHES = "No entries found matching '{query}'."
INFO_GOODBYE = "Goodbye!"
INFO_HELP = "Run 'pulseguard --help' for usage information."

# Console messages
CONSOLE_INTRO = "PulseGuard Console. Type 'help' for commands or 'quit' to exit."
CONSOLE_PROMPT = "pulseguard> "

# Help text will be generated dynamically

# Demo data
DEMO_ENTRIES = [
    {
        "name": "Gmail",
        "username": "user@gmail.com",
        "password": "demo_password_123",
        "url": "https://gmail.com",
        "notes": "Personal email account",
    },
    {
        "name": "GitHub",
        "username": "developer",
        "password": "github_token_456",
        "url": "https://github.com",
        "notes": "Development account",
    },
    {
        "name": "Bank",
        "username": "user123",
        "password": "secure_bank_pass",
        "url": "https://mybank.com",
        "notes": "Online banking",
    },
]
