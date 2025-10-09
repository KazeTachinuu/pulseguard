#!/bin/bash
# Setup script to install git hooks from the repository

HOOKS_DIR=".githooks"
GIT_HOOKS_DIR=".git/hooks"

if [ ! -d "$GIT_HOOKS_DIR" ]; then
    echo "Error: Not in a git repository"
    exit 1
fi

echo "Installing git hooks..."

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    cp "$HOOKS_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    echo "✓ Installed pre-commit hook"
else
    echo "⚠ Warning: pre-commit hook not found in $HOOKS_DIR"
fi

echo ""
echo "Git hooks installed successfully!"
echo "Hooks will now run automatically before commits."
echo ""
echo "To bypass hooks temporarily, use: git commit --no-verify"
