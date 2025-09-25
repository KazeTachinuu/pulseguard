# PulseGuard Test Suite

The suite is intentionally lean but covers the layers that matter today:

- **Unit (tests/tui/test_actions.py, tests/tui/test_panels.py)** — validate the
  panel registry wiring and action handlers in isolation. These checks confirm
  that panel metadata resolves correctly, unknown identifiers fail fast, and the
  placeholder actions communicate their intent.
- **Widget (tests/tui/test_app.py)** — exercise the Textual scaffold with
  `app.run_test()`. Assertions focus on the detail pane content, status banner
  updates, and behaviour when panels have no actions. The tests run under
  `pytest-asyncio` in auto mode.
- **Functional (tests/integration/test_app_functional.py)** — drive a concise
  navigation flow across the lazygit-style layout. It mirrors expected keyboard
  usage (arrow keys + enter) and verifies the status banner reflects the chosen
  panel’s action.

## Running locally

```bash
uv pip install -e .[dev,test]
uv run pytest
```

`textual` is a required dependency, so the UI and functional tests run instead
of skipping. The GitLab pipeline executes the same command inside a
`python:3.11` container to stay aligned with local expectations.
