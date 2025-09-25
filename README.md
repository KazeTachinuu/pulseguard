# PulseGuard

PulseGuard is a clean-room starter for a Textual-based password manager. The
current build intentionally mirrors the official Textual quickstart so future
features begin from a predictable, minimal baseline.

## Getting Started

```bash
uv venv
source .venv/bin/activate
uv pip install -e .[dev,test]
```

## Daily Commands

```bash
uv run pulseguard   # launch the placeholder TUI
uv run pytest       # run tests
uv run black src tests
uv run ruff check src tests
```

## Project Map
- Runtime code: `src/pulseguard/`
- Tests: `tests/`
- Working agreements: `AGENTS.md`
- Architectural notes: `CONTEXT.md`

Add new modules only when behaviour demands it. Keep abstractions small, and
capture any security-impacting decision in `CONTEXT.md`.

## TUI Layout
The placeholder Textual app mirrors lazygit's split view: a compact navigation
list on the left and a detail pane on the right. Use it as a guide when adding
real panels—keep copy short and interactions keyboard-first.

### Extensibility
- Panel metadata lives in `pulseguard.tui.panels`; update the registry to add
  new views or actions.
- Action implementations sit in `pulseguard.tui.actions` so business logic stays
  decoupled from rendering.
- The app (`pulseguard.tui.app`) only coordinates layout and delegates work to
  the registry—follow this pattern to avoid UI bloat.
- Styling is generated from `pulseguard.tui.theme`; tweak `MONOKAI_THEME` or add
  a new theme instance to reskin the UI in one place.

### CI/CD
- GitLab pipelines use `python:3.11`, install `uv`, and run `uv run pytest --junitxml=junit.xml`.
- Keep tests fast, deterministic, and focused; match the pipeline locally before opening a merge request.
