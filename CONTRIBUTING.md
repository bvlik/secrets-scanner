# Contributing

Thanks for your interest!

## Dev setup
```bash
pip install -e .
pip install pytest ruff bandit
```

## Before opening a PR
- `ruff check .` — lint
- `bandit -r src` — security scan
- `pytest -q` — tests

## Adding a detection rule
Add a `Rule` to `src/secretscanner/rules.py` and a test case in `tests/`. Keep regexes precise to
avoid false positives, and prefer adding a placeholder pattern over a noisy match.

## Conventions
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`)
