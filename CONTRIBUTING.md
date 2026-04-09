# Contributing

## Setup

```bash
git clone https://github.com/matt-szymczyk/kube2docs.git
cd kube2docs
uv pip install -e ".[dev]"
```

## Running tests

```bash
uv run pytest
```

## Linting and formatting

```bash
uv run ruff check src/
uv run ruff format src/
```

## Type checking

```bash
uv run mypy src/kube2docs/
```

## Code style

- Python 3.12+ syntax (`list[str]`, `X | None` unions, etc.)
- 120 character line length
- Ruff rules: E, F, I, N, W, UP, B, SIM
- Pydantic `BaseModel` for data schemas
- Every module uses `logger = logging.getLogger(__name__)`

## Submitting changes

1. Fork the repo and create a feature branch.
2. Make sure tests, linting, and type checking all pass before pushing.
3. Open a pull request against `main`.
