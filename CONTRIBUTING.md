# Contributing

Thanks for taking the time to improve ContextAudit.

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
make test
make quality
```

## Development Guidelines

- Keep runtime dependencies minimal. The current package uses only the Python standard library.
- Add or update tests for every behavior change.
- Prefer deterministic detectors and stable report ordering.
- Keep examples synthetic and do not commit real credentials, customer text, or private notes.
- Document limitations plainly. Do not present heuristic checks as proof of model behavior.

## Pull Request Checklist

- `make test` passes.
- `make quality` passes.
- Public documentation reflects user-facing behavior changes.
- New examples avoid real secrets and private data.
- The change does not add private planning files or local environment artifacts.
