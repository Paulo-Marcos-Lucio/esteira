<p align="center"><a href="CONTRIBUTING.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/esteira/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Contributing

Contributions are welcome — especially **new checks**.

## Environment

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before the PR

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adding a Check

1. Declare the metadata in `src/esteira/checks/catalog.py`.
2. Emit the finding from a detector in `src/esteira/checks/detectors.py`
   (line-based, when a line number is needed; structural, when it depends on the YAML tree).
3. Add the pattern to the vulnerable workflow in `tests/conftest.py` and an assertion
   in `tests/test_detectors.py` — and confirm that the safe workflow remains clean.
