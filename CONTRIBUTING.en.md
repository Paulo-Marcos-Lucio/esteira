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

## Definition of Done for bug fixes

Fixing the example that showed up in the report and calling it resolved does
not close the item: it needs a test that failed against the code before the
fix, plus an invariant — property-based with Hypothesis when the class is a
family of inputs — that keeps the whole class from coming back. Criterion and
real examples in [Sentinela's
`docs/definicao-de-pronto.md`](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/definicao-de-pronto.md)
(Portuguese), which applies to all five tools in the suite, not just it.
