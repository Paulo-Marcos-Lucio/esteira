<p align="center"><a href="CONTRIBUTING.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/esteira/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Contribuindo

Contribuições são bem-vindas — sobretudo **novas checagens**.

## Ambiente

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Antes do PR

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Adicionando uma checagem

1. Declare os metadados em `src/esteira/checks/catalog.py`.
2. Emita o achado a partir de um detector em `src/esteira/checks/detectors.py`
   (por linha, quando precisa de número de linha; estrutural, quando depende da árvore YAML).
3. Adicione o padrão ao workflow vulnerável em `tests/conftest.py` e uma asserção
   em `tests/test_detectors.py` — e confirme que o workflow seguro continua limpo.

## Definição de pronto para correção de defeito

Corrigir o exemplo que apareceu no relatório e chamar de resolvido não fecha
o item: é preciso um teste que falhava contra o código anterior à correção,
mais um invariante — property-based com Hypothesis quando a classe for uma
família de entradas — que impeça a classe inteira de voltar. Critério e
exemplos reais em [`docs/definicao-de-pronto.md` da
Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/definicao-de-pronto.md),
válido para as cinco ferramentas da suíte, não só para ela.
