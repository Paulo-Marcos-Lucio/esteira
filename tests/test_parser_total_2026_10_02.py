"""Invariante do E13: o parser (`core.loader.load`) é TOTAL sobre qualquer JSON de entrada.

JSON é um subconjunto de YAML — todo documento JSON válido é um documento YAML válido. Um
workflow do GitHub é sempre um MAPEAMENTO no topo; a classe que `load()` precisa travar é:
nenhum JSON arbitrário pode escapar sem classificação. Antes do fix de 2026-07-30
(`tests/test_robustez_2026_07_30.py`), um topo não-mapa caía no fallback por linha SEM sinal —
"0 achados, exit 0" num documento estruturalmente inválido (fail-open). Esses testes existentes
cobrem exemplos manuais (uma lista, um escalar). Esta suíte generaliza para a CLASSE inteira via
Hypothesis: para QUALQUER valor JSON, `load()` nunca levanta exceção e classifica de forma
determinística em exatamente um de três baldes:

  1. objeto JSON (dict) no topo  → parseia como workflow: `data` é o dict, sem `parse_error`;
  2. `null` no topo              → documento vazio legítimo (mesma classe de um arquivo em
                                    branco): sem `data` e sem `parse_error` — não é "inválido",
                                    é "nada a dizer" (ver `test_empty_and_comment_only_files_
                                    stay_clean` em test_robustez_2026_07_30.py);
  3. qualquer outro JSON no topo (lista, string, número, booleano) → "não auditável":
                                    `parse_error` preenchido, `data` é `None`.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from esteira.core.loader import load

# Restrito ao plano básico multilíngue (exclui substitutos e caracteres além de U+FFFF): JSON
# escapa um caractere fora do BMP como par substituto (duas unidades \u), convenção que o
# escape \u do YAML não recombina de volta num só código — ida e volta perderia fidelidade por
# uma diferença de ESCAPE entre formatos, não por falha do parser que este teste verifica.
_TEXTO = st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0xD7FF), max_size=15)
_CHAVE = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0xD7FF), min_size=1, max_size=10
)

_ESCALAR = st.one_of(
    st.booleans(),
    st.integers(min_value=-(10**12), max_value=10**12),
    _TEXTO,
)
_JSON = st.recursive(
    _ESCALAR | st.none(),
    lambda filhos: st.one_of(
        st.lists(filhos, max_size=4),
        st.dictionaries(_CHAVE, filhos, max_size=4),
    ),
    max_leaves=15,
)

# Topo que NÃO é mapeamento nem `null`: lista (mesmo vazia — `isinstance([], dict)` é falso) ou
# escalar. É a classe que o critério de aceite chama de "não auditável".
_TOPO_NAO_MAPA = st.one_of(_ESCALAR, st.lists(_JSON, max_size=4))

_TOPO_MAPA = st.dictionaries(_CHAVE, _JSON, max_size=4)


def _carregar(valor: Any) -> Any:
    texto = json.dumps(valor)
    with tempfile.TemporaryDirectory() as tmp:
        caminho = Path(tmp) / "w.yml"
        caminho.write_text(texto, encoding="utf-8")
        return load(caminho)


@settings(max_examples=200, deadline=None)
@given(valor=_TOPO_MAPA)
def test_objeto_json_no_topo_parseia_como_workflow(valor: dict[str, Any]) -> None:
    wf = _carregar(valor)
    assert wf.parse_error is None, f"objeto JSON válido marcado inválido: {wf.parse_error!r}"
    assert wf.data == valor


@settings(max_examples=200, deadline=None)
@given(valor=_TOPO_NAO_MAPA)
def test_topo_nao_mapa_e_sempre_nao_auditavel(valor: Any) -> None:
    """INVARIANTE da classe: NENHUM JSON cujo topo não seja um objeto escapa sem sinal."""
    wf = _carregar(valor)
    assert wf.parse_error is not None, (
        f"JSON de topo não-mapa ({valor!r}) passou sem parse_error — "
        "voltaria a ser o fail-open de 2026-07-30"
    )
    assert wf.data is None


def test_null_no_topo_e_documento_vazio_legitimo_nao_invalido() -> None:
    """`null` é tratado como arquivo vazio (classe já coberta em test_robustez_2026_07_30.py),
    não como 'não auditável' — é o único JSON sem objeto que o parser aceita em silêncio."""
    wf = _carregar(None)
    assert wf.parse_error is None
    assert wf.data is None


def test_parser_nunca_levanta_para_nenhum_json() -> None:
    # Smoke test determinístico (fora do Hypothesis) com os quatro tipos de topo que JSON
    # permite, só para documentar os baldes num teste que não depende de busca aleatória.
    for exemplo in (True, 42, "texto", [1, 2], {"on": "push"}, None, [], {}):
        _carregar(exemplo)  # não pode levantar
