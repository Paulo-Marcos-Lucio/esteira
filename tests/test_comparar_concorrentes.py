"""ES-BENCHb — testa a lógica de comparação, não os binários dos concorrentes.

`bench/comparar_concorrentes.py` shella para fora para zizmor/actionlint/octoscan/poutine,
que não estão instalados no runner de CI (instalar 4 toolchains extras para 4 ferramentas de
terceiro é decisão de infra, fora do escopo deste item). O que fica sob teste é o que não
depende desses binários: os parsers (dado o JSON bruto que cada ferramenta de fato produz,
capturado numa corrida real contra `bench/`, o parser extrai os achados certos) e a lógica de
casamento arquivo+linha+regra contra `manifest.json` + `equivalencias.json` — é aí que um bug
de adjudicação (como o que este item corrigiu: a coluna de falso-positivo da própria Esteira
saindo invertida) se esconderia em silêncio.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

BENCH = Path(__file__).resolve().parent.parent / "bench"


def _modulo() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "bench_comparar", BENCH / "comparar_concorrentes.py"
    )
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="module")
def mod() -> ModuleType:
    return _modulo()


# ---- fixtures de saída bruta real, capturadas rodando cada ferramenta contra bench/ --------

ZIZMOR_JSON = """ INFO zizmor: completed
[
  {
    "ident": "template-injection",
    "locations": [
      {
        "symbolic": {"key": {"Local": {"verbatim_path": "bench/positivos/script-injection.yml"}}},
        "concrete": {"location": {"start_point": {"row": 9, "column": 8}}}
      }
    ]
  }
]"""

ACTIONLINT_JSON = (
    '[{"filepath":"bench/positivos/script-injection.yml","line":10,'
    '"column":31,"kind":"expression","message":"..."}]'
)

OCTOSCAN_JSON = (
    '[{"filepath":".github/workflows/script-injection.yml","line":10,'
    '"column":31,"kind":"expression-injection","message":"..."}]'
)

POUTINE_JSON = json.dumps(
    {
        "findings": [
            {
                "rule_id": "injection",
                "meta": {"path": ".github/workflows/script-injection.yml", "line": 10},
            },
            {
                # achado sem linha (ex.: nível de repositório) — não deve derrubar o parser
                "rule_id": "known_vulnerability_in_build_platform",
                "meta": {},
            },
        ]
    }
)


def test_parse_zizmor_extrai_arquivo_linha_e_regra(mod: ModuleType) -> None:
    achados = mod.parse_zizmor(ZIZMOR_JSON)
    assert achados == [("script-injection.yml", 10, "template-injection")]


def test_parse_actionlint(mod: ModuleType) -> None:
    assert mod.parse_actionlint(ACTIONLINT_JSON) == [("script-injection.yml", 10, "expression")]


def test_parse_actionlint_saida_vazia(mod: ModuleType) -> None:
    assert mod.parse_actionlint("") == []


def test_parse_octoscan(mod: ModuleType) -> None:
    assert mod.parse_octoscan(OCTOSCAN_JSON) == [
        ("script-injection.yml", 10, "expression-injection")
    ]


def test_parse_poutine_ignora_achado_sem_linha(mod: ModuleType) -> None:
    assert mod.parse_poutine(POUTINE_JSON) == [("script-injection.yml", 10, "injection")]


def test_bate_respeita_tolerancia_de_uma_linha(mod: ModuleType) -> None:
    assert mod.bate("script-injection", 10, 10)
    assert mod.bate("script-injection", 10, 9)
    assert mod.bate("script-injection", 10, 11)
    assert not mod.bate("script-injection", 10, 8)
    assert not mod.bate("script-injection", 10, 12)


def test_bate_regra_so_arquivo_ignora_linha(mod: ModuleType) -> None:
    """invalid-yaml casa só por arquivo — ver REGRAS_SO_ARQUIVO e a nota em equivalencias.json."""
    assert mod.bate("invalid-yaml", 1, 37)


# ---- equivalencias.json: o arquivo real precisa ser consistente consigo mesmo --------------


def test_equivalencias_cobre_toda_regra_positiva_do_manifesto(mod: ModuleType) -> None:
    manifesto = mod.ler_manifesto()
    equivalencias = mod.ler_equivalencias()
    regras_do_manifesto = {str(r["regra"]) for r in manifesto if r["eh_achado"]}
    assert regras_do_manifesto <= set(equivalencias)


def test_equivalencias_so_referencia_ferramentas_conhecidas(mod: ModuleType) -> None:
    for item in mod.ler_equivalencias().values():
        assert set(item) <= {"regra", "zizmor", "actionlint", "octoscan", "poutine", "nota"}


# ---- montar_linhas / gerar_markdown: a adjudicação propriamente dita ------------------------


def _resultado(mod: ModuleType, achados: list[tuple[str, int, str]]) -> object:
    return mod.ResultadoFerramenta("x", achados, None)


def test_montar_linhas_marca_falso_positivo_da_esteira_corretamente(mod: ModuleType) -> None:
    """Regressão do bug corrigido neste item: um achado da Esteira numa linha-armadilha de
    `negativos/` precisa virar 'fp', não 'hit' com a polaridade de FP invertida."""
    manifesto = [
        {
            "arquivo": "negativos/armadilha.yml",
            "linha": 5,
            "eh_achado": False,
            "regra": None,
            "nota": "",
        }
    ]
    equivalencias: dict[str, dict[str, object]] = {}
    ferramentas_vazias = {
        "zizmor": _resultado(mod, []),
        "actionlint": _resultado(mod, []),
        "octoscan": _resultado(mod, []),
        "poutine": _resultado(mod, []),
    }

    # Esteira disparou (incorretamente) na linha-armadilha: deve contar como FP, não como hit.
    linhas_com_fp = mod.montar_linhas(
        manifesto, equivalencias, [("armadilha.yml", 5, "qualquer-regra")], ferramentas_vazias
    )
    assert linhas_com_fp[0].por_ferramenta["esteira"] == "fp"

    # Esteira ficou calada: correto, deve ser 'ok', não 'fp'.
    linhas_sem_fp = mod.montar_linhas(manifesto, equivalencias, [], ferramentas_vazias)
    assert linhas_sem_fp[0].por_ferramenta["esteira"] == "ok"


def test_montar_linhas_marca_hit_e_miss_em_positivos(mod: ModuleType) -> None:
    manifesto = [
        {
            "arquivo": "positivos/exemplo.yml",
            "linha": 10,
            "eh_achado": True,
            "regra": "script-injection",
            "nota": "",
        }
    ]
    equivalencias = {
        "script-injection": {
            "regra": "script-injection",
            "zizmor": "template-injection",
            "actionlint": None,
            "octoscan": None,
            "poutine": None,
            "nota": None,
        }
    }
    ferramentas = {
        "zizmor": _resultado(mod, [("exemplo.yml", 10, "template-injection")]),
        "actionlint": _resultado(mod, []),
        "octoscan": _resultado(mod, []),
        "poutine": _resultado(mod, []),
    }
    linhas = mod.montar_linhas(
        manifesto, equivalencias, [("exemplo.yml", 10, "script-injection")], ferramentas
    )
    linha = linhas[0]
    assert linha.por_ferramenta["esteira"] == "hit"
    assert linha.por_ferramenta["zizmor"] == "hit"
    assert linha.por_ferramenta["actionlint"] is None  # sem equivalência mapeada
    assert linha.por_ferramenta["octoscan"] is None

    # Sem o achado do zizmor, vira miss (a checagem existe e mapeia, só não achou desta vez).
    ferramentas_sem_zizmor = {**ferramentas, "zizmor": _resultado(mod, [])}
    linhas_miss = mod.montar_linhas(
        manifesto, equivalencias, [("exemplo.yml", 10, "script-injection")], ferramentas_sem_zizmor
    )
    assert linhas_miss[0].por_ferramenta["zizmor"] == "miss"


def test_gerar_markdown_contem_convite_a_contestacao_e_resumo(mod: ModuleType) -> None:
    manifesto = [
        {"arquivo": "positivos/a.yml", "linha": 1, "eh_achado": True, "regra": "r1", "nota": ""},
        {"arquivo": "negativos/b.yml", "linha": 2, "eh_achado": False, "regra": None, "nota": ""},
    ]
    equivalencias = {
        "r1": {
            "regra": "r1",
            "zizmor": None,
            "actionlint": None,
            "octoscan": None,
            "poutine": None,
            "nota": None,
        }
    }
    ferramentas = {nome: _resultado(mod, []) for nome in mod.FERRAMENTAS}
    linhas = mod.montar_linhas(manifesto, equivalencias, [("a.yml", 1, "r1")], ferramentas)
    markdown = mod.gerar_markdown(linhas, ferramentas, equivalencias)

    assert "convite" in markdown.lower() and "contestação" in markdown.lower()
    assert "## Resumo" in markdown
    assert "equivalencias.json" in markdown


def test_gerar_markdown_relata_ferramenta_que_nao_rodou(mod: ModuleType) -> None:
    manifesto: list[dict[str, object]] = []
    equivalencias: dict[str, dict[str, object]] = {}
    ferramentas = {nome: _resultado(mod, []) for nome in mod.FERRAMENTAS}
    ferramentas["zizmor"] = mod.ResultadoFerramenta("zizmor", [], "binário não encontrado")
    linhas = mod.montar_linhas(manifesto, equivalencias, [], ferramentas)
    markdown = mod.gerar_markdown(linhas, ferramentas, equivalencias)

    assert "não rodou" in markdown
    assert "binário não encontrado" in markdown
