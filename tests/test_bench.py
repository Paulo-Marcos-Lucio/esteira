"""P2-04 — o corpus rotulado é portão, não enfeite.

Um `bench/` que ninguém roda apodrece em silêncio: a regra muda, o número do README continua
lá, e a medição vira lembrança. Este teste faz a bateria rodar no mesmo `pytest` do CI, então
quem afrouxar uma detecção coberta pelo corpus quebra a suíte antes do merge.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

BENCH = Path(__file__).resolve().parent.parent / "bench"


def _avaliar() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench_avaliar", BENCH / "avaliar.py")
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="module")
def manifesto() -> list[dict[str, object]]:
    dados: list[dict[str, object]] = json.loads(
        (BENCH / "manifest.json").read_text(encoding="utf-8")
    )
    return dados


def test_todo_rotulo_do_manifesto_aponta_para_um_arquivo_que_existe(
    manifesto: list[dict[str, object]],
) -> None:
    """Rótulo órfão infla o denominador do recall para baixo sem ninguém perceber."""
    for rotulo in manifesto:
        assert (BENCH / str(rotulo["arquivo"])).is_file(), rotulo["arquivo"]


def test_bench_sem_falso_negativo_e_sem_falso_positivo() -> None:
    """Recall 19/19 e precisão 19/19 sobre o corpus. É a trava anti-regressão da calibração —
    e o exit code do `avaliar.py` é a mesma coisa, para quem roda a bateria na mão."""
    assert _avaliar().main() == 0


def test_corpus_cobre_o_catalogo_inteiro(manifesto: list[dict[str, object]]) -> None:
    """Checagem sem caso positivo no corpus NÃO está medida por nenhum número do README —
    e uma checagem nova não pode nascer fora da régua sem que a suíte reclame."""
    from esteira.checks.catalog import CATALOG

    cobertas = {r["regra"] for r in manifesto if r["eh_achado"]}
    assert set(CATALOG) - cobertas == set()


def test_negativos_nao_tem_nenhum_rotulo_positivo(manifesto: list[dict[str, object]]) -> None:
    """`negativos/` é o lado da precisão: um positivo plantado ali desmonta a medição."""
    assert not [
        r for r in manifesto if r["eh_achado"] and str(r["arquivo"]).startswith("negativos")
    ]
