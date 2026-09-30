"""Contrapartida pública da E08: a classe "propagação de taint por outputs entre steps não é
rastreada" saía só em prosa, na seção "Limitações conhecidas" do README — um consumidor de
máquina (dashboard/CI) lendo o JSON não tinha como saber que "0 achados" não fala sobre ela.
`coverage.known_gaps` é a mesma classe, na saída estruturada.

Diferença de `omitted_by_operator`: aquele é checagem EXISTENTE que `--only`/`--skip` excluiu
desta varredura; `known_gaps` é checagem que o catálogo INTEIRO não tem, para nenhuma varredura —
por isso é constante por versão da ferramenta, não varia com o repositório nem com o recorte.
"""

from __future__ import annotations

from pathlib import Path

from esteira.checks.engine import scan
from esteira.report.json_report import KNOWN_GAPS, to_document


def test_known_gaps_sai_no_bloco_coverage(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    ids = {gap["id"] for gap in cov["known_gaps"]}
    assert "outputs-propagation-untracked" in ids


def test_known_gaps_traz_o_detalhe_em_texto(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    gap = next(g for g in cov["known_gaps"] if g["id"] == "outputs-propagation-untracked")
    assert "outputs" in gap["detail"]
    assert "linha de ORIGEM" in gap["detail"]


def test_known_gaps_e_constante_independente_do_recorte(safe_repo: Path) -> None:
    # `--only` muda `ran`/`omitted_by_operator`; `known_gaps` não é sobre o que RODOU, é sobre o
    # que o catálogo nunca cobre — recortar a varredura não devolve a cobertura que falta ali.
    completo = to_document(scan(safe_repo))["coverage"]["known_gaps"]
    recortado = to_document(scan(safe_repo, only={"script-injection"}))["coverage"]["known_gaps"]
    assert completo == recortado == [dict(gap) for gap in KNOWN_GAPS]


def test_scan_limpo_e_completo_ainda_assim_declara_known_gaps(safe_repo: Path) -> None:
    # O caso que motiva o item: varredura completa, zero achados — "limpo" não pode significar
    # "cobre tudo". known_gaps precisa sobreviver mesmo no veredito mais verde possível.
    resultado = scan(safe_repo)
    assert not resultado.findings
    assert resultado.cobertura_parcial is False
    assert to_document(resultado)["coverage"]["known_gaps"]
