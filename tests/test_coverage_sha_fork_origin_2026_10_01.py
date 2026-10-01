"""Contrapartida pública da E09: "o SHA fixado pertence mesmo ao repositório declarado?"

'unpinned-action-thirdparty'/'unpinned-action-firstparty' só confirmam o FORMATO da referência —
SHA completo de 40 caracteres versus tag/branch mutável. Nenhuma checagem do catálogo confirma que
o commit pinado pertence de fato ao histórico do 'owner/repo' nomeado, e não a um fork dele: o
GitHub resolve 'uses: owner/repo@sha' contra o grafo de objetos Git compartilhado entre um
repositório e seus forks, então um SHA que existe só num fork resolve do mesmo jeito ("imposter
commit") — e um self-scan limpo, com todas as actions pinadas por SHA, não fala sobre esse risco.

A pesquisa de Adnan Khan sobre o compromisso do angular/dev-infra (dez/2025, bounty de US$
31.337 pago pelo Google) documenta exatamente essa classe: a melhor via de impacto discutida era
uma PR de version-bump que reapontasse o SHA pinado de uma action para um commit existente só num
fork de 'actions/checkout' — um "SHA bump" que passa review sem o revisor confirmar a origem.
Confirmar a origem genuína exige consulta de rede à API do GitHub (o que o fork realmente
contém), e esta ferramenta mantém o motor público 100% offline por desenho.
"""

from __future__ import annotations

from pathlib import Path

from esteira.checks.engine import scan
from esteira.report.json_report import KNOWN_GAPS, to_document


def test_known_gaps_sai_no_bloco_coverage(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    ids = {gap["id"] for gap in cov["known_gaps"]}
    assert "sha-pin-fork-origin-unverified" in ids


def test_known_gaps_traz_o_detalhe_em_texto(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    gap = next(g for g in cov["known_gaps"] if g["id"] == "sha-pin-fork-origin-unverified")
    assert "imposter" in gap["detail"]
    assert "fork" in gap["detail"]


def test_scan_so_com_shas_pinados_ainda_assim_declara_o_gap(safe_repo: Path) -> None:
    # O caso que motiva o item: 'safe_repo' só usa actions pinadas por SHA completo — o veredito
    # de formato é limpo (zero achados de 'unpinned-action-*'). Mesmo assim, "pinado por SHA" não
    # é "confirmado como pertencente ao repositório declarado": o gap precisa sobreviver aqui.
    resultado = scan(safe_repo)
    ids_achados = {f.check_id for f in resultado.findings}
    assert "unpinned-action-thirdparty" not in ids_achados
    assert "unpinned-action-firstparty" not in ids_achados
    cov = to_document(resultado)["coverage"]
    assert any(g["id"] == "sha-pin-fork-origin-unverified" for g in cov["known_gaps"])


def test_known_gaps_e_constante_independente_do_recorte(safe_repo: Path) -> None:
    completo = to_document(scan(safe_repo))["coverage"]["known_gaps"]
    recortado = to_document(scan(safe_repo, only={"script-injection"}))["coverage"]["known_gaps"]
    assert completo == recortado == [dict(gap) for gap in KNOWN_GAPS]
