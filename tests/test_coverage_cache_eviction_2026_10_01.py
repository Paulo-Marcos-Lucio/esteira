"""Contrapartida pública da E10: a classe cache-poisoning por EVICÇÃO FORÇADA.

'cache-poisoning' só casa um par estrutural visível no YAML: uma ESCRITA em contexto
não-confiável e uma RESTAURAÇÃO da MESMA chave em contexto confiável, ambas nos workflows
escaneados. Isso não cobre o envenenamento por evicção: encher a cota de cache do repositório
(10 GB) para o LRU do GitHub expulsar a entrada legítima e escrever uma maliciosa sob a mesma
chave, agora livre — sem write/restore simétrico nenhum visível no repositório vítima, porque a
escrita de enchimento não precisa pertencer a nenhum workflow dele.

É a técnica real do compromisso do angular/dev-infra (dezembro/2025, bounty de US$ 31.337 pago
pelo Google): a ferramenta pública "Cacheract" encheu a cota para expulsar a entrada legítima; o
workflow agendado "ng-renovate" restaurou a entrada envenenada e expôs um token administrativo.
Um workflow que só RESTAURA uma chave privilegiada, sem nenhuma escrita visível no repositório,
não dispara 'cache-poisoning' — mas continua exposto ao mesmo risco.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from esteira.checks.engine import scan
from esteira.report.json_report import KNOWN_GAPS, to_document

# Um workflow agendado (privilegiado, análogo ao "ng-renovate" do incidente) que só RESTAURA uma
# chave de cache — nenhum WRITE em lugar nenhum do repositório. 'cache-poisoning' exige o par
# escrita/restauração no mesmo scan; sem a escrita, não há achado algum.
RESTORE_ONLY_WORKFLOW = """\
name: renovate-like
on:
  schedule:
    - cron: "0 3 * * *"
permissions:
  contents: write
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/cache/restore@0c45773b623bea8c8e75f24db7b59e957e7efc87
        with:
          key: node-modules-cache
          path: node_modules
      - name: install
        run: npm ci
"""


@pytest.fixture
def restore_only_repo(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "renovate-like.yml").write_text(RESTORE_ONLY_WORKFLOW, encoding="utf-8")
    return tmp_path


def test_known_gaps_sai_no_bloco_coverage(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    ids = {gap["id"] for gap in cov["known_gaps"]}
    assert "cache-poisoning-by-eviction-unverified" in ids


def test_known_gaps_traz_o_detalhe_em_texto(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    gap = next(g for g in cov["known_gaps"] if g["id"] == "cache-poisoning-by-eviction-unverified")
    assert "evicção" in gap["detail"] or "LRU" in gap["detail"]
    assert "zizmor" in gap["detail"]


def test_restauracao_privilegiada_sem_par_escrita_nao_dispara_cache_poisoning(
    restore_only_repo: Path,
) -> None:
    # O caso que motiva o item: um workflow agendado e privilegiado que só RESTAURA uma chave,
    # sem write visível em lugar nenhum do repositório — exatamente a forma do "ng-renovate" no
    # incidente real — não produz achado de 'cache-poisoning' (o detector exige o par).
    resultado = scan(restore_only_repo)
    ids_achados = {f.check_id for f in resultado.findings}
    assert "cache-poisoning" not in ids_achados


def test_mesmo_sem_achado_de_cache_poisoning_o_gap_continua_declarado(
    restore_only_repo: Path,
) -> None:
    cov = to_document(scan(restore_only_repo))["coverage"]
    ids = {gap["id"] for gap in cov["known_gaps"]}
    assert "cache-poisoning-by-eviction-unverified" in ids


def test_known_gaps_e_constante_independente_do_recorte(safe_repo: Path) -> None:
    completo = to_document(scan(safe_repo))["coverage"]["known_gaps"]
    recortado = to_document(scan(safe_repo, only={"script-injection"}))["coverage"]["known_gaps"]
    assert completo == recortado == [dict(gap) for gap in KNOWN_GAPS]
