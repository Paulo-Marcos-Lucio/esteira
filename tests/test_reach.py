"""Alcance de um workflow — quem consegue disparar (ES-05c).

`pull_request_target`/`issues`/`issue_comment` aceitam evento de quem não tem push no
repositório (fork, comentário, issue) — EXTERNO. `push`/`schedule` só disparam por quem já
tem escrita no repositório ou pelo relógio — MANTENEDOR. A invariante que este arquivo tranca
é a cláusula "nunca MANTENEDOR" do critério de aceite: nenhum gatilho fora das duas listas
conhecidas pode ser rotulado MANTENEDOR, porque isso soa seguro para algo que a função nunca
avaliou. O teste de propriedade cobre TODO subconjunto possível de nomes de gatilho — não só
os exemplos do critério — para que a regra não regrida por um gatilho que ninguém pensou em
testar isoladamente.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from esteira.checks.engine import scan
from esteira.core.reach import Alcance, alcance_de_triggers

_EXTERNO = {"pull_request_target", "issues", "issue_comment"}
_MANTENEDOR = {"push", "schedule"}
_DESCONHECIDO = {"workflow_dispatch", "pull_request", "workflow_call", "watch", "fork"}
_QUALQUER = _EXTERNO | _MANTENEDOR | _DESCONHECIDO


def test_exemplos_do_criterio_de_aceite() -> None:
    assert alcance_de_triggers({"pull_request_target"}) is Alcance.EXTERNO
    assert alcance_de_triggers({"issues"}) is Alcance.EXTERNO
    assert alcance_de_triggers({"issue_comment"}) is Alcance.EXTERNO
    assert alcance_de_triggers({"push"}) is Alcance.MANTENEDOR
    assert alcance_de_triggers({"schedule"}) is Alcance.MANTENEDOR
    assert alcance_de_triggers({"workflow_dispatch"}) is Alcance.INDETERMINADO
    assert alcance_de_triggers(set()) is Alcance.INDETERMINADO


@given(triggers=st.sets(st.sampled_from(sorted(_QUALQUER))))
def test_qualquer_gatilho_externo_presente_da_externo(triggers: set[str]) -> None:
    """EXTERNO tem prioridade: um gatilho externo no meio de outros ainda torna o workflow
    externamente disparável, então a mistura não pode "diluir" o risco para MANTENEDOR."""
    if triggers & _EXTERNO:
        assert alcance_de_triggers(triggers) is Alcance.EXTERNO


@given(triggers=st.sets(st.sampled_from(sorted(_MANTENEDOR)), min_size=1))
def test_so_gatilhos_conhecidos_de_mantenedor_da_mantenedor(triggers: set[str]) -> None:
    assert alcance_de_triggers(triggers) is Alcance.MANTENEDOR


@given(
    conhecidos=st.sets(st.sampled_from(sorted(_MANTENEDOR))),
    desconhecidos=st.sets(st.sampled_from(sorted(_DESCONHECIDO)), min_size=1),
)
def test_gatilho_desconhecido_nunca_da_mantenedor(
    conhecidos: set[str], desconhecidos: set[str]
) -> None:
    """A cláusula literal do critério de aceite: presença de QUALQUER gatilho fora do
    catálogo conhecido barra o veredito MANTENEDOR, mesmo lado a lado com push/schedule."""
    resultado = alcance_de_triggers(conhecidos | desconhecidos)
    assert resultado is not Alcance.MANTENEDOR
    assert resultado is Alcance.INDETERMINADO


@given(triggers=st.sets(st.sampled_from(sorted(_QUALQUER))))
def test_alcance_e_total_um_resultado_para_qualquer_entrada(triggers: set[str]) -> None:
    """A função nunca lança e sempre devolve um membro da enum — não há entrada de gatilhos
    conhecidos que a deixe sem resposta."""
    assert isinstance(alcance_de_triggers(triggers), Alcance)


def _repo_com_workflow(base: Path, on_yaml: str) -> Path:
    # Sem bloco `permissions:` de propósito — garante que `missing-permissions` dispare em
    # QUALQUER gatilho, então o teste tem achado para conferir o `reach` carimbado por cima.
    wf = base / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "w.yml").write_text(
        f"name: w\non:\n{on_yaml}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ola\n",
        encoding="utf-8",
    )
    return base


def test_scan_carimba_reach_externo_a_partir_de_pull_request_target(tmp_path: Path) -> None:
    repo = _repo_com_workflow(tmp_path, "  pull_request_target:\n")
    resultado = scan(repo)
    assert resultado.findings
    assert all(f.reach is Alcance.EXTERNO for f in resultado.findings)


def test_scan_carimba_reach_mantenedor_a_partir_de_push(tmp_path: Path) -> None:
    repo = _repo_com_workflow(tmp_path, "  push:\n    branches: [main]\n")
    resultado = scan(repo)
    assert resultado.findings
    assert all(f.reach is Alcance.MANTENEDOR for f in resultado.findings)
