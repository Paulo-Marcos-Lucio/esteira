"""Invariante da matriz de cobertura CICD-SEC (`checks/cobertura.py`).

A classe de defeito que este teste tranca: uma matriz de cobertura que declara ausência sem
dizer onde olhou é tão enganosa quanto não ter matriz — o cliente não consegue distinguir "não
cobrimos e sabemos por quê" de "não cobrimos e não checamos". `ClasseCICDSEC` já recusa montar
uma classe `nao-coberto` sem `motivo`/`incidente`; aqui a propriedade é testada contra qualquer
particionamento das dez classes entre os três status, não só contra o `CLASSES` real — para que
uma `CLASSES` futura, com outra combinação, não escape da regra por acidente.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esteira.checks.catalog import CATALOG
from esteira.checks.cobertura import CLASSES, IDS_CICD_SEC, ClasseCICDSEC, StatusCobertura, avaliar

_ALGUM_CHECK = next(iter(CATALOG))
_STATUS = st.sampled_from(list(StatusCobertura))


def _classe_valida(cid: str, status: StatusCobertura) -> ClasseCICDSEC:
    if status is StatusCobertura.NAO_COBERTO:
        return ClasseCICDSEC(cid, cid, status, motivo="porque sim", incidente="caso X")
    return ClasseCICDSEC(cid, cid, status, checks=(_ALGUM_CHECK,))


# --------------------------------------------------------------------------- #
# a partição real: as dez classes, sem buraco e sem sobra
# --------------------------------------------------------------------------- #


def test_classes_real_cobre_exatamente_o_eixo_cicd_sec() -> None:
    assert set(CLASSES) == IDS_CICD_SEC


def test_avaliar_particiona_sem_interseccao_e_sem_buraco() -> None:
    particao = avaliar()
    todos = [cid for valores in particao.values() for cid in valores]
    assert set(todos) == IDS_CICD_SEC
    assert len(todos) == len(IDS_CICD_SEC)  # sem duplicata entre partições: a UNIÃO é a soma


def test_toda_classe_nao_coberto_tem_motivo_e_incidente() -> None:
    particao = avaliar()
    for cid in particao[StatusCobertura.NAO_COBERTO]:
        classe = CLASSES[cid]
        assert classe.motivo, f"{cid}: nao-coberto sem motivo"
        assert classe.incidente, f"{cid}: nao-coberto sem incidente"


def test_toda_classe_coberta_ou_parcial_cita_checagem_real() -> None:
    for cid, classe in CLASSES.items():
        if classe.status is StatusCobertura.NAO_COBERTO:
            continue
        assert classe.checks, f"{cid}: {classe.status.value} sem nenhuma checagem citada"
        for check_id in classe.checks:
            assert check_id in CATALOG, f"{cid}: checagem '{check_id}' não existe"


# --------------------------------------------------------------------------- #
# a invariante genérica, property-based: para QUALQUER particionamento das dez classes entre
# os três status (não só o `CLASSES` de hoje), `avaliar` só aceita entrada onde nao-coberto
# carrega motivo+incidente — porque essa exigência mora na construção, não em `avaliar`.
# --------------------------------------------------------------------------- #


@settings(max_examples=100)
@given(status_por_classe=st.dictionaries(st.sampled_from(sorted(IDS_CICD_SEC)), _STATUS))
def test_qualquer_particionamento_completo_passa_por_avaliar(
    status_por_classe: dict[str, StatusCobertura],
) -> None:
    if set(status_por_classe) != IDS_CICD_SEC:
        return  # hypothesis pode gerar dict parcial; o caso "incompleto" é testado à parte
    classes = {cid: _classe_valida(cid, status) for cid, status in status_por_classe.items()}
    particao = avaliar(classes)
    todos = [cid for valores in particao.values() for cid in valores]
    assert set(todos) == IDS_CICD_SEC
    assert len(todos) == len(IDS_CICD_SEC)
    for cid in particao[StatusCobertura.NAO_COBERTO]:
        assert classes[cid].motivo and classes[cid].incidente


@settings(max_examples=50)
@given(faltante=st.sampled_from(sorted(IDS_CICD_SEC)))
def test_avaliar_rejeita_particao_com_classe_faltando(faltante: str) -> None:
    incompleta = {
        cid: _classe_valida(cid, StatusCobertura.COBERTO) for cid in IDS_CICD_SEC if cid != faltante
    }
    with pytest.raises(ValueError):
        avaliar(incompleta)


def test_avaliar_rejeita_classe_fora_do_eixo() -> None:
    classes = {cid: _classe_valida(cid, StatusCobertura.COBERTO) for cid in IDS_CICD_SEC}
    classes["CICD-SEC-99"] = ClasseCICDSEC(
        "CICD-SEC-99", "fora do eixo", StatusCobertura.COBERTO, checks=(_ALGUM_CHECK,)
    )
    del classes["CICD-SEC-1"]
    with pytest.raises(ValueError):
        avaliar(classes)


# --------------------------------------------------------------------------- #
# a trava na construção: não é possível declarar `nao-coberto` sem motivo+incidente, nem
# `coberto`/`parcial` sem citar checagem real — isso impede uma `CLASSES` futura de voltar a
# confundir "não cobrimos" com "não dissemos nada".
# --------------------------------------------------------------------------- #


@settings(max_examples=50)
@given(
    motivo=st.one_of(st.none(), st.just("")),
    incidente=st.one_of(st.none(), st.just("")),
)
def test_nao_coberto_sem_motivo_ou_incidente_nao_constroi(
    motivo: str | None, incidente: str | None
) -> None:
    if motivo and incidente:
        return  # o par completo é o caso válido, testado em outro lugar
    with pytest.raises(ValueError):
        ClasseCICDSEC(
            "CICD-SEC-1",
            "Insufficient Flow Control Mechanisms",
            StatusCobertura.NAO_COBERTO,
            motivo=motivo,
            incidente=incidente,
        )


@pytest.mark.parametrize("status", [StatusCobertura.COBERTO, StatusCobertura.PARCIAL])
def test_coberto_ou_parcial_sem_checagem_nao_constroi(status: StatusCobertura) -> None:
    with pytest.raises(ValueError):
        ClasseCICDSEC("CICD-SEC-3", "Dependency Chain Abuse", status, checks=())


def test_checagem_inexistente_nao_constroi() -> None:
    with pytest.raises(ValueError):
        ClasseCICDSEC(
            "CICD-SEC-3",
            "Dependency Chain Abuse",
            StatusCobertura.COBERTO,
            checks=("checagem-que-nao-existe",),
        )
