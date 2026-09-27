"""E07b — `security-tool-unpinned`: ferramenta de segurança conhecida fixada por tag/branch.

Cobre o disparo (ação da lista + ref não-SHA, com subpath normalizado e case-insensitive),
os NÃO-disparos que seguram o FP (ref SHA, action fora da lista) e a SUBSUNÇÃO: o achado
dedicado troca — não soma — o `unpinned-action-firstparty`/`unpinned-action-thirdparty`
genérico da MESMA linha. A rede de propriedade generaliza os exemplos para TODA a lista
`ACOES_DE_SEGURANCA`, não só o item citado no critério de aceite.
"""

from __future__ import annotations

import yaml
from hypothesis import given
from hypothesis import strategies as st

from esteira.checks.catalog import CATALOG
from esteira.checks.detectors import run_all
from esteira.checks.ferramenta_de_seguranca import (
    ACOES_DE_SEGURANCA,
    CATALOG_ENTRIES,
    check_security_tool_unpinned,
)
from esteira.core.models import Severity, Workflow

_SHA_SEGURO = "b4ffde65f46336ab88eb53be808477a3936bae11"  # 40 hex, não é um caso do catálogo


def _wf(text: str) -> Workflow:
    data = yaml.safe_load(text)
    return Workflow(path="w.yml", text=text, data=data if isinstance(data, dict) else None)


def _uses(action_ref: str) -> Workflow:
    return _wf(
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: {action_ref}\n"
    )


def _ids(wf: Workflow) -> set[str]:
    return {f.check_id for f in check_security_tool_unpinned(wf)}


def _run_all_ids(wf: Workflow) -> set[str]:
    return {f.check_id for f in run_all(wf)}


# --------------------------------------------------------------------------- #
# exemplos
# --------------------------------------------------------------------------- #


def test_ferramenta_de_seguranca_por_tag_dispara() -> None:
    wf = _uses("gitleaks/gitleaks-action@v2")
    achados = check_security_tool_unpinned(wf)
    assert len(achados) == 1
    f = achados[0]
    assert f.check_id == "security-tool-unpinned"
    assert f.severity is Severity.HIGH
    assert f.evidence == "gitleaks/gitleaks-action@v2"


def test_sha_nao_dispara() -> None:
    assert _ids(_uses(f"gitleaks/gitleaks-action@{_SHA_SEGURO}")) == set()


def test_action_fora_da_lista_nao_dispara() -> None:
    assert _ids(_uses("actions/checkout@v4")) == set()


def test_subpath_normalizado_dispara() -> None:
    # 'github/codeql-action/analyze' é o MESMO repositório que 'github/codeql-action' — o risco
    # é da ferramenta, não do subdiretório usado.
    assert "security-tool-unpinned" in _ids(_uses("github/codeql-action/analyze@v3"))


def test_casamento_de_raiz_nao_ignora_maiusculas_do_ref() -> None:
    assert "security-tool-unpinned" in _ids(_uses("gitleaks/gitleaks-action@V2"))


def test_action_local_ou_sem_ref_ignorada() -> None:
    assert (
        _ids(_wf("on: push\njobs:\n  b:\n    steps:\n      - uses: ./.github/actions/x\n")) == set()
    )


def test_sem_data_yaml_nao_quebra() -> None:
    assert check_security_tool_unpinned(Workflow(path="x.yml", text=":", data=None)) == []


def test_catalog_entries_registrado_e_unico() -> None:
    ids = [m.id for m in CATALOG_ENTRIES]
    assert ids == ["security-tool-unpinned"]
    assert "security-tool-unpinned" in CATALOG
    assert CATALOG["security-tool-unpinned"].severity is Severity.HIGH


def test_lista_de_ferramentas_nao_vazia() -> None:
    assert len(ACOES_DE_SEGURANCA) >= 5
    assert all("/" in raiz for raiz in ACOES_DE_SEGURANCA)


# --------------------------------------------------------------------------- #
# subsunção — via run_all, o único ponto que vê os dois achados juntos
# --------------------------------------------------------------------------- #


def test_subsome_o_unpinned_generico_da_mesma_linha() -> None:
    ids = _run_all_ids(_uses("gitleaks/gitleaks-action@v2"))
    assert "security-tool-unpinned" in ids
    assert "unpinned-action-thirdparty" not in ids
    assert "unpinned-action-firstparty" not in ids


def test_ferramenta_de_seguranca_de_primeira_parte_tambem_subsome() -> None:
    # github/codeql-action é 1ª parte (owner 'github') — sem subsunção o genérico seria
    # 'unpinned-action-firstparty' (BAIXA); o dedicado (ALTA) precisa tomar o lugar dele também.
    ids = _run_all_ids(_uses("github/codeql-action@v3"))
    assert "security-tool-unpinned" in ids
    assert "unpinned-action-firstparty" not in ids


def test_generico_sobrevive_quando_nao_ha_ferramenta_de_seguranca() -> None:
    # Subsunção é ESCOPADA à lista: uma action de terceiros comum continua com o achado
    # genérico — não pode desaparecer achado nenhum por causa desta checagem nova.
    ids = _run_all_ids(_uses("some-org/deploy-action@v1"))
    assert "unpinned-action-thirdparty" in ids
    assert "security-tool-unpinned" not in ids


def test_duas_actions_uma_ferramenta_uma_generica_cada_uma_seu_achado() -> None:
    wf = _wf(
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: gitleaks/gitleaks-action@v2\n"
        "      - uses: some-org/deploy-action@v1\n"
    )
    achados = run_all(wf)
    por_linha = {f.line: f.check_id for f in achados}
    assert por_linha[7] == "security-tool-unpinned"
    assert por_linha[8] == "unpinned-action-thirdparty"


# --------------------------------------------------------------------------- #
# propriedade — generaliza para TODA a lista, não só o exemplo do critério de aceite
# --------------------------------------------------------------------------- #

_ALFABETO_REF = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
_REFS_NAO_SHA = st.text(alphabet=_ALFABETO_REF, min_size=1, max_size=12).filter(
    lambda s: not (len(s) == 40 and all(c in "0123456789abcdefABCDEF" for c in s))
)


@given(raiz=st.sampled_from(sorted(ACOES_DE_SEGURANCA)), ref=_REFS_NAO_SHA, subpath=st.booleans())
def test_toda_ferramenta_da_lista_com_ref_nao_sha_subsome(
    raiz: str, ref: str, subpath: bool
) -> None:
    """Classe: ação ∈ ACOES_DE_SEGURANCA ∧ ref não-SHA ⇒ security-tool-unpinned sozinho na linha
    (nunca junto do genérico), qualquer que seja a ferramenta da lista ou o subpath usado."""
    acao = f"{raiz}/subdir" if subpath else raiz
    ids = _run_all_ids(_uses(f"{acao}@{ref}"))
    assert "security-tool-unpinned" in ids
    assert not any(cid.startswith("unpinned-action-") for cid in ids)


@given(
    raiz=st.sampled_from(sorted(ACOES_DE_SEGURANCA)),
    hexref=st.text(alphabet="0123456789abcdef", min_size=40, max_size=40),
)
def test_toda_ferramenta_da_lista_com_sha_nunca_dispara(raiz: str, hexref: str) -> None:
    """Classe complementar: mesma ferramenta, ref SHA ⇒ nenhum achado de nenhuma das duas
    famílias (nem o dedicado, nem o genérico que ele substituiria)."""
    ids = _run_all_ids(_uses(f"{raiz}@{hexref}"))
    assert "security-tool-unpinned" not in ids
    assert not any(cid.startswith("unpinned-action-") for cid in ids)
