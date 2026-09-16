"""ES-01d — invariantes de CLASSE do mecanismo de supressão inline (`detectors._partition` /
`detectors._suppression_reason`), a mesma partição que o ES-01c passou a expor no relatório.

Os testes por exemplo (`test_review_fixes.py::test_inline_suppression_is_honored` e vizinhos)
já cobriam casos concretos. Aqui a rede é de PROPRIEDADE: gera milhares de combinações de
achado, diretiva e linha e afirma o que NÃO pode falhar nunca, para as três classes que este
item nomeia:

* **conservação** — nenhum achado bruto se perde nem duplica: visíveis + suprimidos é sempre
  exatamente o conjunto que entrou, qualquer que seja a mistura de diretivas nas linhas.
* **escopo** — `# esteira: ignore[a, b]` nunca cala um achado cujo `check_id` não está em
  `{a, b}` (o defeito fail-open que a diretiva escopada existe para fechar).
* **fail-closed** — só uma diretiva RECONHECIDA cala um achado; texto de comentário sem as
  palavras-chave, ou uma linha fora do arquivo, tem que deixar o achado visível por padrão.
"""

from __future__ import annotations

from collections import Counter

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from esteira.checks.catalog import CATALOG
from esteira.checks.detectors import _partition, _suppression_reason
from esteira.core.models import Finding, Severity, Workflow

_CHECK_IDS = sorted(CATALOG)


def _finding(check_id: str, line: int) -> Finding:
    return Finding(
        check_id=check_id,
        title="t",
        severity=Severity.MEDIUM,
        path="w.yml",
        line=line,
        detail="d",
        recommendation="r",
    )


def _wf(lines: list[str]) -> Workflow:
    text = "\n".join(lines) + "\n" if lines else "\n"
    return Workflow(path="w.yml", text=text, data={})


# --------------------------------------------------------------------------- #
# conservação — visíveis + suprimidos == brutos, sempre
# --------------------------------------------------------------------------- #

_N_LINHAS = 6
# Uma diretiva possível por linha: nenhuma, ampla, escopada (subconjunto de check_ids reais) ou
# zizmor — as quatro formas que `_suppression_reason` reconhece.
_DIRETIVA = st.one_of(
    st.none(),
    st.just("esteira: ignore"),
    st.lists(st.sampled_from(_CHECK_IDS), min_size=1, max_size=3, unique=True).map(
        lambda ids: "esteira: ignore[" + ", ".join(ids) + "]"
    ),
    st.just("zizmor: ignore[regra-qualquer]"),
)


@settings(max_examples=200)
@given(
    achados=st.lists(
        st.tuples(st.sampled_from(_CHECK_IDS), st.integers(min_value=1, max_value=_N_LINHAS)),
        max_size=10,
    ),
    diretivas=st.dictionaries(
        st.integers(min_value=1, max_value=_N_LINHAS), _DIRETIVA, max_size=_N_LINHAS
    ),
)
def test_conservacao_visiveis_mais_suprimidos_e_sempre_os_brutos(
    achados: list[tuple[str, int]], diretivas: dict[int, str | None]
) -> None:
    linhas = [
        f"      - run: echo {i}  # {diretivas.get(i) or ''}".rstrip()
        for i in range(1, _N_LINHAS + 1)
    ]
    wf = _wf(linhas)
    brutos = [_finding(check_id, linha) for check_id, linha in achados]

    visiveis, suprimidos = _partition(wf, brutos)

    assert len(visiveis) + len(suprimidos) == len(brutos)
    reconstituido = visiveis + [s.finding for s in suprimidos]
    assert Counter(reconstituido) == Counter(brutos)
    # partição de verdade: nenhum achado está nos dois grupos ao mesmo tempo.
    assert {id(f) for f in visiveis}.isdisjoint(id(s.finding) for s in suprimidos)


# --------------------------------------------------------------------------- #
# escopo — diretiva escopada nunca vaza para um check_id fora da lista
# --------------------------------------------------------------------------- #


@settings(max_examples=200)
@given(
    alvo=st.sampled_from(_CHECK_IDS),
    outros=st.lists(st.sampled_from(_CHECK_IDS), min_size=1, max_size=3, unique=True),
)
def test_escopo_diretiva_nao_vaza_para_check_id_fora_da_lista(alvo: str, outros: list[str]) -> None:
    assume(alvo not in outros)
    linha = f"      - run: echo x  # esteira: ignore[{', '.join(outros)}]"
    wf = _wf([linha])
    achado = _finding(alvo, 1)

    assert _suppression_reason(wf, achado) is None


@settings(max_examples=200)
@given(
    alvo=st.sampled_from(_CHECK_IDS),
    outros=st.lists(st.sampled_from(_CHECK_IDS), min_size=0, max_size=2, unique=True),
)
def test_escopo_diretiva_cala_quando_o_check_id_esta_na_lista(alvo: str, outros: list[str]) -> None:
    """Reverso da propriedade acima: a mesma diretiva escopada CALA quando `alvo` está na lista
    — sem isso, a invariante de não-vazamento seria satisfeita trivialmente por nunca suprimir."""
    lista = [*outros, alvo] if alvo not in outros else outros
    linha = f"      - run: echo x  # esteira: ignore[{', '.join(lista)}]"
    wf = _wf([linha])
    achado = _finding(alvo, 1)

    assert _suppression_reason(wf, achado) is not None


# --------------------------------------------------------------------------- #
# fail-closed — só diretiva RECONHECIDA cala; ausência de match nunca suprime
# --------------------------------------------------------------------------- #

_TEXTO_SEM_IGNORE = st.text(
    alphabet=st.characters(blacklist_characters="\n#", blacklist_categories=("Cs",)),
    max_size=40,
).filter(lambda s: "ignore" not in s.lower())


@settings(max_examples=200)
@given(alvo=st.sampled_from(_CHECK_IDS), comentario=_TEXTO_SEM_IGNORE)
def test_fail_closed_sem_diretiva_reconhecida_nunca_suprime(alvo: str, comentario: str) -> None:
    linha = f"      - run: echo x  # {comentario}"
    wf = _wf([linha])
    achado = _finding(alvo, 1)

    assert _suppression_reason(wf, achado) is None


@settings(max_examples=100)
@given(alvo=st.sampled_from(_CHECK_IDS), linha_alvo=st.integers(min_value=2, max_value=50))
def test_fail_closed_linha_fora_do_arquivo_nunca_suprime(alvo: str, linha_alvo: int) -> None:
    """Achado ancorado além do fim do arquivo (índice fora de `wf.lines`) não pode ser tratado
    como suprimido por omissão — o padrão seguro é reportar, nunca calar por engano de índice."""
    wf = _wf(["      - run: echo x  # esteira: ignore"])  # 1 linha só; linha_alvo é sempre >= 2
    achado = _finding(alvo, linha_alvo)

    assert _suppression_reason(wf, achado) is None
