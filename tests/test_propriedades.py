"""Testes property-based (Hypothesis) da INVARIANTE de segurança da redação.

Um vazamento de credencial num relatório entregue ao cliente é o "bug sério achado tarde"
por excelência. Os testes por exemplo checam os tokens que alguém digitou; este gera milhares
de credenciais de cada formato conhecido e afirma a propriedade que NÃO pode falhar nunca:

    nenhuma credencial de formato conhecido sobrevive verbatim a `redact()`.

Se um dia alguém afrouxar um padrão de `_PADROES`, esta rede fica vermelha no CI — antes de
o vazamento chegar num laudo.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from esteira.core.redaction import mask, redact

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# Cada estratégia constrói uma credencial VÁLIDA para o padrão correspondente de _PADROES.
_CREDENCIAIS = st.one_of(
    st.text(_ALNUM, min_size=36, max_size=60).map(lambda s: "ghp_" + s),  # GitHub PAT
    st.text(_UP, min_size=16, max_size=16).map(lambda s: "AKIA" + s),  # AWS access key id
    st.text(_ALNUM, min_size=16, max_size=40).map(lambda s: "sk_live_" + s),  # Stripe
    st.text(_ALNUM, min_size=35, max_size=35).map(lambda s: "AIza" + s),  # Google API key
    st.text(_ALNUM, min_size=36, max_size=36).map(lambda s: "npm_" + s),  # npm
)


@settings(max_examples=400)
@given(
    cred=_CREDENCIAIS,
    antes=st.text(_ALNUM + " .:/=", max_size=20),
    depois=st.text(_ALNUM + " .:", max_size=20),
)
def test_nenhuma_credencial_conhecida_sobrevive_a_redacao(
    cred: str, antes: str, depois: str
) -> None:
    """INVARIANTE: a credencial crua nunca aparece inteira na saída redigida, em qualquer entorno."""
    linha = f"{antes} {cred} {depois}"
    saida = redact(linha) or ""
    assert cred not in saida, f"credencial vazou na redação: {cred!r}"
    assert "…" in saida, "a máscara não foi aplicada"


@settings(max_examples=200)
@given(cred=_CREDENCIAIS)
def test_redacao_e_idempotente(cred: str) -> None:
    """INVARIANTE: redigir de novo não come mais nada (a máscara quebra a classe do padrão)."""
    uma = redact(cred)
    duas = redact(uma)
    assert uma == duas, "redação não é idempotente"


@settings(max_examples=300)
@given(valor=st.text(min_size=1, max_size=200))
def test_mask_expoe_no_maximo_as_pontas(valor: str) -> None:
    """INVARIANTE: `mask` expõe no máximo `2*keep` caracteres (+ a máscara) e nunca o valor inteiro."""
    keep = 4
    m = mask(valor, keep=keep)
    # a saída nunca é maior que as duas pontas + o caractere de máscara
    assert len(m) <= 2 * keep + 1, f"mask expôs demais: {valor!r} -> {m!r}"
    # um segredo longo jamais aparece inteiro na forma mascarada
    if len(valor) > 2 * keep + 4:
        assert valor not in m, f"valor inteiro sobreviveu à máscara: {valor!r} -> {m!r}"
