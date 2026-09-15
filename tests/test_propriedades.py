"""Testes property-based (Hypothesis) da INVARIANTE de segurança da redação.

Um vazamento de credencial num relatório entregue ao cliente é o "bug sério achado tarde"
por excelência. Os testes por exemplo checam os tokens que alguém digitou; este gera milhares
de credenciais de cada formato conhecido e afirma a propriedade que NÃO pode falhar nunca:

    nenhuma credencial de formato conhecido sobrevive verbatim a `redact()`.

Se um dia alguém afrouxar um padrão de `_PADROES`, esta rede fica vermelha no CI — antes de
o vazamento chegar num laudo.
"""

from __future__ import annotations

import re
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.core.redaction import KEEP_PUBLICADO, mask, para_publicacao, redact

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# Um token mascarado no laudo tem a forma `<prefixo>…<sufixo>`. Isola as pontas visíveis para
# contá-las (mesma classe de caracteres que `redaction._TOKEN_MASCARADO`).
_TOKEN = re.compile(r"([A-Za-z0-9._/+~-]*)…([A-Za-z0-9._/+~-]*)")

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


@settings(max_examples=300)
@given(cred=_CREDENCIAIS, keep4=st.text(_ALNUM + " .:/=", max_size=30))
def test_para_publicacao_nunca_expoe_mais_que_o_teto(cred: str, keep4: str) -> None:
    """INVARIANTE (Classe E): `para_publicacao` encurta cada ponta visível ao teto KEEP_PUBLICADO,
    é monotônica (nunca revela mais que a máscara keep=4 de origem) e nunca deixa o segredo cru."""
    evidencia = redact(f"{keep4} {cred}")  # forma mascarada de triagem (keep=4)
    publicada = para_publicacao(evidencia) or ""
    assert cred not in publicada, f"segredo cru vazou no publicado: {cred!r}"
    for pre, suf in _TOKEN.findall(publicada):
        assert len(pre) <= KEEP_PUBLICADO, f"prefixo publicado > {KEEP_PUBLICADO}: {pre!r}"
        assert len(suf) <= KEEP_PUBLICADO, f"sufixo publicado > {KEEP_PUBLICADO}: {suf!r}"
    # idempotência: reduzir de novo não muda nada
    assert para_publicacao(publicada) == publicada


def _repo_com_credencial(tmp_path: Path, cred: str) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "vaza.yml").write_text(
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        f'      - run: echo "chave={cred} ${{{{ secrets.X }}}}"\n',
        encoding="utf-8",
    )
    return tmp_path


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(cred=_CREDENCIAIS)
def test_snippet_publicado_do_sarif_expoe_no_maximo_duas_pontas(cred: str, tmp_path: Path) -> None:
    """INVARIANTE de ponta a ponta (Classe E): para TODA credencial de formato conhecido, o
    `snippet` que a Esteira publica no SARIF (→ Code Scanning) expõe no máximo KEEP_PUBLICADO
    caracteres por ponta e nunca o valor cru. Fecha a classe no artefato que de fato SOBE."""
    import json

    from esteira.checks.engine import scan
    from esteira.report.sarif import to_sarif

    repo = _repo_com_credencial(tmp_path, cred)
    run = json.loads(to_sarif(scan(repo)))["runs"][0]
    snippets = [
        loc["physicalLocation"]["region"]["snippet"]["text"]
        for res in run["results"]
        for loc in res["locations"]
        if "snippet" in loc["physicalLocation"].get("region", {})
    ]
    assert any(cred[:2] in s for s in snippets), "o caso precisa gerar um snippet com a credencial"
    for s in snippets:
        assert cred not in s, f"segredo cru no snippet publicado: {cred!r}"
        for pre, suf in _TOKEN.findall(s):
            assert len(pre) <= KEEP_PUBLICADO and len(suf) <= KEEP_PUBLICADO, (
                f"snippet publicado expôs > {KEEP_PUBLICADO} por ponta: {s!r}"
            )
