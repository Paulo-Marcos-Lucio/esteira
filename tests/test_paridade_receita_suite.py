"""Paridade de receita da SUÍTE AppSec (Classe F) — travada por teste.

Um cliente confere os QUATRO tools (guardião/chaveiro/esteira/sentinela) com UMA receita só:
o mesmo `artifact_sha256` (JSON compacto-ordenado → SHA-256) e a mesma redação publicada
(≤ 2 caracteres por ponta, valor curto vira só o marcador). Os VALORES-OURO abaixo são
IDÊNTICOS nos quatro repositórios — quem edita um esperado quebra a paridade da suíte.

O ponto deste arquivo é provar que o CÓDIGO REAL de produção da Esteira bate com o ouro. Por
isso ele IMPORTA as funções de `esteira.core.*` — não reimplementa a receita à mão. As duas
funções canônicas da suíte moram, na Esteira, assim:

* ``artifact_sha256`` (JSON compacto-ordenado → SHA-256) É ``provenance.canonical_sha256`` — a
  primitiva que serializa `sort_keys=True, ensure_ascii=False, separators=(",", ":")` e tira o
  SHA-256 do UTF-8. O ``provenance.artifact_sha256`` público é essa mesma primitiva com o próprio
  campo ``artifact_sha256`` zerado antes (auto-hash do relatório); o teste prova que ele DELEGA a
  `canonical_sha256`, então a receita é uma só.
* redação publicada keep=2 É ``redaction.para_publicacao(redaction.mask(x, keep=4), keep=2)`` — o
  caminho de produção do `snippet` do SARIF: a máscara de TRIAGEM (keep=4) que o `redact` aplica a
  cada credencial, reduzida ao teto PUBLICADO (keep=2) que sobe pro Code Scanning. É exatamente o
  que `report/sarif.py` faz com a evidência.
"""

from __future__ import annotations

from esteira.core.provenance import artifact_sha256, canonical_sha256
from esteira.core.redaction import KEEP_PUBLICADO, mask, para_publicacao

# --- VALORES-OURO — idênticos nos quatro tools da suíte. NÃO editar os esperados. ------------ #
GOLDEN_DOC = {"alvo": "exemplo.com.br", "achados": 2, "regra": "pção-ção", "z": 1, "a": [3, 2, 1]}
GOLDEN_ARTIFACT_SHA256 = "bcd1a357a62308d43397cf4357ffb4fa45b904f9a31353da7e10468f213f6af1"
GOLDEN_REDACT = {
    "AKIAIOSFODNN7EXAMPLE": "AK…LE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a": "gh…4a",
    "1234": "…",
}


def _redacao_publicada(valor: str) -> str | None:
    """Caminho de produção do snippet publicado: triagem keep=4 → teto publicado keep=2.

    Exercita as DUAS funções reais compostas na mesma ordem que `report/sarif.py` — `mask`
    (usada por `redact` para mascarar cada credencial) e `para_publicacao` (que o renderizador
    SARIF aplica antes de publicar). Nada é reimplementado aqui."""
    return para_publicacao(mask(valor, keep=4), keep=KEEP_PUBLICADO)


def test_artifact_sha256_receita_unica_da_suite() -> None:
    """A serialização canônica REAL da Esteira produz o hash-ouro da suíte para a entrada canônica."""
    assert canonical_sha256(GOLDEN_DOC) == GOLDEN_ARTIFACT_SHA256


def test_artifact_sha256_publico_delega_na_serializacao_canonica() -> None:
    """`provenance.artifact_sha256` é a receita canônica com o auto-campo zerado — não uma segunda
    receita. Prova a delegação para QUALQUER documento (não só o de ouro), fixando que a suíte tem
    UMA só forma de hashear."""
    for doc in (GOLDEN_DOC, {"x": 1}, {"artifact_sha256": "antigo", "a": [1, 2]}):
        assert artifact_sha256(doc) == canonical_sha256({**doc, "artifact_sha256": None})


def test_redact_publicado_no_maximo_2_por_ponta() -> None:
    """A redação publicada REAL (keep=2) bate o ouro da suíte, credencial a credencial: pontas
    longas expõem ≤ 2 chars/ponta; um valor curto demais colapsa só no marcador."""
    for entrada, esperado in GOLDEN_REDACT.items():
        assert _redacao_publicada(entrada) == esperado, f"redação publicada divergiu em {entrada!r}"
