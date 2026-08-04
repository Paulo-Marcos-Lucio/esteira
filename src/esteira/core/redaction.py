"""Redação de credencial literal na evidência.

Regra da casa, igual à do Guardião: **o segredo cru nunca sai** — nem para o console, nem para
o JSON entregue ao cliente, nem para o `snippet` do SARIF, que sobe para o GitHub Code Scanning.
A Esteira copiava até 120 caracteres crus da linha do workflow para `evidence`; como a regra
`secret-in-run` existe exatamente para achar linha com segredo, o relatório que denunciava o
vazamento era ele próprio um segundo vazamento — e num arquivo que circula por e-mail.

**Só padrão de credencial conhecido, jamais entropia genérica.** É restrição deliberada:

- `${{ secrets.X }}` é uma REFERÊNCIA, não um valor. Redigir isso destruiria a evidência sem
  proteger coisa nenhuma — e é justamente o que o auditor precisa ler.
- 40 hex é o formato de um pin de action (`actions/checkout@11d5960a…`), o dado mais importante
  da evidência de `unpinned-action-*`. Uma regra de entropia comeria justo essa evidência.

O preço é assumido e está no `bench/README.md`: uma credencial de formato desconhecido (senha
solta, token interno de empresa) **não** é redigida. Contra isso a defesa é não colar segredo
literal no workflow — que é o que a própria ferramenta cobra.
"""

from __future__ import annotations

import re

# Formatos com prefixo/estrutura reconhecível e público. Cada um foi escolhido por ter
# âncora literal — nada aqui casa por "parece aleatório".
_PADROES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),  # GitHub PAT/OAuth/App/refresh
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),  # GitHub fine-grained PAT
    re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),  # Stripe
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
    re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),  # Google OAuth token
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),  # npm
    re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b"),  # PyPI
    re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),  # SendGrid
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),  # GitLab PAT
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),  # DigitalOcean
    # JWT: três segmentos base64url. O 1º é sempre `eyJ` (`{"` em base64), o que dá a âncora
    # literal e evita casar texto qualquer com pontos.
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # Bloco PEM em UMA linha (o `run:` de instalação de chave costuma colar assim).
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]{16,}-----END [A-Z ]*PRIVATE KEY-----"),
)

# Reticência (U+2026), não "...": três pontos são caractere base64url válido e um leitor
# desatento leria "…" como parte do valor. E ela é o que torna a redação IDEMPOTENTE — quebra
# a classe de caracteres de todos os padrões acima, então redigir de novo não come mais nada.
_MASCARA = "…"


def mask(valor: str, *, keep: int = 4) -> str:
    """Mascara um valor preservando as pontas: o prefixo diz QUAL credencial é, o sufixo diz
    QUAL das várias — e nenhum dos dois permite reconstruir o meio.

    Abaixo do limiar não revela nada além da primeira letra: com valor curto, 8 caracteres
    expostos são um pedaço grande demais do espaço de busca.
    """
    n = len(valor)
    if n == 0:
        return ""
    if n <= 2 * keep + 4:
        return valor[0] + _MASCARA
    return f"{valor[:keep]}{_MASCARA}{valor[-keep:]}"


def redact(texto: str | None) -> str | None:
    """Substitui toda credencial de formato conhecido pela forma mascarada. Idempotente."""
    if not texto:
        return texto
    saida = texto
    for padrao in _PADROES:
        saida = padrao.sub(lambda m: mask(m.group(0)), saida)
    return saida


def evidence(linha: str, *, limite: int = 120) -> str:
    """Evidência pronta para o relatório: redige e SÓ ENTÃO trunca.

    A ordem é o ponto. Truncar primeiro cortaria uma credencial que começa no caractere 110 em
    10 caracteres crus — fragmento curto demais para casar com qualquer padrão daqui, e ainda
    assim vazamento (reduz o espaço de busca de quem tiver o resto).
    """
    redigida = redact(linha.strip()) or ""
    return redigida[:limite]
