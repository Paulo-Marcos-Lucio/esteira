"""Redação de credencial literal na evidência.

Regra da casa, igual à do Guardião: **o segredo cru nunca sai** — nem para o console, nem para
o JSON entregue ao cliente, nem para o `snippet` do SARIF, que sobe para o GitHub Code Scanning.
A Esteira copiava até 120 caracteres crus da linha do workflow para `evidence`; como a regra
`secret-in-run` existe exatamente para achar linha com segredo, o relatório que denunciava o
vazamento era ele próprio um segundo vazamento — e num arquivo que circula por e-mail.

**Dois níveis de exposição, como no Guardião.** O console e o JSON de triagem preservam 4+4 (o
prefixo identifica QUAL credencial é, de relance, e nenhum dos dois é publicado). O que SOBE — o
`snippet` do SARIF, legível por quem tiver leitura no repositório — passa por
:func:`para_publicacao` e cai para :data:`KEEP_PUBLICADO` (2+2): 4+4 numa senha de 16 é metade
dela. A garantia deixa de ser "menor que a do Guardião apesar da docstring" e passa a ser a mesma.

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

#: Quanto de cada ponta sobrevive num artefato PUBLICADO — o `snippet` do SARIF, que sobe para o
#: GitHub Code Scanning e é legível por quem tiver leitura no repositório. Com os 4+4 do padrão,
#: uma credencial de 13+ caracteres saía com 8 em claro — metade de uma senha humana de 16
#: (`Nordeste2019!Rj`), e um dicionário recupera o resto. O console e o JSON de TRIAGEM ficam em
#: 4+4 de propósito (o prefixo diz QUAL credencial é, de relance, e eles não são publicados); o
#: que SOBE — o SARIF — encurta para 2+2. É a mesma regra do Guardião (:data:`KEEP_PUBLICADO`).
KEEP_PUBLICADO = 2

# Um token já mascarado tem a forma `<prefixo>…<sufixo>` (ou `<char>…`). Este padrão isola as
# pontas VISÍVEIS de cada token para `para_publicacao` encurtá-las sem tocar no resto da linha.
# A classe exclui `=`, `:`, aspas e espaço de propósito — são os separadores que cercam a
# credencial no YAML (`chave=AKIA…`), e pará-los ali garante que só o prefixo/sufixo da própria
# credencial entra na conta. YAML não contém U+2026, então todo `…` aqui é fronteira nossa.
_TOKEN_MASCARADO = re.compile(r"([A-Za-z0-9._/+~-]*)…([A-Za-z0-9._/+~-]*)")


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


def redact(texto: str | None, *, keep: int = 4) -> str | None:
    """Substitui toda credencial de formato conhecido pela forma mascarada. Idempotente."""
    if not texto:
        return texto
    saida = texto
    for padrao in _PADROES:
        saida = padrao.sub(lambda m: mask(m.group(0), keep=keep), saida)
    return saida


def para_publicacao(evidencia: str | None, *, keep: int = KEEP_PUBLICADO) -> str | None:
    """Reduz as pontas de uma evidência JÁ mascarada (keep=4, para console/JSON de triagem) ao
    teto do artefato PUBLICADO (keep=2, para o `snippet` do SARIF → Code Scanning).

    Monotônico e seguro por construção: só ENCURTA o que o marcador `…` já delimitou — jamais
    revela um caractere a mais do que a máscara de origem —, e é idempotente (reduzir de novo não
    muda nada). Texto sem `…` (uma evidência que não era credencial, como o pin de uma action)
    passa intacto. Fecha a classe: para toda credencial de formato conhecido, o que sobe no SARIF
    expõe no máximo ``keep`` caracteres por ponta.

    **Colapso do valor curto (receita comum da suíte).** O caminho PUBLICADO é mais estrito que o
    de triagem: quando o que sobra das duas pontas VISÍVEIS já cabe numa só (``len(pre)+len(suf)
    <= keep``), o valor mascarado era curto demais para expor um único caractere no artefato que
    SOBE pro Code Scanning — reduz a só o marcador. É o mesmo veredicto do stub canônico
    ``mark if len(x) <= 2*keep`` que os quatro tools da suíte compartilham: uma credencial de
    formato conhecido tem pontas longas (4+4 na triagem → 2+2 aqui, total 4 > keep=2, intacta),
    então só o token minúsculo — que a máscara de triagem já reduzira a ``X…`` — colapsa. Isto NÃO
    revela nada a mais (só a menos) e mantém a idempotência (o marcador sozinho já é ponto fixo).
    """
    if not evidencia:
        return evidencia

    def encurta(m: re.Match[str]) -> str:
        pre = m.group(1)[:keep]
        suf = m.group(2)[-keep:] if m.group(2) else ""
        if len(pre) + len(suf) <= keep:
            return _MASCARA
        return f"{pre}{_MASCARA}{suf}"

    return _TOKEN_MASCARADO.sub(encurta, evidencia)


def evidence(linha: str, *, limite: int = 120) -> str:
    """Evidência pronta para o relatório: redige e SÓ ENTÃO trunca.

    A ordem é o ponto. Truncar primeiro cortaria uma credencial que começa no caractere 110 em
    10 caracteres crus — fragmento curto demais para casar com qualquer padrão daqui, e ainda
    assim vazamento (reduz o espaço de busca de quem tiver o resto).
    """
    redigida = redact(linha.strip()) or ""
    return redigida[:limite]
