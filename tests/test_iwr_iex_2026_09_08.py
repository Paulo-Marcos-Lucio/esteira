"""Invariante de CLASSE (property-based) do item `AUD0908-esteira-fp-iwr-iex-sem-ancora`
(auditoria FN/FP 2026-09-08): `iwr|iex`, o equivalente PowerShell de `curl|bash`, só é
`curl-pipe-shell` em POSIÇÃO DE COMANDO — a mesma ancora `_LEAD_CMD` que as sete outras
variantes POSIX de `_curl_pipe_hit` já usam.

Antes do fix, `_IWR_IEX` era a única das oito sem esse prefixo: a sequência disparava em
qualquer posição da linha, inclusive dentro do argumento entre aspas de um comando de
impressão (echo/printf/Write-Host/Write-Output) — o mesmo falso-positivo que C14
(`tests/test_review_fixes.py`) fechou para `curl|bash`, nunca espelhado para a forma
PowerShell. A correção ataca a classe: qualquer combinação de baixador/executor/impressor
deixa de disparar fora de posição de comando, e continua disparando em qualquer posição de
comando real (início de linha, ou depois de `;`/`&`/`|`/`` ` ``/`(`).
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from esteira.checks.detectors import _curl_pipe_hit

_BAIXADORES = ("iwr", "irm", "curl", "wget", "invoke-webrequest", "invoke-restmethod")
_EXECUTORES = ("iex", "invoke-expression")
_IMPRESSORES = ("echo", "printf", "Write-Host", "Write-Output")
_LEADS_DE_COMANDO = ("", "\n", ";", "&", "|", "`", "(")


def _par(baixador: str, executor: str, caixa_alta: bool) -> str:
    par = f"{baixador} -useb https://example.invalid/install.ps1 | {executor}"
    return par.upper() if caixa_alta else par


@given(
    baixador=st.sampled_from(_BAIXADORES),
    executor=st.sampled_from(_EXECUTORES),
    impressor=st.sampled_from(_IMPRESSORES),
    caixa_alta=st.booleans(),
)
def test_iwr_iex_dentro_de_literal_impresso_nunca_dispara(
    baixador: str, executor: str, impressor: str, caixa_alta: bool
) -> None:
    """FP-classe: a sequência só existe dentro do argumento entre aspas de um comando de
    impressão (texto de ajuda/documentação), nunca em posição de comando — e por isso nunca
    pode virar curl-pipe-shell, espelhando o que C14 já garante para `curl|bash`."""
    par = _par(baixador, executor, caixa_alta)
    linha = f'{impressor} "To install, run: {par}"'
    assert not _curl_pipe_hit(linha)


@given(
    baixador=st.sampled_from(_BAIXADORES),
    executor=st.sampled_from(_EXECUTORES),
    caixa_alta=st.booleans(),
    lead=st.sampled_from(_LEADS_DE_COMANDO),
)
def test_iwr_iex_em_posicao_de_comando_sempre_dispara(
    baixador: str, executor: str, caixa_alta: bool, lead: str
) -> None:
    """TP-classe: a mesma sequência em POSIÇÃO DE COMANDO real continua disparando — o fix
    não pode fechar o falso-positivo junto com o caso real (Chocolatey: `iwr ... | iex`)."""
    par = _par(baixador, executor, caixa_alta)
    linha = f"{lead} {par}" if lead else par
    assert _curl_pipe_hit(linha)
