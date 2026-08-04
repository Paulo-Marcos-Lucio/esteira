"""P2-03 — `secret-in-run` contra o caso real reproduzido no fork `iac-scanner`.

O bloco auditado (`.github/workflows/nightly-e2e.yml`, linhas 57-58) é este:

    [ -n "${{ secrets.OPENAI_API_KEY }}" ] || { echo "::warning::OPENAI_API_KEY not set"; exit 0; }
    echo "OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }}" >> $GITHUB_ENV

A ferramenta acertava o arquivo e errava as duas linhas ao mesmo tempo:

- apontava a linha 57 dizendo "um segredo é impresso num comando que escreve no log do job".
  Falso: o `echo` dali imprime `::warning::OPENAI_API_KEY not set` — texto sem segredo nenhum.
  O `${{ secrets… }}` está no `[ -n … ]`, que é OUTRO comando da mesma linha;
- e ficava calada na linha 58, que é onde há risco de verdade. Ali o segredo também não vai
  para o log (o `>>` grava em arquivo, e o GitHub ainda mascara segredo no log): ele passa a
  existir no AMBIENTE de todos os steps seguintes do job, inclusive actions de terceiros que
  leem `process.env` inteiro.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from esteira.checks.engine import scan
from esteira.core.models import Finding

_GUARDA_IAC = (
    '[ -n "${{ secrets.OPENAI_API_KEY }}" ] || '
    '{ echo "::warning::OPENAI_API_KEY not set — skipping"; exit 0; }'
)


def _achados(tmp_path: Path, run: str) -> list[Finding]:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "n.yml").write_text(
        textwrap.dedent(f"""\
        on: push
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: {run}
        """),
        encoding="utf-8",
    )
    return [f for f in scan(tmp_path).findings if f.check_id == "secret-in-run"]


@pytest.mark.parametrize(
    "run",
    [
        _GUARDA_IAC,
        '[ -z "${{ secrets.TOKEN }}" ] && echo "faltou configurar o segredo"',
        'test -n "${{ secrets.TOKEN }}"; echo pronto',
    ],
)
def test_echo_que_nao_recebe_o_segredo_nao_e_vazamento(tmp_path: Path, run: str) -> None:
    """`echo` e `${{ secrets.* }}` na MESMA LINHA, em COMANDOS diferentes, não é vazamento.

    O idioma "checa se o segredo está configurado e avisa se não estiver" é banal em pipeline
    de matriz — e a mensagem avisada é, por construção, o NOME da variável, não o valor.
    """
    assert _achados(tmp_path, run) == []


def test_export_para_github_env_e_apontado(tmp_path: Path) -> None:
    """O falso-negativo do outro lado: gravar segredo em `$GITHUB_ENV` é risco de verdade."""
    run = 'echo "OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }}" >> $GITHUB_ENV'
    assert [f.check_id for f in _achados(tmp_path, run)] == ["secret-in-run"]


@pytest.mark.parametrize(
    "run",
    [
        'echo "K=${{ secrets.X }}" >> $GITHUB_ENV',
        'echo "K=${{ secrets.X }}" >> "$GITHUB_ENV"',
        'echo "K=${{ secrets.X }}" >> ${GITHUB_ENV}',
    ],
)
def test_texto_do_achado_de_github_env_fala_de_propagacao_e_nao_afirma_log(
    tmp_path: Path, run: str
) -> None:
    """O texto entregue ao cliente tem de descrever o risco QUE EXISTE.

    Afirmar "vai para o log" ali é errado em dois níveis: o `>>` grava em arquivo, e o GitHub
    mascara segredo no log. Um cliente que confere a afirmação e vê que ela não se sustenta
    descarta o achado inteiro — e o risco real (propagação para os steps seguintes) morre junto.
    """
    (achado,) = _achados(tmp_path, run)
    mensagem = f"{achado.detail} {achado.recommendation} {achado.fix_suggestion or ''}"
    assert "steps seguintes" in mensagem
    assert "log" not in mensagem.lower()


def test_impressao_sem_redirecionamento_continua_falando_de_log(tmp_path: Path) -> None:
    """A correção do texto do caso `$GITHUB_ENV` não pode apagar o texto CERTO do outro caso:
    `echo` sem redirecionamento manda o valor para o stdout, que é o log do job."""
    (achado,) = _achados(tmp_path, 'echo "token=${{ secrets.API_TOKEN }}"')
    assert "log" in achado.detail.lower()


def test_gravacao_em_arquivo_comum_continua_sem_alarme(tmp_path: Path) -> None:
    """Instalar uma chave em disco (`> id_deploy`) é o padrão canônico e seguro — não virou
    achado junto com o `$GITHUB_ENV`."""
    assert _achados(tmp_path, "printf '%s' \"${{ secrets.KEY }}\" > id_deploy") == []
