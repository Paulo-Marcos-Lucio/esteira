"""ES-04d — `github-env-injection`: escrita suja em `$GITHUB_ENV` sob `pull_request_target`.

`$GITHUB_ENV` não é uma variável, é um ARQUIVO que o runner relê como `nome=valor` por linha.
Citar a variável entre aspas ("$VAR") evita o `script-injection` clássico (a string do shell não
quebra), mas não protege este sink: se o valor carrega uma quebra de linha, o atacante deixa de
só controlar o VALOR e passa a declarar uma variável de ambiente NOVA, com o nome que quiser,
visível a todos os steps seguintes — inclusive actions de terceiros, que leem o `process.env`
inteiro. Sob `pull_request_target` esse job roda com segredos e token de escrita.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from esteira.checks.engine import scan
from esteira.core.models import Finding

_CHECK_ID = "github-env-injection"


def _achados(tmp_path: Path, workflow: str) -> list[Finding]:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "w.yml").write_text(textwrap.dedent(workflow), encoding="utf-8")
    return [f for f in scan(tmp_path).findings if f.check_id == _CHECK_ID]


def test_interpolacao_direta_sob_pull_request_target_e_apontada(tmp_path: Path) -> None:
    workflow = """\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
        """
    assert len(_achados(tmp_path, workflow)) == 1


def test_indirecao_via_env_sob_pull_request_target_e_apontada(tmp_path: Path) -> None:
    """O caso que interessa de verdade: a indireção via `env:` que já evita `script-injection`
    (a linha de `run:` não tem `${{ }}` nenhum) mas continua não-confiável dentro do arquivo
    `$GITHUB_ENV`."""
    workflow = """\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            env:
              TITLE: ${{ github.event.pull_request.title }}
            steps:
              - run: echo "SUBJECT=$TITLE" >> "$GITHUB_ENV"
        """
    achados = _achados(tmp_path, workflow)
    assert len(achados) == 1
    assert "SUBJECT" in (achados[0].evidence or "") + achados[0].detail


@pytest.mark.parametrize("trigger", ["push", "pull_request", "workflow_dispatch", "issues"])
def test_mesma_escrita_fora_de_pull_request_target_nao_dispara(
    tmp_path: Path, trigger: str
) -> None:
    """O risco calibrado aqui é a ESCALADA de privilégio de `pull_request_target` (segredos +
    token de escrita). Fora dele o padrão não some — outras checagens (`secret-in-run`,
    `script-injection`) continuam cobrindo o que lhes cabe — mas esta regra não repete o alarme."""
    workflow = f"""\
        on: {trigger}
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            env:
              TITLE: ${{{{ github.event.pull_request.title }}}}
            steps:
              - run: echo "SUBJECT=$TITLE" >> "$GITHUB_ENV"
        """
    assert _achados(tmp_path, workflow) == []


def test_valor_confiavel_nao_dispara_falso_positivo(tmp_path: Path) -> None:
    """`$GITHUB_ENV` sob `pull_request_target` é rotina para valor que a própria automação
    calcula (SHA do repo, timestamp, `github.run_id`) — sem contexto do atacante, não há o que
    injetar, e a regra não deve gritar contra o padrão são."""
    workflow = """\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "RUN_ID=${{ github.run_id }}" >> "$GITHUB_ENV"
        """
    assert _achados(tmp_path, workflow) == []


def test_escrita_em_github_output_nao_e_github_env_injection(tmp_path: Path) -> None:
    """Sink distinto: `$GITHUB_OUTPUT` tem modelo de risco próprio (taint de output de step,
    já coberto por `script-injection`) e não é o que esta regra mede."""
    workflow = """\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            env:
              TITLE: ${{ github.event.pull_request.title }}
            steps:
              - id: s
                run: echo "subject=$TITLE" >> "$GITHUB_OUTPUT"
        """
    assert _achados(tmp_path, workflow) == []
