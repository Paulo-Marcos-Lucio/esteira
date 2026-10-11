"""ES-04e — `unsound-condition`: `if:` de job/step provadamente sempre-verdadeiro.

O `if:` só conta como achado quando é PROVADO sempre-verdadeiro independente do contexto do
run — o literal `true` ou uma autocomparação `X == X` (verdadeira por reflexividade, qualquer
que seja o valor real de X). Qualquer outra coisa fica de fora: o objetivo é zero falso-positivo,
não pegar toda tautologia possível (que exigiria resolver precedência geral de `&&`/`||`, um
problema bem mais difícil e arriscado de errar).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from esteira.checks.engine import scan
from esteira.core.models import Finding

_CHECK_ID = "unsound-condition"


def _achados(tmp_path: Path, jobs_yaml: str, *, trigger: str = "push") -> list[Finding]:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    workflow = f"on: {trigger}\npermissions: {{}}\njobs:\n" + textwrap.indent(jobs_yaml, "  ")
    (wf / "w.yml").write_text(workflow, encoding="utf-8")
    return [f for f in scan(tmp_path).findings if f.check_id == _CHECK_ID]


def test_if_true_no_job_e_apontado(tmp_path: Path) -> None:
    jobs = "deploy:\n  if: true\n  runs-on: ubuntu-latest\n  steps:\n    - run: echo oi\n"
    assert len(_achados(tmp_path, jobs)) == 1


def test_if_true_no_step_e_apontado(tmp_path: Path) -> None:
    jobs = "b:\n  runs-on: ubuntu-latest\n  steps:\n    - if: true\n      run: echo oi\n"
    assert len(_achados(tmp_path, jobs)) == 1


def test_if_com_wrapper_de_expressao_e_apontado(tmp_path: Path) -> None:
    jobs = "deploy:\n  if: ${{ true }}\n  runs-on: ubuntu-latest\n  steps:\n    - run: echo oi\n"
    assert len(_achados(tmp_path, jobs)) == 1


def test_autocomparacao_e_apontada(tmp_path: Path) -> None:
    """Cópia-e-cola clássico: alguém pretendia comparar dois campos diferentes e comparou o
    mesmo campo consigo mesmo — a condição vira sempre-verdadeira, verdadeira por reflexividade
    mesmo sendo um valor dinâmico (o SHA muda a cada PR, mas nunca deixa de ser igual a si)."""
    jobs = (
        "deploy:\n"
        "  if: ${{ github.event.pull_request.base.sha == github.event.pull_request.base.sha }}\n"
        "  runs-on: ubuntu-latest\n  steps:\n    - run: echo oi\n"
    )
    assert len(_achados(tmp_path, jobs)) == 1


@pytest.mark.parametrize(
    "condicao",
    [
        "github.actor == 'dependabot[bot]'",  # é falsifiable-actor-condition, não esta regra
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "success()",
        "github.event.pull_request.base.sha == github.event.pull_request.head.sha",
    ],
)
def test_comparacao_normal_nao_dispara(tmp_path: Path, condicao: str) -> None:
    jobs = f"deploy:\n  if: ${{{{ {condicao} }}}}\n  runs-on: ubuntu-latest\n  steps:\n    - run: echo oi\n"
    assert _achados(tmp_path, jobs) == []


def test_precedencia_de_e_ou_nao_e_lida_como_tautologia(tmp_path: Path) -> None:
    """`&&` tem precedência MENOR que `==` no GitHub Actions: `a && b == a && b` é
    `a && (b == a) && b`, não `(a && b) == (a && b)`. Um split ingênuo em `==` cortaria os dois
    lados como texto idêntico ('a && b') e acusaria tautologia que não existe — a regra tem de
    recusar quando qualquer lado esconde um `&&`/`||` de nível superior fora de parênteses."""
    jobs = "deploy:\n  if: ${{ a && b == a && b }}\n  runs-on: ubuntu-latest\n  steps:\n    - run: echo oi\n"
    assert _achados(tmp_path, jobs) == []


def test_operandos_entre_parenteses_continuam_provaveis(tmp_path: Path) -> None:
    """Com parênteses explícitos a ambiguidade de precedência não existe — `(a && b) == (a &&
    b)` agrupa de verdade, então o mesmo texto nos dois lados volta a ser prova legítima."""
    jobs = (
        "deploy:\n  if: ${{ (a && b) == (a && b) }}\n  runs-on: ubuntu-latest\n"
        "  steps:\n    - run: echo oi\n"
    )
    assert len(_achados(tmp_path, jobs)) == 1


def test_if_false_nao_dispara(tmp_path: Path) -> None:
    jobs = "deploy:\n  if: false\n  runs-on: ubuntu-latest\n  steps:\n    - run: echo oi\n"
    assert _achados(tmp_path, jobs) == []
