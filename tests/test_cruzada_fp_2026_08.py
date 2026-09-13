"""Invariantes das correções de FALSO POSITIVO da auditoria cruzada (2026-08-28/29).

Cada teste ataca a CLASSE. Os FP de secret-in-run/script-injection eram os piores: gritavam
"vazamento de segredo" / "injeção crítica" onde não havia — o que faz o cliente descartar o
laudo inteiro (e junto o achado real).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from esteira.checks.engine import scan


def _ids(tmp_path: Path, text: str) -> set[str]:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(textwrap.dedent(text), encoding="utf-8")
    return {f.check_id for f in scan(tmp_path).findings}


def _run(cmd: str) -> str:
    return f"""\
        on: push
        permissions: {{}}
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: {cmd}
    """


# ---- secret-in-run: masking, pipe e booleano não são vazamento ----
def test_add_mask_nao_e_vazamento(tmp_path: Path) -> None:
    assert "secret-in-run" not in _ids(tmp_path, _run('echo "::add-mask::${{ secrets.API_KEY }}"'))


def test_pipe_a_consumidor_que_nao_reemite_nao_vai_ao_log(tmp_path: Path) -> None:
    # Invariante REDUZIDO (era "echo pipado não vai ao log", classe FALSA — vide a contraprova
    # abaixo `| tee /dev/stderr`). O verdadeiro é: pipe a um consumidor que NÃO reemite o stdin ao
    # stdout (transforma/grava/consome) não leva o segredo ao log (FP 17).
    for cmd in (
        'echo "${{ secrets.KUBECONFIG_B64 }}" | base64 -d > "$HOME/.kube/config"',
        "printf '%s' \"${{ secrets.GPG_KEY }}\" | gpg --batch --import",
        'echo -n "${{ secrets.SA_JSON }}" | jq -r .project_id',
    ):
        assert "secret-in-run" not in _ids(tmp_path, _run(cmd)), cmd


def test_pipe_ou_redirect_a_sink_de_log_vaza(tmp_path: Path) -> None:  # contraprova positiva
    # A CLASSE que o invariante antigo cristalizava como segura é, na verdade, vazamento: `tee`
    # copia o stdin para o stdout, `cat` reemite, e `/dev/stderr|stdout`/`/proc/self/fd/1` SÃO o
    # log do job — não "arquivo seguro". Todos DEVEM virar achado.
    for cmd in (
        'echo "token=${{ secrets.API_KEY }}" | tee /dev/stderr',
        'echo "${{ secrets.API_KEY }}" | tee leak.txt',
        'echo "${{ secrets.API_KEY }}" | cat',
        'echo "${{ secrets.API_KEY }}" > /dev/stderr',
        'echo "${{ secrets.API_KEY }}" > /proc/self/fd/1',
    ):
        assert "secret-in-run" in _ids(tmp_path, _run(cmd)), cmd


def test_secret_em_comparacao_booleana_nao_vaza(tmp_path: Path) -> None:
    cmd = "echo \"presente: ${{ secrets.DEPLOY_KEY != '' }}\""
    assert "secret-in-run" not in _ids(tmp_path, _run(cmd))


def test_echo_direto_do_segredo_ainda_vaza(tmp_path: Path) -> None:  # contraprova
    assert "secret-in-run" in _ids(tmp_path, _run('echo "chave=${{ secrets.API_KEY }}"'))


# ---- script-injection: expressão booleana não é injetável ----
def test_funcao_booleana_nao_e_injecao(tmp_path: Path) -> None:
    cmd = "echo ${{ contains(github.event.pull_request.title, '[skip ci]') }}"
    assert "script-injection" not in _ids(tmp_path, _run(cmd))


def test_contexto_nao_confiavel_cru_ainda_e_injecao(tmp_path: Path) -> None:  # contraprova
    cmd = "echo ${{ github.event.pull_request.title }}"
    assert "script-injection" in _ids(tmp_path, _run(cmd))


# ---- self-hosted: grupo GitHub-hosted vs. self-hosted ----
def test_runner_group_github_hosted_nao_e_self_hosted(tmp_path: Path) -> None:
    wf = """\
        on: push
        permissions: {}
        jobs:
          j:
            runs-on:
              group: ubuntu-runners
            steps:
              - run: echo hi
    """
    assert "self-hosted-runner" not in _ids(tmp_path, wf)


def test_runner_group_de_hardware_segue_self_hosted(tmp_path: Path) -> None:  # contraprova
    wf = """\
        on: push
        permissions: {}
        jobs:
          j:
            runs-on:
              group: amd-mi300-1gpu
            steps:
              - run: echo hi
    """
    assert "self-hosted-runner" in _ids(tmp_path, wf)


# ---- broad-permissions: supressão inline no escopo + job que não herda ----
def test_supressao_inline_na_linha_do_escopo_e_honrada(tmp_path: Path) -> None:
    wf = """\
        on: push
        permissions:
          contents: read
          packages: write # zizmor: ignore[excessive-permissions]
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo a
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo b
    """
    assert "broad-permissions" not in _ids(tmp_path, wf)


def test_workflow_write_nao_alarma_se_todo_job_declara_o_seu(tmp_path: Path) -> None:
    wf = """\
        on: push
        permissions:
          packages: write
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: echo a
          b:
            runs-on: ubuntu-latest
            permissions: {}
            steps:
              - run: echo b
    """
    assert "broad-permissions" not in _ids(tmp_path, wf)


def test_workflow_write_herdado_ainda_alarma(tmp_path: Path) -> None:  # contraprova
    wf = """\
        on: push
        permissions:
          packages: write
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo a
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo b
    """
    assert "broad-permissions" in _ids(tmp_path, wf)
