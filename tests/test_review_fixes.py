"""Testes de regressão dos bugs achados na revisão adversarial da Esteira.

Cada teste falha na versão anterior ao fix e passa depois — é a prova de que a
correção resolve o defeito específico, não apenas de que "o código roda".
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from esteira.checks.detectors import _EXPR
from esteira.checks.engine import scan
from esteira.cli import app
from esteira.core.models import ScanResult, Severity

runner = CliRunner()


def _scan_text(tmp_path: Path, text: str, name: str = "w.yml") -> ScanResult:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(text, encoding="utf-8")
    return scan(tmp_path)


def _ids(tmp_path: Path, text: str) -> set[str]:
    return {f.check_id for f in _scan_text(tmp_path, text).findings}


# --------------------------------------------------------------------------- #
# detectors.py
# --------------------------------------------------------------------------- #


# HIGH — script-injection marcava a própria mitigação (contexto em env:/with:).
def test_script_injection_ignores_context_in_env(tmp_path: Path) -> None:
    safe = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: echo "$TITLE"
    """)
    assert "script-injection" not in _ids(tmp_path, safe)


def test_script_injection_still_fires_inside_run(tmp_path: Path) -> None:
    vuln = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}"
    """)
    assert "script-injection" in _ids(tmp_path, vuln)


def test_script_injection_block_ends_at_sibling_env_key(tmp_path: Path) -> None:
    # Bloco '- run: |' compacto: a coluna da chave 'run' (não a do '-') delimita o bloco;
    # a chave-irmã 'env:' seguinte não pode continuar "dentro do run" e gerar FP.
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo ok
                env:
                  TITLE: ${{ github.event.issue.title }}
    """)
    assert "script-injection" not in _ids(tmp_path, wf)


# HIGH — self-hosted em block-list (runs-on:\n  - self-hosted) passava batido.
def test_self_hosted_detected_in_block_list_form(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on:
              - self-hosted
              - linux
            steps:
              - run: echo hi
    """)
    assert "self-hosted-runner" in _ids(tmp_path, wf)


# HIGH — checkout sob PPT: substring "head"/"github.event" gerava CRITICAL falso.
@pytest.mark.parametrize(
    "safe_ref",
    ["refs/heads/main", "${{ github.event.repository.default_branch }}", "${{ github.sha }}"],
)
def test_ppt_checkout_ignores_base_refs(tmp_path: Path, safe_ref: str) -> None:
    wf = textwrap.dedent(f"""\
        on: pull_request_target
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: {safe_ref}
    """)
    assert "pull-request-target-checkout" not in _ids(tmp_path, wf)


def test_ppt_checkout_flags_pr_head(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
    """)
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


# MED — o finding deve apontar para o ref ofensor, não para o 1º checkout do arquivo.
def test_ppt_checkout_line_points_to_offending_ref(tmp_path: Path) -> None:
    text = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.head_ref }}
    """)
    findings = [
        f
        for f in _scan_text(tmp_path, text).findings
        if f.check_id == "pull-request-target-checkout"
    ]
    assert len(findings) == 1
    offending = text.splitlines()[findings[0].line - 1]
    assert offending.strip().startswith("ref:")


# MED — curl|bash com sudo com flags / zsh / |& era falso-negativo.
@pytest.mark.parametrize(
    "cmd",
    [
        "curl -fsSL https://x.invalid/i.sh | sudo -E bash",
        "wget -qO- https://x.invalid/i.sh |& zsh",
        "curl https://x.invalid/i.sh | sudo bash",
    ],
)
def test_curl_pipe_shell_variants(tmp_path: Path, cmd: str) -> None:
    wf = textwrap.dedent(f"""\
        on: push
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: {cmd}
    """)
    assert "curl-pipe-shell" in _ids(tmp_path, wf)


# MED — step comentado não pode gerar finding (e quebrar o CI de quem usa a Esteira).
def test_commented_out_step_is_ignored(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              # - uses: some-org/evil-action@v1
              - run: echo ok
    """)
    assert "unpinned-action-thirdparty" not in _ids(tmp_path, wf)


# MED — _EXPR precisa ser linear (sem backtracking catastrófico com .*?).
def test_expr_regex_has_no_catastrophic_backtracking() -> None:
    pathological = "${{ " * 2000  # muitas aberturas, nenhum fechamento
    assert _EXPR.findall(pathological) == []
    assert _EXPR.findall("echo ${{ github.head_ref }}") == [" github.head_ref "]


# LOW — 'permissions:' nulo tranca o token (seguro) e não é ausência de permissões.
def test_null_permissions_is_not_missing(tmp_path: Path) -> None:
    wf = "on: push\npermissions:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert "missing-permissions" not in _ids(tmp_path, wf)


def test_absent_permissions_is_still_flagged(tmp_path: Path) -> None:
    wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert "missing-permissions" in _ids(tmp_path, wf)


# LOW — em flow-style, o ref capturava o '}' e o SHA virava "unpinned".
def test_flowstyle_sha_pinned_is_not_flagged(tmp_path: Path) -> None:
    sha = "b4ffde65f46336ab88eb53be808477a3936bae11"
    wf = (
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        f"    steps: [{{uses: actions/checkout@{sha}}}]\n"
    )
    ids = _ids(tmp_path, wf)
    assert "unpinned-action-firstparty" not in ids
    assert "unpinned-action-thirdparty" not in ids


def test_flowstyle_tag_pinned_is_flagged(tmp_path: Path) -> None:
    wf = (
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps: [{uses: some-org/act@v1}]\n"
    )
    assert "unpinned-action-thirdparty" in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# loader.py + run_all — YAML inválido não pode ser engolido em silêncio.
# --------------------------------------------------------------------------- #


def test_invalid_yaml_emits_finding(tmp_path: Path) -> None:
    bad = "on: push\njobs: [este flow nunca fecha\n"
    assert "invalid-yaml" in _ids(tmp_path, bad)


# --------------------------------------------------------------------------- #
# cli.py — fail-closed, validação de filtros e --output.
# --------------------------------------------------------------------------- #


def test_scan_no_workflows_avisa_mas_nao_reprova(tmp_path: Path) -> None:
    # Caminho que EXISTE e não tem workflow: é fato legítimo (subprojeto de monorepo sem CI),
    # não erro de uso — avisa em stderr e sai 0. O caso perigoso de verdade, o caminho
    # digitado errado, é barrado pelo teste abaixo, com exit 2.
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Nenhum workflow encontrado" in result.output


def test_scan_nonexistent_path_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "nao-existe")])
    assert result.exit_code == 2


def test_scan_unknown_only_exits_2(vuln_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(vuln_repo), "--only", "nao-existe"])
    assert result.exit_code == 2


def test_scan_console_with_output_is_rejected(vuln_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "saida.txt"
    result = runner.invoke(app, ["scan", str(vuln_repo), "-o", str(out)])
    assert result.exit_code == 2
    assert not out.exists()


# =========================================================================== #
# 2ª rodada adversarial (workflow de 20 agentes) — checagens agora ESTRUTURAIS.
# =========================================================================== #

_STEPS = "on: {trigger}\npermissions: {{}}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"


def _one_step_run(cmd: str, *, trigger: str = "push") -> str:
    return _STEPS.format(trigger=trigger) + f"      - run: {cmd}\n"


# C1 — _EXPR não casava format('{0}',...): bypass silencioso de script-injection/secret.
def test_expr_matches_format_placeholders() -> None:
    got = _EXPR.findall("${{ format('branch {0}', github.head_ref) }}")
    assert got and "github.head_ref" in got[0]


def test_script_injection_detects_format_wrapper(tmp_path: Path) -> None:
    wf = _one_step_run("echo \"${{ format('{0}', github.event.issue.title) }}\"")
    assert "script-injection" in _ids(tmp_path, wf)


# C2 — plain scalar de run: (valor na próxima linha / multiline) era cegado.
def test_script_injection_run_value_on_next_line(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run:
                  echo "${{ github.event.issue.title }}"
    """)
    assert "script-injection" in _ids(tmp_path, wf)


def test_script_injection_plain_multiline_continuation(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo foo &&
                  echo "${{ github.event.issue.title }}"
    """)
    assert "script-injection" in _ids(tmp_path, wf)


# C3 — injeção em linha de comentário DENTRO de run:| (FN) vs comentário YAML inline (FP).
def test_script_injection_in_run_comment_line(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  # deploy ${{ github.event.issue.title }}
                  echo ok
    """)
    assert "script-injection" in _ids(tmp_path, wf)


def test_no_script_injection_from_yaml_inline_comment(tmp_path: Path) -> None:
    wf = _one_step_run("echo ok  # ${{ github.head_ref }}")
    assert "script-injection" not in _ids(tmp_path, wf)


# C4 — permissões a nível de job nunca eram avaliadas / suprimiam missing-permissions.
def test_job_level_write_all_is_flagged(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - run: echo hi
    """)
    assert "broad-permissions" in _ids(tmp_path, wf)


def test_mixed_job_permissions_still_flags_missing(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: echo a
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo b
    """)
    assert "missing-permissions" in _ids(tmp_path, wf)


# C5 — chave coercida para bool (YAML 1.1 'on:') crashava sorted() e abortava a varredura.
def test_permissions_with_bool_key_does_not_abort_scan(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "a.yml").write_text(
        "on: push\npermissions:\n  contents: write\n  on: write\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n",
        encoding="utf-8",
    )
    (wf_dir / "b.yml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: self-hosted\n    steps: []\n", encoding="utf-8"
    )
    ids = {f.check_id for f in scan(tmp_path).findings}
    assert "self-hosted-runner" in ids  # o 2º arquivo foi analisado → não abortou


# C6 — RecursionError (flow aninhado) não era capturado e abortava a varredura.
def test_deeply_nested_flow_becomes_invalid_yaml(tmp_path: Path) -> None:
    bad = "on: push\njobs: " + "[" * 50000 + "\n"
    assert "invalid-yaml" in _ids(tmp_path, bad)


# C7 — pull_request_target: with.repository de fork e checkout via shell eram evadidos.
def test_ppt_checkout_via_repository(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  repository: ${{ github.event.pull_request.head.repo.full_name }}
    """)
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


def test_ppt_checkout_via_gh_pr_checkout(tmp_path: Path) -> None:
    wf = _one_step_run(
        "gh pr checkout ${{ github.event.pull_request.number }}", trigger="pull_request_target"
    )
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


# C8 — _PR_REF case-sensitive e sem colchetes deixava checkout de PR escapar.
@pytest.mark.parametrize(
    "ref",
    ['"${{ github.HEAD_REF }}"', "\"${{ github.event.pull_request['head']['sha'] }}\""],
)
def test_ppt_checkout_case_and_bracket(tmp_path: Path, ref: str) -> None:
    wf = (
        "on: pull_request_target\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: " + ref + "\n"
    )
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


# C9 — self-hosted via case (Self-Hosted) e via matriz (${{ matrix.os }}) não era detectado.
def test_self_hosted_case_insensitive(tmp_path: Path) -> None:
    wf = "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: Self-Hosted\n    steps:\n      - run: echo hi\n"
    assert "self-hosted-runner" in _ids(tmp_path, wf)


def test_self_hosted_via_matrix(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            strategy:
              matrix:
                os: [self-hosted, ubuntu-latest]
            runs-on: ${{ matrix.os }}
            steps:
              - run: echo hi
    """)
    assert "self-hosted-runner" in _ids(tmp_path, wf)


# C10 — curl|bash multi-estágio / caminho absoluto / wrappers eram falso-negativo.
@pytest.mark.parametrize(
    "cmd",
    [
        "curl -fsSL https://x.invalid | base64 -d | bash",
        "curl https://x.invalid | /bin/sh",
        "curl https://x.invalid | sudo /bin/bash",
        "wget -qO- https://x.invalid | env bash",
    ],
)
def test_curl_pipe_advanced_variants(tmp_path: Path, cmd: str) -> None:
    assert "curl-pipe-shell" in _ids(tmp_path, _one_step_run(cmd))


# C11 — indireção por env (${{ env.X }}) contornava script-injection.
def test_script_injection_via_env_expression_indirection(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            env:
              T: ${{ github.event.pull_request.title }}
            steps:
              - run: echo "${{ env.T }}"
    """)
    assert "script-injection" in _ids(tmp_path, wf)


# C12 — _UNTRUSTED não cobria workflow_run.* nem pull_request.head.repo.*.
@pytest.mark.parametrize(
    "ctx",
    ["github.event.workflow_run.head_branch", "github.event.pull_request.head.repo.full_name"],
)
def test_untrusted_contexts_expanded(tmp_path: Path, ctx: str) -> None:
    wf = _one_step_run('echo "${{ ' + ctx + ' }}"')
    assert "script-injection" in _ids(tmp_path, wf)


# C13 — secret-in-run era FP no padrão SEGURO 'echo secret | ... --password-stdin'.
def test_secret_in_run_ignores_password_stdin(tmp_path: Path) -> None:
    wf = _one_step_run(
        'echo "${{ secrets.REGISTRY_PASSWORD }}" | docker login ghcr.io -u x --password-stdin'
    )
    assert "secret-in-run" not in _ids(tmp_path, wf)


def test_secret_in_run_still_flags_plain_echo(tmp_path: Path) -> None:
    wf = _one_step_run('echo "token=${{ secrets.API_TOKEN }}"')
    assert "secret-in-run" in _ids(tmp_path, wf)


# C14 — invalid-yaml era MEDIUM e passava no --fail-on high (fail-open).
def test_invalid_yaml_fails_ci_by_default(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "bad.yml").write_text("on: push\njobs: [nao fecha\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1


# C17 — script-injection disparava em subcampo seguro (commits[0].id = SHA).
def test_commits_id_is_not_flagged(tmp_path: Path) -> None:
    wf = _one_step_run('git tag "build-${{ github.event.commits[0].id }}"')
    assert "script-injection" not in _ids(tmp_path, wf)


def test_commits_message_is_flagged(tmp_path: Path) -> None:
    wf = _one_step_run('echo "${{ github.event.commits[0].message }}"')
    assert "script-injection" in _ids(tmp_path, wf)


# C19 — 'uses:' em texto de shell gerava FP; SHA maiúsculo era dado como não-pinado.
def test_uses_in_shell_text_is_not_flagged(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "exemplo - uses: actions/checkout@v3"
    """)
    ids = _ids(tmp_path, wf)
    assert "invalid-yaml" not in ids  # o YAML é válido: o 'uses:' está só no texto do shell
    assert "unpinned-action-firstparty" not in ids
    assert "unpinned-action-thirdparty" not in ids


def test_uppercase_sha_is_pinned(tmp_path: Path) -> None:
    sha = "B4FFDE65F46336AB88EB53BE808477A3936BAE11"
    wf = (
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - uses: actions/checkout@{sha}\n"
    )
    assert "unpinned-action-firstparty" not in _ids(tmp_path, wf)


# C20 — curl|bash num comentário YAML inline (comando real inofensivo) gerava FP.
def test_curl_pipe_ignores_inline_shell_comment(tmp_path: Path) -> None:
    wf = _one_step_run("make build  # legacy curl https://x.invalid | bash")
    assert "curl-pipe-shell" not in _ids(tmp_path, wf)


# C21 — 'steps' declarado como mapa único ainda deve ser analisado.
def test_steps_as_mapping_still_scanned(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              uses: actions/checkout@v4
              with:
                ref: ${{ github.head_ref }}
    """)
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


# =========================================================================== #
# 3ª rodada adversarial (workflow focado na reescrita) — bypasses/FN/FP finos.
# =========================================================================== #


# C1 — notação por colchete/aspas era bypass canônico da checagem CRITICAL.
@pytest.mark.parametrize(
    "expr",
    ["github.event.issue['title']", "github['event']['issue']['title']"],
)
def test_bracket_notation_injection_is_detected(tmp_path: Path, expr: str) -> None:
    wf = _one_step_run("echo ${{ " + expr + " }}", trigger="issues")
    assert "script-injection" in _ids(tmp_path, wf)


# C2 — o sink de execução `with.script` do actions/github-script não era varrido.
def test_github_script_injection_is_detected(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: issues
        permissions: {}
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    const t = "${{ github.event.issue.title }}";
                    await github.rest.issues.createComment({issue_number: 1, body: t});
    """)
    assert "script-injection" in _ids(tmp_path, wf)


# C3 — job id não-string (2024, 'on', null) estourava TypeError → invalid-yaml falso + fail-open.
def test_non_string_job_id_does_not_crash(tmp_path: Path) -> None:
    wf = "on: push\njobs:\n  2024:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n"
    ids = _ids(tmp_path, wf)
    assert "invalid-yaml" not in ids  # o YAML é válido
    assert "self-hosted-runner" in ids  # e os findings reais não somem


# C4 — checkout de PR sob PPT via indireção de env não era detectado.
def test_ppt_checkout_via_env_indirection(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        env:
          PRREF: 'refs/pull/${{ github.event.pull_request.number }}/merge'
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: '${{ env.PRREF }}'
    """)
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


# C5 — `git fetch ... base.ref` (branch-base confiável) era falso-positivo.
def test_git_fetch_base_ref_is_not_flagged(tmp_path: Path) -> None:
    wf = _one_step_run(
        "git fetch origin ${{ github.event.pull_request.base.ref }}",
        trigger="pull_request_target",
    )
    assert "pull-request-target-checkout" not in _ids(tmp_path, wf)


# C6 — self-hosted contribuído só por strategy.matrix.include[] não era enumerado.
def test_self_hosted_via_matrix_include(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ${{ matrix.os }}
            strategy:
              matrix:
                os: [ubuntu-latest]
                include:
                  - os: self-hosted
            steps:
              - run: echo hi
    """)
    assert "self-hosted-runner" in _ids(tmp_path, wf)


# C7 — subcampos injetáveis de workflow_run estavam ausentes de _UNTRUSTED.
@pytest.mark.parametrize(
    "ctx",
    [
        "github.event.workflow_run.head_commit.author.email",
        "github.event.workflow_run.display_title",
    ],
)
def test_workflow_run_subfields_detected(tmp_path: Path, ctx: str) -> None:
    wf = _one_step_run("echo ${{ " + ctx + " }}", trigger="workflow_run")
    assert "script-injection" in _ids(tmp_path, wf)


# C9 — dois checkouts idênticos em jobs diferentes colapsavam num finding só.
def test_ppt_two_jobs_produce_two_distinct_findings(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.head_ref }}
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.head_ref }}
    """)
    findings = [
        f for f in _scan_text(tmp_path, wf).findings if f.check_id == "pull-request-target-checkout"
    ]
    assert len(findings) == 2
    assert len({f.line for f in findings}) == 2  # linhas distintas, sem colapso


# C10 — wrappers time/nice/nohup/xargs/timeout/stdbuf antes do shell escapavam.
@pytest.mark.parametrize("wrapper", ["time bash", "nohup sh", "timeout 5 bash", "xargs bash"])
def test_curl_pipe_wrapper_variants(tmp_path: Path, wrapper: str) -> None:
    wf = _one_step_run(f"curl https://x.invalid | {wrapper}")
    assert "curl-pipe-shell" in _ids(tmp_path, wf)


# C11 — indireção de env encadeada (multi-hop) não era seguida.
def test_script_injection_via_chained_env(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: issues
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              A: '${{ github.event.issue.title }}'
              B: '${{ env.A }}'
            steps:
              - run: echo ${{ env.B }}
    """)
    assert "script-injection" in _ids(tmp_path, wf)


# C13 — composite action (runs.steps) tinha as checagens puladas + missing-permissions falso.
def test_composite_action_is_scanned(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        runs:
          using: composite
          steps:
            - run: echo "${{ github.event.issue.title }}"
            - uses: some-org/evil@v1
    """)
    ids = _ids(tmp_path, wf)
    assert "script-injection" in ids
    assert "unpinned-action-thirdparty" in ids
    assert "missing-permissions" not in ids  # arquivo de action não tem 'permissions'


# C14 — curl|bash dentro de string ecoada (texto de ajuda) era falso-positivo.
def test_curl_pipe_in_echoed_string_is_not_flagged(tmp_path: Path) -> None:
    wf = _one_step_run('echo "To install run curl https://get.foo | bash"')
    assert "curl-pipe-shell" not in _ids(tmp_path, wf)


# C15 — format() com chaves escapadas {{ }} quebrava o _EXPR e escondia a injeção.
def test_script_injection_through_format_escaped_braces(tmp_path: Path) -> None:
    wf = _one_step_run(
        "echo ${{ format('{{ {0} }}', github.event.issue.title) }}", trigger="issues"
    )
    assert "script-injection" in _ids(tmp_path, wf)


# =========================================================================== #
# Bateria de execução real (2026-07-22) em 8 repos públicos — calibração de
# campo achada na auditoria adversarial multidimensional.
# =========================================================================== #


def _findings(tmp_path: Path, text: str) -> list:
    return _scan_text(tmp_path, text).findings


# E1+E4 — reusable workflow: severidade LOW (não thirdparty HIGH) e cada job em sua linha.
def test_reusable_workflows_low_and_distinct_lines(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          a:
            uses: some-org/repo/.github/workflows/ci.yml@main
          b:
            uses: some-org/repo/.github/workflows/ci.yml@main
    """)
    ru = [f for f in _findings(tmp_path, wf) if f.check_id == "unpinned-reusable-workflow"]
    assert len(ru) == 2
    assert all(f.severity is Severity.LOW for f in ru)
    assert len({f.line for f in ru}) == 2  # linhas distintas (5 e 7), sem colar na 1ª
    assert "unpinned-action-thirdparty" not in {f.check_id for f in _findings(tmp_path, wf)}


def test_thirdparty_action_still_high(tmp_path: Path) -> None:
    wf = _STEPS.format(trigger="push") + "      - uses: some-org/evil-action@v1\n"
    third = [f for f in _findings(tmp_path, wf) if f.check_id == "unpinned-action-thirdparty"]
    assert third and third[0].severity is Severity.HIGH


# E2+E5 — dangerous-trigger agora é LOW e cobre issue_comment (gatilho de pwn-request).
def test_dangerous_trigger_is_low(tmp_path: Path) -> None:
    wf = _one_step_run("echo hi", trigger="pull_request_target")
    dt = [f for f in _findings(tmp_path, wf) if f.check_id == "dangerous-trigger"]
    assert dt and dt[0].severity is Severity.LOW


def test_issue_comment_is_a_dangerous_trigger(tmp_path: Path) -> None:
    wf = _one_step_run("echo hi", trigger="issue_comment")
    assert "dangerous-trigger" in _ids(tmp_path, wf)


# E3 — supressão inline '# zizmor: ignore' e '# esteira: ignore' é respeitada.
def test_inline_suppression_is_honored(tmp_path: Path) -> None:
    z = "on: pull_request_target  # zizmor: ignore[dangerous-triggers]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert "dangerous-trigger" not in _ids(tmp_path, z)
    e = "on: pull_request_target  # esteira: ignore\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert "dangerous-trigger" not in _ids(tmp_path, e)


# E6 — self-hosted via runner group (transformers usa 'group: amd-mi300-1gpu').
def test_self_hosted_via_runner_group(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on:
              group: amd-mi300-1gpu
            steps:
              - run: echo hi
    """)
    assert "self-hosted-runner" in _ids(tmp_path, wf)


# E7 — reusable workflow (workflow_call) herda permissões do CALLER, não da org.
def test_workflow_call_missing_permissions_message(tmp_path: Path) -> None:
    wf = "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    mp = [f for f in _findings(tmp_path, wf) if f.check_id == "missing-permissions"]
    assert mp and "caller" in mp[0].detail


# E8 — ppt-checkout credita mitigações (persist-credentials:false + sparse-checkout) → HIGH.
def test_ppt_checkout_credits_mitigations(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
                  persist-credentials: false
                  sparse-checkout: docs
    """)
    ppt = [f for f in _findings(tmp_path, wf) if f.check_id == "pull-request-target-checkout"]
    assert ppt and ppt[0].severity is Severity.HIGH  # mitigado, não CRITICAL cego


# Benchmark vs zizmor (2026-07-22): fechando gaps de cobertura de CI/CD.
def test_secrets_inherit_flagged(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          call:
            uses: org/repo/.github/workflows/ci.yml@main
            secrets: inherit
    """)
    assert "secrets-inherit" in _ids(tmp_path, wf)


def test_explicit_secrets_not_flagged(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          call:
            uses: org/repo/.github/workflows/ci.yml@main
            secrets:
              FOO: ${{ secrets.FOO }}
    """)
    assert "secrets-inherit" not in _ids(tmp_path, wf)


def test_unpinned_container_image_flagged(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            container:
              image: node:18
            steps:
              - run: echo hi
    """)
    assert "unpinned-container-image" in _ids(tmp_path, wf)


def test_digest_pinned_image_not_flagged(tmp_path: Path) -> None:
    digest = "a" * 64
    wf = textwrap.dedent(f"""\
        on: push
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            services:
              db:
                image: postgres@sha256:{digest}
            steps:
              - run: echo hi
    """)
    assert "unpinned-container-image" not in _ids(tmp_path, wf)
