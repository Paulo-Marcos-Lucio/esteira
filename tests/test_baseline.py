"""`esteira baseline gravar` + `esteira scan --baseline` (item ES-03c da fila de cadência).

Critério de aceite: achado presente na baseline sai com `origem='baseline'` e não conta para
`--fail-on`; reindentar o arquivo não move o item. O fingerprint é o MESMO do SARIF
(`report.sarif._fingerprint`, sem o número da linha) — os testes de reindentação afirmam a
mesma invariante que já protege o SARIF, agora atravessando `baseline.gravar`/`aplicar`.
"""

from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from esteira.checks.engine import scan
from esteira.cli import app
from esteira.core import baseline
from esteira.core.models import Severity

runner = CliRunner()

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

_WF_DOIS_ACHADOS = textwrap.dedent("""\
    on: pull_request_target
    permissions: write-all
    jobs:
      b:
        runs-on: self-hosted
        steps:
          - uses: some-org/some-action@v1
          - run: echo "${{ github.event.issue.title }}"
""")


def _escrever(base: Path, texto: str, nome: str = "w.yml") -> Path:
    wf_dir = base / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / nome).write_text(texto, encoding="utf-8")
    return base


def test_gravar_e_aplicar_marca_origem_baseline(tmp_path: Path) -> None:
    repo = _escrever(tmp_path / "repo", _WF_CRITICO)
    baseline_path = tmp_path / "baseline.json"

    antes = scan(repo)
    assert antes.findings and all(f.origem == "scan" for f in antes.findings)

    total = baseline.gravar(baseline_path, antes)
    assert total == len(antes.findings)

    fingerprints = baseline.carregar(baseline_path)
    depois = baseline.aplicar(scan(repo), fingerprints)
    assert depois.findings
    assert all(f.origem == "baseline" for f in depois.findings)


def test_achado_de_baseline_nao_conta_para_max_severity(tmp_path: Path) -> None:
    repo = _escrever(tmp_path / "repo", _WF_CRITICO)
    baseline_path = tmp_path / "baseline.json"
    baseline.gravar(baseline_path, scan(repo))

    resultado = baseline.aplicar(scan(repo), baseline.carregar(baseline_path))
    assert resultado.max_severity() is None


def test_achado_novo_continua_contando_mesmo_com_baseline_de_outro_achado(
    tmp_path: Path,
) -> None:
    """A baseline suprime o que já conhecia, não a checagem inteira: um achado NOVO no mesmo
    repositório ainda tem que reprovar o portão."""
    repo = _escrever(tmp_path / "repo", _WF_CRITICO)
    baseline_path = tmp_path / "baseline.json"
    baseline.gravar(baseline_path, scan(repo))

    # mesmo repositório, mais um arquivo com um achado que a baseline nunca viu
    _escrever(repo, _WF_DOIS_ACHADOS, nome="outro.yml")
    resultado = baseline.aplicar(scan(repo), baseline.carregar(baseline_path))
    origens = {f.origem for f in resultado.findings}
    assert origens == {"scan", "baseline"}
    assert resultado.max_severity() is not None


def test_carregar_baseline_ausente_e_fail_closed(tmp_path: Path) -> None:
    try:
        baseline.carregar(tmp_path / "nao-existe.json")
    except baseline.BaselineInvalida:
        pass
    else:
        raise AssertionError("baseline ausente deveria falhar, não devolver conjunto vazio")


def test_carregar_baseline_corrompida_e_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{ isto não é json válido", encoding="utf-8")
    try:
        baseline.carregar(path)
    except baseline.BaselineInvalida:
        pass
    else:
        raise AssertionError("baseline corrompida deveria falhar, não devolver conjunto vazio")


def test_carregar_baseline_schema_desconhecido_e_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"schema": "outra-coisa/1", "fingerprints": []}), encoding="utf-8")
    try:
        baseline.carregar(path)
    except baseline.BaselineInvalida:
        pass
    else:
        raise AssertionError("schema desconhecido deveria falhar, não devolver conjunto vazio")


def test_cli_baseline_gravar_depois_scan_fica_verde(tmp_path: Path) -> None:
    repo = _escrever(tmp_path / "repo", _WF_CRITICO)
    baseline_path = tmp_path / "baseline.json"

    sem_baseline = runner.invoke(app, ["scan", str(repo)])
    assert sem_baseline.exit_code == 1

    gravou = runner.invoke(app, ["baseline", "gravar", str(repo), "-o", str(baseline_path)])
    assert gravou.exit_code == 0
    assert baseline_path.exists()

    com_baseline = runner.invoke(app, ["scan", str(repo), "--baseline", str(baseline_path)])
    assert com_baseline.exit_code == 0

    documento = json.loads(
        runner.invoke(
            app, ["scan", str(repo), "-f", "json", "--baseline", str(baseline_path)]
        ).stdout
    )
    assert documento["findings"]
    assert all(f["origin"] == "baseline" for f in documento["findings"])


def test_cli_scan_baseline_inexistente_falha_fail_closed(tmp_path: Path) -> None:
    repo = _escrever(tmp_path / "repo", _WF_CRITICO)
    resultado = runner.invoke(app, ["scan", str(repo), "--baseline", str(tmp_path / "x.json")])
    assert resultado.exit_code == 2


# =========================================================================== #
# invariante: reindentar o workflow não move o achado para fora da baseline
# =========================================================================== #


@given(linhas_em_branco=st.integers(min_value=0, max_value=8))
def test_reindentar_nao_move_achado_para_fora_da_baseline(linhas_em_branco: int) -> None:
    """INVARIANTE (mesma classe que já protege o SARIF, ver
    `test_fingerprint_nao_muda_quando_o_workflow_e_reindentado`): o fingerprint não usa a
    linha, então nenhuma quantidade de linha em branco na frente do workflow pode reabrir um
    achado que a baseline já conhecia. (Espaço/tab antes de `on:` não é reindentação — é YAML
    inválido, outro achado por construção; por isso a variação aqui é só linha em branco,
    igual ao teste do SARIF que esta invariante estende.)

    Usa `tempfile` (não o fixture `tmp_path`) de propósito: o Hypothesis reexecuta o corpo
    várias vezes por `@given` e um fixture de escopo de função não é resetado entre execuções.
    """
    with tempfile.TemporaryDirectory() as raiz:
        base = Path(raiz)
        original = _escrever(base / "original", _WF_CRITICO)
        baseline_path = base / "baseline.json"
        baseline.gravar(baseline_path, scan(original))

        reindentado = _escrever(base / "reindentado", "\n" * linhas_em_branco + _WF_CRITICO)
        resultado = baseline.aplicar(scan(reindentado), baseline.carregar(baseline_path))
        assert resultado.findings
        assert all(f.origem == "baseline" for f in resultado.findings)
        assert resultado.max_severity() is None


def test_gravar_e_deterministico_mesmo_conteudo_mesma_baseline(tmp_path: Path) -> None:
    """A baseline é comparada por diff de git: gravar duas vezes o mesmo estado não pode
    produzir arquivos diferentes por causa de ordem de iteração não determinística."""
    repo = _escrever(tmp_path / "repo", _WF_DOIS_ACHADOS)
    p1, p2 = tmp_path / "b1.json", tmp_path / "b2.json"
    baseline.gravar(p1, scan(repo))
    baseline.gravar(p2, scan(repo))
    assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")


def test_severidade_maxima_ignora_baseline_mas_relatorio_continua_listando(
    tmp_path: Path,
) -> None:
    """'não conta para --fail-on' não é 'desaparece do relatório': o achado baselineado
    continua em `findings` (ver docstring de `baseline.aplicar`)."""
    repo = _escrever(tmp_path / "repo", _WF_CRITICO)
    baseline_path = tmp_path / "baseline.json"
    antes = scan(repo)
    baseline.gravar(baseline_path, antes)

    depois = baseline.aplicar(scan(repo), baseline.carregar(baseline_path))
    assert len(depois.findings) == len(antes.findings)
    assert depois.max_severity() != Severity.CRITICAL
