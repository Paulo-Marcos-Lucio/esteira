"""ES-01c — achado suprimido deixa de ser descartado em silêncio e passa a sair no relatório.

Antes, `run_all` filtrava achados calados por `# esteira: ignore` / `# zizmor: ignore` e os
jogava fora: o JSON, o SARIF e o console não tinham como distinguir "nada encontrado" de
"encontrado e calado por alguém". Estes testes cobrem os três formatos combinados — JSON
(`suppressed[]` + `summary.suppressed`), SARIF (`suppressions[]` com `kind: inSource`) e
console (rodapé sempre, lista completa só com `--show-suppressed`).
"""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from esteira.checks.engine import scan
from esteira.cli import app
from esteira.report.console import render
from esteira.report.json_report import to_json
from esteira.report.sarif import to_sarif

runner = CliRunner()

# Um achado calado por diretiva escopada (script-injection na linha 7) e um achado aberto
# (secret-in-run na linha 8, sem diretiva) — para provar que a supressão não vaza para o
# achado vizinho e que os dois aparecem nos lugares certos do relatório.
_WORKFLOW = textwrap.dedent("""\
    on: push
    permissions:
      contents: read
    jobs:
      b:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{ github.event.issue.title }}"  # esteira: ignore[script-injection]
          - run: echo "tok=${{ secrets.API_TOKEN }}"
    """)


def _repo(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(_WORKFLOW, encoding="utf-8")
    return tmp_path


def test_achado_suprimido_nao_aparece_em_findings_mas_o_visivel_sim(tmp_path: Path) -> None:
    result = scan(_repo(tmp_path))
    ids_visiveis = {f.check_id for f in result.findings}
    assert "script-injection" not in ids_visiveis
    assert "secret-in-run" in ids_visiveis
    ids_suprimidos = {s.finding.check_id for s in result.suppressed}
    assert ids_suprimidos == {"script-injection"}


def test_json_lista_suprimidos_e_conta_no_summary(tmp_path: Path) -> None:
    doc = json.loads(to_json(scan(_repo(tmp_path))))
    assert doc["summary"]["suppressed"] == 1
    # o total/by_severity do summary continuam falando só do que está ABERTO.
    assert doc["summary"]["total"] == len(doc["findings"])
    assert "script-injection" not in {f["id"] for f in doc["findings"]}
    (suprimido,) = doc["suppressed"]
    assert suprimido["id"] == "script-injection"
    assert "esteira: ignore" in suprimido["justification"]


def test_sarif_marca_suprimido_com_suppressions_insource(tmp_path: Path) -> None:
    doc = json.loads(to_sarif(scan(_repo(tmp_path))))
    resultados = doc["runs"][0]["results"]
    por_regra = {r["ruleId"]: r for r in resultados}
    assert "script-injection" in por_regra  # dismissed, não apagado do SARIF
    assert "secret-in-run" in por_regra
    suprimido = por_regra["script-injection"]
    assert suprimido["suppressions"] == [
        {"kind": "inSource", "justification": suprimido["suppressions"][0]["justification"]}
    ]
    assert "esteira: ignore" in suprimido["suppressions"][0]["justification"]
    assert "suppressions" not in por_regra["secret-in-run"]


def test_console_rodape_conta_suprimidos_sem_listar_por_padrao(tmp_path: Path) -> None:
    console = Console(file=io.StringIO(), width=200)
    render(scan(_repo(tmp_path)), console)
    saida = console.file.getvalue()  # type: ignore[attr-defined]
    assert "1 achado(s) suprimido" in saida
    assert "--show-suppressed" in saida
    assert "esteira: ignore[script-injection]" not in saida  # justificativa não vaza sem a flag


def test_console_show_suppressed_lista_a_justificativa(tmp_path: Path) -> None:
    console = Console(file=io.StringIO(), width=200)
    render(scan(_repo(tmp_path)), console, show_suppressed=True)
    saida = console.file.getvalue()  # type: ignore[attr-defined]
    assert "script-injection" in saida
    assert "esteira: ignore[script-injection]" in saida


def test_cli_show_suppressed_flag(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    sem_flag = runner.invoke(app, ["scan", str(repo), "--fail-on", "none"])
    assert "--show-suppressed" in sem_flag.stdout
    assert "esteira: ignore[script-injection]" not in sem_flag.stdout

    com_flag = runner.invoke(app, ["scan", str(repo), "--fail-on", "none", "--show-suppressed"])
    assert "esteira: ignore[script-injection]" in com_flag.stdout
