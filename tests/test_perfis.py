"""Perfis de severidade por contexto (EST-06): o mesmo workflow, severidades diferentes.

O critério de aceite pede duas coisas: (1) `--perfil {oss-publico,interno}` ajusta
severidade de forma DECLARADA (o perfil aplicado aparece no envelope, e a mudança vem com
justificativa, nunca como número mudo); (2) um teste prova que o MESMO workflow recebe
severidades diferentes conforme o perfil.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from esteira.checks.engine import scan
from esteira.cli import app
from esteira.core.models import Profile, Severity
from esteira.report.console import render
from esteira.report.json_report import to_document
from esteira.report.sarif import to_sarif

runner = CliRunner()


def _self_hosted_severity(root: Path, profile: Profile | None) -> Severity:
    findings = scan(root, profile=profile).findings
    finding = next(f for f in findings if f.check_id == "self-hosted-runner")
    return finding.severity


def test_mesmo_workflow_severidade_diferente_por_perfil(vuln_repo: Path) -> None:
    """O MESMO arquivo (vuln_repo, runner self-hosted) recebe três severidades distintas
    para 'self-hosted-runner' dependendo só do perfil escolhido — nada no arquivo muda."""
    sem_perfil = _self_hosted_severity(vuln_repo, None)
    oss = _self_hosted_severity(vuln_repo, Profile.OSS_PUBLICO)
    interno = _self_hosted_severity(vuln_repo, Profile.INTERNO)
    assert sem_perfil is Severity.MEDIUM  # padrão do catálogo, intocado
    assert oss is Severity.CRITICAL
    assert interno is Severity.LOW
    assert len({sem_perfil, oss, interno}) == 3


def test_sem_perfil_nao_toca_severidade_nem_grava_justificativa(vuln_repo: Path) -> None:
    findings = scan(vuln_repo, profile=None).findings
    finding = next(f for f in findings if f.check_id == "self-hosted-runner")
    assert finding.severity is Severity.MEDIUM
    assert finding.severity_note is None


def test_perfil_ajustado_grava_justificativa_nao_ajustado_fica_mudo(vuln_repo: Path) -> None:
    """A checagem AJUSTADA carrega justificativa; uma checagem que o perfil NÃO toca
    (script-injection não muda em nenhum dos dois perfis) continua com severity_note=None —
    a ausência de nota é tão informativa quanto a presença."""
    findings = scan(vuln_repo, profile=Profile.OSS_PUBLICO).findings
    ajustada = next(f for f in findings if f.check_id == "self-hosted-runner")
    intocada = next(f for f in findings if f.check_id == "script-injection")
    assert ajustada.severity_note is not None
    assert "oss-publico" in ajustada.severity_note
    assert intocada.severity is Severity.CRITICAL  # padrão do catálogo
    assert intocada.severity_note is None


def test_perfil_aparece_no_envelope_json(vuln_repo: Path) -> None:
    doc_sem = to_document(scan(vuln_repo, profile=None))
    doc_oss = to_document(scan(vuln_repo, profile=Profile.OSS_PUBLICO))
    assert doc_sem["profile"] is None
    assert doc_oss["profile"] == "oss-publico"
    ajustada = next(f for f in doc_oss["findings"] if f["id"] == "self-hosted-runner")
    assert ajustada["severity_note"] is not None
    assert ajustada["severity"] == "critical"


def test_perfil_aparece_no_envelope_sarif(vuln_repo: Path) -> None:
    sarif_sem = json.loads(to_sarif(scan(vuln_repo, profile=None)))
    sarif_interno = json.loads(to_sarif(scan(vuln_repo, profile=Profile.INTERNO)))
    assert sarif_sem["runs"][0]["properties"]["profile"] is None
    assert sarif_interno["runs"][0]["properties"]["profile"] == "interno"
    resultados = sarif_interno["runs"][0]["results"]
    ajustado = next(r for r in resultados if r["ruleId"] == "self-hosted-runner")
    assert ajustado["level"] == "note"  # LOW no perfil interno, não mais "warning" (MEDIUM)
    assert "Severidade ajustada" in ajustado["message"]["text"]


def test_dangerous_trigger_e_missing_permissions_tambem_sobem_no_oss_publico(
    vuln_repo: Path,
) -> None:
    findings = {f.check_id: f for f in scan(vuln_repo, profile=Profile.OSS_PUBLICO).findings}
    assert findings["dangerous-trigger"].severity is Severity.MEDIUM  # padrão é LOW


def test_missing_permissions_sobe_no_oss_publico(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "np.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: np\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    sem_perfil = next(f for f in scan(tmp_path).findings if f.check_id == "missing-permissions")
    oss = next(
        f
        for f in scan(tmp_path, profile=Profile.OSS_PUBLICO).findings
        if f.check_id == "missing-permissions"
    )
    assert sem_perfil.severity is Severity.LOW
    assert oss.severity is Severity.MEDIUM
    assert oss.severity_note is not None


def test_cli_perfil_oss_publico(vuln_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(vuln_repo), "-f", "json", "--perfil", "oss-publico"])
    doc = json.loads(result.stdout)
    assert doc["profile"] == "oss-publico"
    achado = next(f for f in doc["findings"] if f["id"] == "self-hosted-runner")
    assert achado["severity"] == "critical"
    assert achado["severity_note"] is not None


def test_cli_perfil_interno(vuln_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(vuln_repo), "-f", "json", "--perfil", "interno"])
    doc = json.loads(result.stdout)
    assert doc["profile"] == "interno"
    achado = next(f for f in doc["findings"] if f["id"] == "self-hosted-runner")
    assert achado["severity"] == "low"


def test_cli_sem_perfil_mantem_catalogo(vuln_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(vuln_repo), "-f", "json"])
    doc = json.loads(result.stdout)
    assert doc["profile"] is None
    achado = next(f for f in doc["findings"] if f["id"] == "self-hosted-runner")
    assert achado["severity"] == "medium"


def test_cli_perfil_invalido_e_erro_de_uso(vuln_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(vuln_repo), "--perfil", "nao-existe"])
    assert result.exit_code == 2


def test_console_mostra_perfil_e_justificativa(vuln_repo: Path) -> None:
    console = Console(file=io.StringIO(), width=200)
    render(scan(vuln_repo, profile=Profile.OSS_PUBLICO), console)
    saida = console.file.getvalue()  # type: ignore[attr-defined]
    assert "Perfil aplicado: oss-publico" in saida
    assert "self-hosted-runner" in saida
    assert "oss-publico" in saida  # a justificativa cita o próprio perfil


def test_console_sem_perfil_nao_mostra_painel(vuln_repo: Path) -> None:
    console = Console(file=io.StringIO(), width=200)
    render(scan(vuln_repo, profile=None), console)
    assert "Perfil aplicado" not in console.file.getvalue()  # type: ignore[attr-defined]
