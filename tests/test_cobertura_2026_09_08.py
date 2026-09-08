"""Invariante suite-meta (P0) — nota/veredito cego à cobertura.

`--only`/`--skip` reduzem o conjunto de checagens que de fato rodou. Sem declarar isso, uma
varredura recortada e SEM achados certificava o repositório inteiro como limpo (verde falso
eterno no CI de quem roda uma checagem isolada). A causa-raiz é atacada onde a Esteira não
tinha máquina de cobertura: `ScanResult` passa a carregar `checagens_omitidas`/`checagens_total`,
`engine.scan()` os computa a partir do catálogo, o console qualifica o veredito limpo, o JSON
ganha bloco `coverage`, e o portão do CI (`_maybe_fail`, espelhando o Sentinela) não passa
verde quando a cobertura é parcial.

Cada teste é um par anti-mutação: reverter qualquer camada do fix deixa UM deles vermelho.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from rich.console import Console
from typer.testing import CliRunner

from esteira.checks.catalog import CATALOG
from esteira.checks.engine import scan
from esteira.cli import app
from esteira.core.models import Finding, ScanResult, Severity
from esteira.report.console import render
from esteira.report.json_report import to_document

runner = CliRunner()
_CATALOGO = frozenset(CATALOG)


def _safe_repo(base: Path) -> Path:
    """Repositório com workflow endurecido: varredura completa => zero achados."""
    wf = base / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "safe.yml").write_text(
        "name: safe\non:\n  push:\n    branches: [main]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ola\n",
        encoding="utf-8",
    )
    return base


@pytest.fixture(scope="session")
def repo_seguro(tmp_path_factory: pytest.TempPathFactory) -> Path:
    # Sessão (não função): hypothesis reusa o mesmo alvo entre exemplos sem disparar o
    # HealthCheck de fixture função-escopada — e a varredura é read-only.
    return _safe_repo(tmp_path_factory.mktemp("cobertura"))


def _render(result: ScanResult) -> str:
    console = Console(file=io.StringIO(), width=200)
    render(result, console)
    return console.file.getvalue()  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# INVARIANTE central (property-based): para QUALQUER subconjunto de checagens, a cobertura
# declarada é exatamente `catálogo` menos o `ativo`, e `parcial` sse algo ficou de fora.
# --------------------------------------------------------------------------- #
@settings(max_examples=200)
@given(recorte=st.sets(st.sampled_from(sorted(_CATALOGO))))
def test_cobertura_reflete_exatamente_o_recorte(recorte: set[str], repo_seguro: Path) -> None:
    r = scan(repo_seguro, only=recorte or None)
    ativo = recorte if recorte else set(_CATALOGO)
    esperado_omitidas = set(_CATALOGO) - ativo
    assert set(r.checagens_omitidas) == esperado_omitidas
    assert r.cobertura_parcial is bool(esperado_omitidas)
    assert r.checagens_total == len(_CATALOGO)
    assert r.checagens_executadas == len(_CATALOGO) - len(r.checagens_omitidas)


def test_skip_tambem_torna_a_varredura_parcial(repo_seguro: Path) -> None:
    r = scan(repo_seguro, skip={"script-injection"})
    assert r.cobertura_parcial is True
    assert "script-injection" in r.checagens_omitidas
    assert r.checagens_executadas == len(_CATALOGO) - 1


def test_scan_recortado_declara_as_omitidas(repo_seguro: Path) -> None:
    # O caso do achado (--somente uma checagem que não casa o alvo): limpo, MAS parcial.
    r = scan(repo_seguro, only={"script-injection"})
    assert not r.findings
    assert r.cobertura_parcial is True
    assert r.checagens_omitidas  # não-vazio
    assert "broad-permissions" in r.checagens_omitidas  # uma checagem não-executada
    assert "script-injection" not in r.checagens_omitidas


def test_scan_completo_certifica_cobertura_plena(repo_seguro: Path) -> None:
    r = scan(repo_seguro)
    assert not r.findings
    assert r.cobertura_parcial is False
    assert r.checagens_omitidas == ()
    assert r.checagens_executadas == r.checagens_total == len(_CATALOGO)


# --------------------------------------------------------------------------- #
# JSON: bloco `coverage` para o consumidor de máquina distinguir "limpo" de "não olhado".
# --------------------------------------------------------------------------- #
def test_json_bloco_coverage_completo(repo_seguro: Path) -> None:
    cov = to_document(scan(repo_seguro))["coverage"]
    assert cov["partial"] is False
    assert cov["ran"] == cov["base_total"] == len(_CATALOGO)
    assert cov["omitted_by_operator"] == []


def test_json_bloco_coverage_parcial(repo_seguro: Path) -> None:
    cov = to_document(scan(repo_seguro, only={"script-injection"}))["coverage"]
    assert cov["partial"] is True
    assert cov["ran"] == 1
    assert cov["base_total"] == len(_CATALOGO)
    assert "broad-permissions" in cov["omitted_by_operator"]


# --------------------------------------------------------------------------- #
# Console: o veredito limpo é qualificado quando parcial; a linha de cobertura sai também
# COM achados; a varredura completa e limpa continua verde e sem ruído.
# --------------------------------------------------------------------------- #
def test_console_qualifica_veredito_limpo_parcial() -> None:
    saida = _render(
        ScanResult(
            findings=[],
            files_scanned=1,
            checagens_total=len(_CATALOGO),
            checagens_omitidas=("broad-permissions", "secret-in-run"),
        )
    )
    assert "nas checagens executadas" in saida
    assert "Cobertura parcial" in saida
    assert "broad-permissions" in saida


def test_console_veredito_limpo_completo_e_verde() -> None:
    saida = _render(ScanResult(findings=[], files_scanned=1, checagens_total=len(_CATALOGO)))
    assert "Nenhum problema encontrado" in saida
    assert "Cobertura parcial" not in saida
    assert "nas checagens executadas" not in saida


def test_console_imprime_cobertura_mesmo_com_achados() -> None:
    achado = Finding(
        check_id="script-injection",
        title="t",
        severity=Severity.HIGH,
        path="w.yml",
        line=1,
        detail="d",
        recommendation="r",
    )
    saida = _render(
        ScanResult(
            findings=[achado],
            files_scanned=1,
            checagens_total=len(_CATALOGO),
            checagens_omitidas=("broad-permissions",),
        )
    )
    assert "Cobertura parcial" in saida
    assert "broad-permissions" in saida


# --------------------------------------------------------------------------- #
# Portão do CI (_maybe_fail): parcial + limpo NÃO passa verde; --fail-on none desliga a trava.
# --------------------------------------------------------------------------- #
def test_cli_parcial_limpo_nao_passa_verde(safe_repo: Path) -> None:
    r = runner.invoke(app, ["scan", str(safe_repo), "--only", "script-injection"])
    assert r.exit_code == 1
    assert "Cobertura parcial" in r.stderr


def test_cli_parcial_com_fail_on_none_passa(safe_repo: Path) -> None:
    r = runner.invoke(
        app, ["scan", str(safe_repo), "--only", "script-injection", "--fail-on", "none"]
    )
    assert r.exit_code == 0


def test_cli_completo_limpo_passa_verde(safe_repo: Path) -> None:
    r = runner.invoke(app, ["scan", str(safe_repo)])
    assert r.exit_code == 0
