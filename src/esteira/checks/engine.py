"""Motor: descobre workflows, roda as checagens e agrega os achados."""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Iterable
from datetime import date
from pathlib import Path

from esteira.checks.catalog import CATALOG, make_finding
from esteira.checks.detectors import run_all
from esteira.core.exceptions import Excecao, carregar_excecoes
from esteira.core.loader import iter_workflow_files, load
from esteira.core.models import Finding, ScanResult, Suprimido


def _display_path(path: Path, base: Path) -> str:
    """Caminho do achado, relativo à raiz varrida e em barras normais.

    O Code Scanning do GitHub exige que ``artifactLocation.uri`` seja relativo à raiz do
    repositório: com caminho absoluto ele aceita o SARIF e descarta os resultados, sem erro
    visível. Relativizar aqui — no único ponto onde a raiz é conhecida — conserta de uma vez
    o SARIF, o JSON e a coluna 'Local' do console, e mantém a saída idêntica entre a máquina
    do dev e o runner (o que também estabiliza o partialFingerprint do SARIF).
    """
    try:
        relative = Path(os.path.relpath(path, base))
    except ValueError:  # unidades diferentes no Windows: não há caminho relativo
        return path.as_posix()
    if relative.is_absolute() or relative.parts[:1] == ("..",):
        return path.as_posix()
    return relative.as_posix()


def _scan_file(path: Path, base: Path) -> list[Finding]:
    """Analisa um arquivo, jamais deixando uma exceção derrubar a varredura toda."""
    display = _display_path(path, base)
    try:
        workflow = load(path)
        workflow.path = display
        return run_all(workflow)
    except Exception as exc:
        return [
            make_finding(
                "invalid-yaml",
                display,
                1,
                f"Falha inesperada ao analisar o arquivo: {type(exc).__name__}: {exc}",
            )
        ]


def _achado_expirado(finding: Finding, excecao: Excecao) -> Finding:
    aviso = f"supressão expirada em {excecao.expira}"
    return dataclasses.replace(finding, detail=f"{finding.detail} ({aviso}).")


def _aplicar_excecoes(
    findings: list[Finding], excecoes: list[Excecao], hoje: date
) -> tuple[list[Finding], list[Suprimido]]:
    """Separa `findings` em (visíveis, suprimidos) contra as exceções de config.

    Primeira exceção que CASA decide: vencida, o achado fica visível e ganha a nota de
    validade expirada; vigente, o achado sai para `suprimidos` com origem/motivo — nunca é
    deletado. Sem exceção casando, o achado segue como estava.
    """
    visiveis: list[Finding] = []
    suprimidos: list[Suprimido] = []
    for finding in findings:
        excecao_casada = next((e for e in excecoes if e.casa(finding.check_id, finding.path)), None)
        if excecao_casada is None:
            visiveis.append(finding)
        elif excecao_casada.expirada(hoje):
            visiveis.append(_achado_expirado(finding, excecao_casada))
        else:
            suprimidos.append(
                Suprimido(finding=finding, origem="config", motivo=excecao_casada.motivo)
            )
    return visiveis, suprimidos


def scan(
    root: Path | str,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
) -> ScanResult:
    only_set = set(only) if only else None
    skip_set = set(skip) if skip else set()

    root = Path(root)
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []
    files = iter_workflow_files(root)
    for path in files:
        for finding in _scan_file(path, base):
            if only_set is not None and finding.check_id not in only_set:
                continue
            if finding.check_id in skip_set:
                continue
            findings.append(finding)

    excecoes = carregar_excecoes(base)
    findings, suprimidos = _aplicar_excecoes(findings, excecoes, date.today())

    # Cobertura: o conjunto ATIVO de checagens é o catálogo depois de aplicar --only/--skip
    # (o mesmo recorte que filtrou os achados acima). O que ficou de fora é omissão do
    # operador — declarada aqui para que o console, o JSON e o portão do CI possam dizer que
    # um resultado sem achados fala só do que rodou. IDs em --only fora do catálogo não
    # entram no conjunto ativo (a CLI já os rejeita com exit 2; aqui a redução é honesta).
    catalogo = set(CATALOG)
    ativo = (only_set & catalogo if only_set is not None else catalogo) - skip_set
    omitidas = tuple(sorted(catalogo - ativo))
    return ScanResult(
        findings=findings,
        suppressed=suprimidos,
        files_scanned=len(files),
        root=str(base),
        checagens_omitidas=omitidas,
        checagens_total=len(catalogo),
    )
