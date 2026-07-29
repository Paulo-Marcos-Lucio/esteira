"""Motor: descobre workflows, roda as checagens e agrega os achados."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from esteira.checks.catalog import make_finding
from esteira.checks.detectors import run_all
from esteira.core.loader import iter_workflow_files, load
from esteira.core.models import Finding, ScanResult


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
    return ScanResult(findings=findings, files_scanned=len(files))
