"""Motor: descobre workflows, roda as checagens e agrega os achados."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from esteira.checks.catalog import CATALOG, make_finding
from esteira.checks.detectors import run_all_partitioned
from esteira.core.loader import iter_workflow_files, load
from esteira.core.models import Finding, ScanResult, SuppressedFinding


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


def _scan_file(path: Path, base: Path) -> tuple[list[Finding], list[SuppressedFinding]]:
    """Analisa um arquivo, jamais deixando uma exceção derrubar a varredura toda."""
    display = _display_path(path, base)
    try:
        workflow = load(path)
        workflow.path = display
        return run_all_partitioned(workflow)
    except Exception as exc:
        return [
            make_finding(
                "invalid-yaml",
                display,
                1,
                f"Falha inesperada ao analisar o arquivo: {type(exc).__name__}: {exc}",
            )
        ], []


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
    suppressed: list[SuppressedFinding] = []
    files = iter_workflow_files(root)

    def _incluida(check_id: str) -> bool:
        if only_set is not None and check_id not in only_set:
            return False
        return check_id not in skip_set

    for path in files:
        visiveis, suprimidos = _scan_file(path, base)
        findings += [f for f in visiveis if _incluida(f.check_id)]
        # Mesmo recorte --only/--skip dos achados abertos: quem pediu para pular uma checagem
        # não quer vê-la reaparecer disfarçada de "suprimida" no relatório.
        suppressed += [s for s in suprimidos if _incluida(s.finding.check_id)]

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
        suppressed=suppressed,
        files_scanned=len(files),
        root=str(base),
        checagens_omitidas=omitidas,
        checagens_total=len(catalogo),
    )
