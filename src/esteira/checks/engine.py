"""Motor: descobre workflows, roda as checagens e agrega os achados."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from esteira.checks.catalog import make_finding
from esteira.checks.detectors import run_all
from esteira.core.loader import iter_workflow_files, load
from esteira.core.models import Finding, ScanResult


def _scan_file(path: Path) -> list[Finding]:
    """Analisa um arquivo, jamais deixando uma exceção derrubar a varredura toda."""
    try:
        return run_all(load(path))
    except Exception as exc:
        return [
            make_finding(
                "invalid-yaml",
                str(path),
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

    findings: list[Finding] = []
    files = iter_workflow_files(root)
    for path in files:
        for finding in _scan_file(path):
            if only_set is not None and finding.check_id not in only_set:
                continue
            if finding.check_id in skip_set:
                continue
            findings.append(finding)
    return ScanResult(findings=findings, files_scanned=len(files))
