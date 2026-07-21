"""Motor: descobre workflows, roda as checagens e agrega os achados."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from esteira.checks.detectors import run_all
from esteira.core.loader import iter_workflow_files, load
from esteira.core.models import Finding, ScanResult


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
        workflow = load(path)
        for finding in run_all(workflow):
            if only_set is not None and finding.check_id not in only_set:
                continue
            if finding.check_id in skip_set:
                continue
            findings.append(finding)
    return ScanResult(findings=findings, files_scanned=len(files))
