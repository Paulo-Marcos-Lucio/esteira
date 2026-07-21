"""Renderizador JSON."""

from __future__ import annotations

import json
from typing import Any

from esteira import __version__
from esteira.core.models import Finding, ScanResult


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "check": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "path": finding.path.replace("\\", "/"),
        "line": finding.line,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "recommendation": finding.recommendation,
    }


def to_document(result: ScanResult) -> dict[str, Any]:
    findings = result.sorted()
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return {
        "tool": "esteira",
        "version": __version__,
        "summary": {
            "total": len(findings),
            "by_severity": counts,
            "files_scanned": result.files_scanned,
        },
        "findings": [finding_to_dict(f) for f in findings],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)
