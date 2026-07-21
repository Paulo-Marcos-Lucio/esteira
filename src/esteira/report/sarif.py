"""Renderizador SARIF 2.1.0 — para a aba Security do GitHub."""

from __future__ import annotations

import json
from typing import Any

from esteira import __version__
from esteira.checks.catalog import CATALOG
from esteira.core.models import Finding, ScanResult, Severity

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rules() -> list[dict[str, Any]]:
    return [
        {
            "id": meta.id,
            "name": meta.title,
            "shortDescription": {"text": meta.title},
            "fullDescription": {"text": meta.recommendation},
            "defaultConfiguration": {"level": _LEVEL[meta.severity]},
            "properties": {
                "tags": ["security", "ci-cd", "github-actions"],
                "security-severity": _SECURITY_SEVERITY[meta.severity],
                "cwe": meta.cwe,
                "owasp": meta.owasp,
            },
        }
        for meta in CATALOG.values()
    ]


def _result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.check_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.detail} {finding.recommendation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
    }


def to_sarif(result: ScanResult) -> str:
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "esteira",
                        "informationUri": "https://github.com/Paulo-Marcos-Lucio/esteira",
                        "version": __version__,
                        "rules": _rules(),
                    }
                },
                "results": [_result(f) for f in result.sorted()],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
