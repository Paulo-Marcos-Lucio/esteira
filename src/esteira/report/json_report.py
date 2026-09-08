"""Renderizador JSON.

Contrato compartilhado da suíte AppSec (`schema: suite-appsec/1`): identificadores e chaves
em inglês (padrão de mercado), todo texto destinado a humano em PT-BR. `summary.by_severity`
sai SEMPRE com as cinco chaves, inclusive zeradas — um painel que lê `.by_severity.high` não
pode quebrar com KeyError porque a varredura veio limpa.
"""

from __future__ import annotations

import json
from typing import Any

from esteira import __version__
from esteira.checks.catalog import OWASP_EDITION
from esteira.core import provenance
from esteira.core.models import Finding, ScanResult, Severity

SCHEMA = "suite-appsec/1"


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "severity_rank": finding.severity.rank,
        "path": finding.path,
        "line": finding.line,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "recommendation": finding.recommendation,
        "fix_suggestion": finding.fix_suggestion,
    }


def to_document(result: ScanResult) -> dict[str, Any]:
    findings = result.sorted()
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "tool": "esteira",
        "version": __version__,
        "owasp_edition": OWASP_EDITION,
        # Proveniência (ver core/provenance.py): sem estes três campos o relatório não é
        # vinculável a um estado do código nem a um estado do catálogo, e um achado que
        # desaparece na entrega seguinte é indistinguível de uma regra que foi afrouxada.
        "commit": provenance.commit(result.root),
        "ruleset_hash": provenance.ruleset_hash(),
        "artifact_sha256": None,
        # Cobertura: o consumidor de máquina (dashboard/CI) precisa distinguir "limpo" de
        # "não olhado". `partial=true` significa que o resultado fala só do que rodou —
        # `--only/--skip` reduziram o conjunto e nenhum achado NÃO é prova de ausência.
        "coverage": _coverage_dict(result),
        "summary": {
            "total": len(findings),
            "by_severity": counts,
            "files_scanned": result.files_scanned,
        },
        "findings": [finding_to_dict(f) for f in findings],
    }
    # Por último e sobre o documento já completo: o auto-hash cobre TUDO o mais, inclusive a
    # proveniência acima. Trocar o commit depois da entrega invalida o hash.
    document["artifact_sha256"] = provenance.artifact_sha256(document)
    return document


def _coverage_dict(result: ScanResult) -> dict[str, Any]:
    """Bloco de cobertura da suíte: quantas checagens rodaram, o total do catálogo, e as que
    o operador deixou de fora. `partial` é a bandeira que o CI lê para não tratar uma
    varredura recortada e sem achados como aprovação."""
    return {
        "partial": result.cobertura_parcial,
        "ran": result.checagens_executadas,
        "base_total": result.checagens_total,
        "omitted_by_operator": list(result.checagens_omitidas),
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)
