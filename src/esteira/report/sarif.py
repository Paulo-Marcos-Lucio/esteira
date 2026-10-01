"""Renderizador SARIF 2.1.0 — para a aba Security do GitHub."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from esteira import __version__
from esteira.checks.catalog import CATALOG, OWASP_EDITION
from esteira.core import provenance, redaction
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
# Namespace do fingerprint. NÃO renomear: o GitHub casa alertas já abertos pelo par
# chave+valor, então trocar a chave orfaniza todos os alertas existentes de uma vez.
_FINGERPRINT_KEY = "esteiraFindingId/v1"


def _help_uri(cwe: str | None) -> str | None:
    """Página do CWE do achado — o único destino estável que o catálogo já carrega."""
    if cwe is None or not cwe.startswith("CWE-"):
        return None
    return f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"


def _rules() -> list[dict[str, Any]]:
    # Catálogo COMPLETO, inclusive as regras que não dispararam: o SARIF 2.1.0 permite, e é
    # o que faz a aba Security mostrar a regra configurada e silenciosa. 16 KB contra o
    # limite de 10 MB do GitHub — não há argumento de tamanho para emitir só as que acharam.
    rules: list[dict[str, Any]] = []
    for meta in CATALOG.values():
        rule: dict[str, Any] = {
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
                # `owasp_edition`, com underscore: era `owasp-edition` (hífen) aqui e
                # `owasp_edition` no JSON e no README. Quem consumia a chave documentada
                # levava KeyError num property bag que o SARIF não valida.
                "owasp_edition": OWASP_EDITION,
            },
        }
        help_uri = _help_uri(meta.cwe)
        if help_uri is not None:
            rule["helpUri"] = help_uri
        rules.append(rule)
    return rules


def _fingerprint(finding: Finding, ordinal: int) -> str:
    """Identidade estável do achado, DE PROPÓSITO sem o número da linha.

    Reindentar o workflow não pode fechar e reabrir o alerta no Code Scanning. O caminho já
    chega relativo à raiz da varredura (`engine._display_path`), então o hash também não muda
    entre a máquina do dev e o runner.

    O ``ordinal`` desempata achados genuinamente repetidos — dois `actions/checkout@v4` no
    mesmo arquivo têm id, caminho e evidência idênticos. Sem ele os dois receberiam o mesmo
    fingerprint e um consumidor que deduplica por (ruleId, fingerprint, arquivo) perderia um
    achado real. É a ordem de ocorrência, não a linha: sobrevive à reindentação.
    """
    material = "\0".join(
        (finding.check_id, finding.path, finding.evidence or finding.detail, str(ordinal))
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _result(finding: Finding, ordinal: int, suppression: str | None = None) -> dict[str, Any]:
    # O SARIF é PUBLICADO (sobe pro Code Scanning): toda evidência mascarada que sai daqui passa
    # por `para_publicacao` e encurta para KEEP_PUBLICADO=2 por ponta — o console/JSON de triagem
    # ficam em 4+4, o que sobe fica em 2+2. `para_publicacao` só encurta tokens `…`; texto sem
    # credencial (o pin de uma action, uma recomendação do catálogo) passa intacto.
    message = redaction.para_publicacao(f"{finding.detail} {finding.recommendation}") or ""
    if finding.fix_suggestion is not None:
        message += f" {redaction.para_publicacao(finding.fix_suggestion) or ''}"
    region: dict[str, Any] = {"startLine": max(finding.line, 1)}
    if finding.evidence:
        region["snippet"] = {"text": redaction.para_publicacao(finding.evidence)}
    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "partialFingerprints": {_FINGERPRINT_KEY: _fingerprint(finding, ordinal)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": region,
                }
            }
        ],
    }
    if suppression is not None:
        # `kind: inSource` é o valor do SARIF 2.1.0 para supressão declarada NO próprio arquivo
        # analisado (o `# esteira: ignore`/`# zizmor: ignore` inline) — o outro valor, `external`,
        # é para quem suprime fora do código (ex.: dismissal só no Code Scanning), que não é o
        # nosso caso. Um resultado com `suppressions` some da lista "open" da aba Security mas
        # continua no SARIF, auditável — dismissed, não apagado.
        result["suppressions"] = [
            {"kind": "inSource", "justification": redaction.para_publicacao(suppression) or ""}
        ]
    return result


def _results(result: ScanResult) -> list[dict[str, Any]]:
    vistos: dict[tuple[str, str, str], int] = {}
    saida: list[dict[str, Any]] = []
    itens: list[tuple[Finding, str | None]] = [(f, None) for f in result.sorted()]
    itens += [(s.finding, s.justification) for s in result.suppressed_sorted()]
    for finding, justification in itens:
        chave = (finding.check_id, finding.path, finding.evidence or finding.detail)
        ordinal = vistos.get(chave, 0)
        vistos[chave] = ordinal + 1
        saida.append(_result(finding, ordinal, justification))
    return saida


def to_sarif(result: ScanResult) -> str:
    # A edição do OWASP e a proveniência vão no NÍVEL DO RUN, e não só dentro de cada regra:
    # quem consome o arquivo inteiro (a aba Security, um agregador) precisava abrir uma regra
    # qualquer para descobrir sob qual edição os rótulos `A03` foram escritos — e não tinha
    # como descobrir contra qual commit o run foi produzido.
    commit = provenance.commit(result.root)
    propriedades: dict[str, Any] = {
        "owasp_edition": OWASP_EDITION,
        # `commit` NÃO mora mais aqui: foi para `versionControlProvenance.revisionId` abaixo — o
        # slot padrão que o GitHub Code Scanning de fato lê (em `properties` ele era ignorado).
        # Fica só o discriminador do que o SHA significa: o commit do repositório AUDITADO.
        "commit_scope": provenance.COMMIT_SCOPE,
        "ruleset_hash": provenance.ruleset_hash(),
        "artifact_sha256": None,
    }
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "esteira",
                "informationUri": "https://github.com/Paulo-Marcos-Lucio/esteira",
                "version": __version__,
                "rules": _rules(),
            }
        },
        "results": _results(result),
        "properties": propriedades,
    }
    # Proveniência de controle de versão no slot canônico do SARIF 2.1.0. O Code Scanning lê
    # `revisionId` daqui; fora de um repositório git (`commit is None`) o bloco é omitido — a
    # resposta honesta é a AUSÊNCIA do carimbo, não um `revisionId: null` que parece informação.
    if commit is not None:
        run["versionControlProvenance"] = [{"revisionId": commit}]
    document: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    # Sobre o `run` já montado e com o campo ainda em `null` — mesma receita do JSON, aplicada
    # ao objeto onde o campo de fato mora.
    propriedades["artifact_sha256"] = provenance.canonical_sha256(document["runs"][0])
    return json.dumps(document, indent=2, ensure_ascii=False)
