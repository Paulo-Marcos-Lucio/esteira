"""Catálogo declarativo das checagens do Esteira."""

from __future__ import annotations

from dataclasses import dataclass

from esteira.core.models import Finding, Severity


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: Severity
    recommendation: str
    owasp: str | None = None
    cwe: str | None = None


CATALOG: dict[str, CheckMeta] = {
    m.id: m
    for m in [
        CheckMeta(
            "script-injection",
            "Injeção de comando via contexto não-confiável em 'run'",
            Severity.CRITICAL,
            "Nunca interpole ${{ github.event.* }} / github.head_ref direto no shell. "
            'Passe por uma variável de ambiente e use "$VAR" com aspas.',
            "A03:2021 Injection",
            "CWE-94",
        ),
        CheckMeta(
            "pull-request-target-checkout",
            "checkout de código de PR em 'pull_request_target'",
            Severity.CRITICAL,
            "pull_request_target roda com segredos e token de escrita. Não faça checkout do "
            "código do PR (head) nesse contexto — é execução de código não-confiável com privilégio.",
            "A08:2021 Software and Data Integrity Failures",
            "CWE-94",
        ),
        CheckMeta(
            "unpinned-action-thirdparty",
            "Action de terceiros não fixada por SHA",
            Severity.HIGH,
            "Fixe actions de terceiros por SHA de commit completo (40 hex), não por tag/branch — "
            "tags podem ser movidas para código malicioso.",
            "A08:2021 Software and Data Integrity Failures",
            "CWE-1357",
        ),
        CheckMeta(
            "broad-permissions",
            "Permissões amplas do GITHUB_TOKEN",
            Severity.HIGH,
            "Evite 'write-all' / 'contents: write' global. Declare o mínimo necessário por job.",
            "A01:2021 Broken Access Control",
            "CWE-732",
        ),
        CheckMeta(
            "secret-in-run",
            "Segredo exposto em comando 'run'",
            Severity.HIGH,
            "Não faça echo/print de ${{ secrets.* }}. Segredos vazam em logs mesmo com masking parcial.",
            "A09:2021 Security Logging and Monitoring Failures",
            "CWE-532",
        ),
        CheckMeta(
            "curl-pipe-shell",
            "Download e execução direta (curl|bash)",
            Severity.MEDIUM,
            "Baixe o script, verifique o hash/assinatura e só então execute — 'curl | bash' roda "
            "código arbitrário da rede sem verificação.",
            "A08:2021 Software and Data Integrity Failures",
            "CWE-494",
        ),
        CheckMeta(
            "self-hosted-runner",
            "Runner self-hosted",
            Severity.MEDIUM,
            "Em repositório público, PRs de fork podem executar em runners self-hosted persistentes. "
            "Use runners efêmeros e isole a rede.",
            "A08:2021 Software and Data Integrity Failures",
            "CWE-668",
        ),
        CheckMeta(
            "dangerous-trigger",
            "Gatilho privilegiado (pull_request_target / workflow_run)",
            Severity.MEDIUM,
            "Esses gatilhos rodam no contexto do repositório-base, com segredos. Revise o que roda "
            "neles e nunca execute código do PR.",
            "A08:2021 Software and Data Integrity Failures",
            "CWE-269",
        ),
        CheckMeta(
            "unpinned-action-firstparty",
            "Action oficial fixada por tag (não SHA)",
            Severity.LOW,
            "Mesmo em actions oficiais (actions/*, github/*), prefira fixar por SHA para builds "
            "reprodutíveis e imunes a mudança de tag.",
            "A08:2021 Software and Data Integrity Failures",
            "CWE-1357",
        ),
        CheckMeta(
            "missing-permissions",
            "Sem bloco 'permissions' explícito",
            Severity.LOW,
            "Declare 'permissions:' explicitamente (idealmente 'contents: read') para não depender "
            "do padrão da organização.",
            "A01:2021 Broken Access Control",
            "CWE-732",
        ),
    ]
}


def make_finding(
    check_id: str,
    path: str,
    line: int,
    detail: str,
    *,
    evidence: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    meta = CATALOG[check_id]
    return Finding(
        check_id=meta.id,
        title=meta.title,
        severity=severity or meta.severity,
        path=path,
        line=line,
        detail=detail,
        recommendation=meta.recommendation,
        evidence=evidence,
        cwe=meta.cwe,
        owasp=meta.owasp,
    )
