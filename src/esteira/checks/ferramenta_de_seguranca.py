"""Ferramenta de segurança conhecida usada via 'uses:', fixada por tag/branch (não SHA).

Uma action de scanner de segurança (secret-scanning, SAST, SCA, hardening de runner) que roda
por tag mutável carrega risco MAIOR que uma action genérica na mesma condição de pin: ela já
executa com acesso de leitura ao código-fonte completo do workflow que chama (semgrep,
gitleaks, trufflehog), ou grava resultado usando um token com `security-events: write`
(CodeQL, Trivy com upload de SARIF). Sequestrar a tag rende execução de código DENTRO da
ferramenta que devia pegar o atacante — a mesma classe de falha do `unpinned-action-*`
genérico, mas com a superfície de ataque sendo a própria varredura de segurança.

Por isso o achado dedicado `security-tool-unpinned` (HIGH) **subsome** — não soma — o
`unpinned-action-firstparty`/`unpinned-action-thirdparty` genérico da MESMA linha: reportar os
dois duplicaria uma única causa raiz (o pin por tag) como se fossem dois defeitos
independentes. A subsunção mora em `detectors.run_all`, o único ponto que já vê o conjunto
completo de achados de todas as checagens antes de aplicar a supressão inline.
"""

from __future__ import annotations

from esteira.checks.catalog import CATALOG, CheckMeta, make_finding
from esteira.checks.detectors import _SHA, _action_ref, _jobs, _steps_of
from esteira.core.models import Finding, Severity, Workflow

# owner/repo de ferramentas de segurança conhecidas usadas como GitHub Action. Curada à mão,
# como o snapshot de `compromised_actions.KNOWN_COMPROMISED` — uma action ausente daqui não é
# veredito de que ela é "segura", só que ainda não subsome o achado genérico.
ACOES_DE_SEGURANCA: frozenset[str] = frozenset(
    {
        "gitleaks/gitleaks-action",
        "trufflesecurity/trufflehog",
        "semgrep/semgrep-action",
        "returntocorp/semgrep-action",
        "github/codeql-action",
        "aquasecurity/trivy-action",
        "anchore/scan-action",
        "ossf/scorecard-action",
        "step-security/harden-runner",
        "snyk/actions",
        "github/dependency-review-action",
        "pypa/gh-action-pip-audit",
    }
)

CATALOG_ENTRIES: list[CheckMeta] = [
    CheckMeta(
        "security-tool-unpinned",
        "Ferramenta de segurança fixada por tag/branch (não SHA)",
        Severity.HIGH,
        "Fixe a action de segurança por SHA de commit completo (40 hex). Uma tag sequestrada "
        "nesse tipo de action rende execução de código dentro da própria varredura de segurança, "
        "ou abuso do token de 'security-events: write' que ela costuma receber — risco maior que "
        "o de uma action genérica no mesmo estado de pin.",
        cwe="CWE-1357",
        owasp="A03:2025 Software Supply Chain Failures",
    ),
]


def check_security_tool_unpinned(wf: Workflow) -> list[Finding]:
    """Cada 'uses:' cuja raiz owner/action está em `ACOES_DE_SEGURANCA` e cujo ref não é SHA."""
    out: list[Finding] = []
    for job in _jobs(wf.data):
        for step in _steps_of(job):
            parsed = _action_ref(step.get("uses"))
            if parsed is None:
                continue
            action, ref = parsed
            if _SHA.match(ref):
                continue
            # Normaliza subpath: `github/codeql-action/analyze@ref` é a MESMA ferramenta que
            # `github/codeql-action@ref` — o risco é do repositório da action, não do subdiretório.
            raiz = "/".join(action.split("/")[:2])
            if raiz not in ACOES_DE_SEGURANCA:
                continue
            at = wf.find_line(f"{action}@{ref}") or wf.find_line(action) or 1
            out.append(
                make_finding(
                    "security-tool-unpinned",
                    wf.path,
                    at,
                    f"'{action}' (ferramenta de segurança) fixada por '{ref}' (não é SHA).",
                    evidence=f"{action}@{ref}",
                )
            )
    return out


# Auto-registro no catálogo (para make_finding e os relatórios conhecerem o id sem editar catalog.py).
for _meta in CATALOG_ENTRIES:
    CATALOG.setdefault(_meta.id, _meta)
