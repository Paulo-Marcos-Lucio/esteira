"""Catálogo declarativo das checagens do Esteira.

Os rótulos OWASP são da edição **2025** (publicada em 06/11/2025) em toda a suíte. A edição
importa: `A03` é *Software Supply Chain Failures* em 2025 e era *Injection* em 2021, e
`Injection` virou `A05`. Consolidar achados de ferramentas em edições diferentes soma coisas
distintas sob o mesmo código, por isso o ano é declarado — no cabeçalho da coluna na tela,
e no campo `owasp_edition` do JSON/SARIF, para quem consome por máquina.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from esteira.core.models import Confidence, Finding, FindingType, Severity
from esteira.core.redaction import redact

# Edição do OWASP Top 10 usada nos rótulos deste catálogo.
OWASP_EDITION = "2025"


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: Severity
    recommendation: str
    owasp: str | None = None
    cwe: str | None = None
    # `kw_only`: obrigatórios (sem default) sem forçar reordenar os 17 construtores
    # abaixo, que já passam owasp/cwe posicionalmente. Uma checagem nova sem os dois
    # quebra a IMPORTAÇÃO do módulo — ver EV-12 no LEDGER da cadência.
    finding_type: FindingType = field(kw_only=True)
    confidence: Confidence = field(kw_only=True)


CATALOG: dict[str, CheckMeta] = {
    m.id: m
    for m in [
        CheckMeta(
            "script-injection",
            "Injeção de comando via contexto não-confiável em 'run'",
            Severity.CRITICAL,
            "Nunca interpole ${{ github.event.* }} / github.head_ref direto no shell. "
            'Passe por uma variável de ambiente e use "$VAR" com aspas.',
            "A05:2025 Injection",
            "CWE-94",
            finding_type=FindingType.SCRIPT,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "pull-request-target-checkout",
            "checkout de código de PR em 'pull_request_target'",
            Severity.CRITICAL,
            "pull_request_target roda com segredos e token de escrita. Não faça checkout do "
            "código do PR (head) nesse contexto — é execução de código não-confiável com privilégio.",
            "A08:2025 Software or Data Integrity Failures",
            "CWE-94",
            finding_type=FindingType.TRIGGER,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "unpinned-action-thirdparty",
            "Action de terceiros não fixada por SHA",
            Severity.HIGH,
            "Fixe actions de terceiros por SHA de commit completo (40 hex), não por tag/branch — "
            "tags podem ser movidas para código malicioso. E mantenha os SHAs sob "
            "Dependabot/Renovate: pinar sem atualizar congela a versão vulnerável, o que é pior "
            "que a tag (que ao menos recebe a correção do mantenedor).",
            "A03:2025 Software Supply Chain Failures",
            "CWE-1357",
            finding_type=FindingType.SUPPLY_CHAIN,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "broad-permissions",
            "Permissões amplas do GITHUB_TOKEN",
            Severity.HIGH,
            "Evite 'write-all' / 'contents: write' global. Declare o mínimo necessário por job.",
            "A01:2025 Broken Access Control",
            "CWE-732",
            finding_type=FindingType.PERMISSIONS,
            confidence=Confidence.MEDIUM,
        ),
        CheckMeta(
            "secret-in-run",
            "Segredo exposto em comando 'run'",
            Severity.HIGH,
            # Sem a palavra 'log' de propósito. A recomendação é colada ao detalhe na mensagem
            # do SARIF, e o detalhe do caso `$GITHUB_ENV` afirma justamente que o segredo NÃO
            # vai para o log — uma recomendação que dissesse o contrário se contradiria dentro
            # da mesma frase entregue ao cliente.
            "Passe o segredo pelo 'env:' do step que precisa dele, e só dele. Não imprima "
            "${{ secrets.* }} no stdout (o mascaramento do GitHub é parcial: quebra quando o "
            "valor é transformado — base64, fatiado, maiúsculas) nem exporte para $GITHUB_ENV, "
            "que entrega o segredo a todos os steps seguintes.",
            "A09:2025 Security Logging and Alerting Failures",
            "CWE-532",
            finding_type=FindingType.SECRET_HANDLING,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "insecure-commands",
            "Comandos inseguros de workflow reabilitados (ACTIONS_ALLOW_UNSECURE_COMMANDS)",
            Severity.HIGH,
            "Remova ACTIONS_ALLOW_UNSECURE_COMMANDS. Ela reativa os comandos legados 'set-env' e "
            "'add-path' via stdout (CVE-2020-15228): qualquer saída controlada por atacante passa a "
            "poder injetar variável de ambiente ou entrada no PATH e escalar para execução de código. "
            "Use os arquivos $GITHUB_ENV / $GITHUB_PATH com valores confiáveis.",
            "A05:2025 Injection",
            "CWE-94",
            finding_type=FindingType.SCRIPT,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "curl-pipe-shell",
            "Download e execução direta (curl|bash)",
            Severity.MEDIUM,
            "Baixe o script, verifique o hash/assinatura e só então execute — 'curl | bash' roda "
            "código arbitrário da rede sem verificação.",
            "A03:2025 Software Supply Chain Failures",
            "CWE-494",
            finding_type=FindingType.SCRIPT,
            confidence=Confidence.MEDIUM,
        ),
        CheckMeta(
            "self-hosted-runner",
            "Runner self-hosted",
            Severity.MEDIUM,
            "Em repositório público, PRs de fork podem executar em runners self-hosted persistentes. "
            "Use runners efêmeros e isole a rede.",
            "A08:2025 Software or Data Integrity Failures",
            "CWE-668",
            finding_type=FindingType.TRIGGER,
            confidence=Confidence.MEDIUM,
        ),
        CheckMeta(
            "dangerous-trigger",
            "Gatilho privilegiado (pull_request_target / workflow_run / issue_comment)",
            Severity.LOW,
            "Informativo: esses gatilhos rodam no contexto do repositório-base, com segredos e token "
            "de escrita. Seguro se NÃO fizerem checkout/execução de código do PR — o risco real "
            "(checkout do PR) é reportado à parte como 'pull-request-target-checkout'.",
            "A08:2025 Software or Data Integrity Failures",
            "CWE-269",
            finding_type=FindingType.TRIGGER,
            confidence=Confidence.LOW,
        ),
        CheckMeta(
            "unpinned-action-firstparty",
            "Action oficial fixada por tag (não SHA)",
            Severity.LOW,
            "Mesmo em actions oficiais (actions/*, github/*), prefira fixar por SHA para builds "
            "reprodutíveis e imunes a mudança de tag.",
            "A03:2025 Software Supply Chain Failures",
            "CWE-1357",
            finding_type=FindingType.SUPPLY_CHAIN,
            confidence=Confidence.LOW,
        ),
        CheckMeta(
            "unpinned-reusable-workflow",
            "Reusable workflow fixado por branch/tag (não SHA)",
            Severity.LOW,
            "Reusable workflow (`org/repo/.github/workflows/x.yml@ref`) fixado por branch/tag. "
            "Fixar por SHA endurece o supply-chain, MAS confira o contexto: dentro da mesma org o "
            "risco é menor, e algumas infra-CI exigem `@main` (o próprio arquivo pode documentar).",
            "A03:2025 Software Supply Chain Failures",
            "CWE-1357",
            finding_type=FindingType.SUPPLY_CHAIN,
            confidence=Confidence.MEDIUM,
        ),
        CheckMeta(
            "missing-permissions",
            "Sem bloco 'permissions' explícito",
            Severity.LOW,
            "Declare 'permissions:' explicitamente (idealmente 'contents: read') para não depender "
            "do padrão da organização.",
            "A01:2025 Broken Access Control",
            "CWE-732",
            finding_type=FindingType.PERMISSIONS,
            confidence=Confidence.LOW,
        ),
        CheckMeta(
            "secrets-inherit",
            "Reusable workflow recebe TODO o cofre de segredos (secrets: inherit)",
            Severity.MEDIUM,
            "'secrets: inherit' entrega todos os segredos do repositório ao workflow chamado. "
            "Passe apenas o necessário explicitamente (secrets:\\n  FOO: ${{ secrets.FOO }}), "
            "sobretudo se o reusable não for fixado por SHA ou for de outra organização.",
            "A03:2025 Software Supply Chain Failures",
            "CWE-522",
            finding_type=FindingType.PERMISSIONS,
            confidence=Confidence.MEDIUM,
        ),
        CheckMeta(
            "secret-to-thirdparty-action",
            "Segredo/GITHUB_TOKEN passado a action de terceiros não fixada por SHA",
            Severity.HIGH,
            "Não passe ${{ secrets.* }} / ${{ github.token }} via 'with:' NEM pelo 'env:' do step "
            "para uma action de terceiros fixada por tag/branch — a action lê o env em process.env, "
            "então se a tag for movida para código malicioso ele recebe o segredo (inclusive o "
            "GITHUB_TOKEN de escrita) pelos dois caminhos. Fixe a action por SHA de commit completo "
            "(40 hex) e passe apenas o token de menor escopo necessário.",
            "A03:2025 Software Supply Chain Failures",
            "CWE-522",
            finding_type=FindingType.SECRET_HANDLING,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "unpinned-container-image",
            "Imagem de contêiner fixada por tag (não por digest)",
            Severity.LOW,
            "Imagens em container:/services:/docker:// fixadas por tag podem ser republicadas "
            "com conteúdo diferente. Fixe por digest (imagem@sha256:...) para builds "
            "reprodutíveis e imunes a supply-chain.",
            "A03:2025 Software Supply Chain Failures",
            "CWE-1357",
            finding_type=FindingType.SUPPLY_CHAIN,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "checkout-credentials-in-artifact",
            "Credencial do checkout publicada junto com o workspace",
            Severity.HIGH,
            "actions/checkout grava a credencial em .git/config — 'persist-credentials' é true "
            "por padrão. Se um step seguinte publica o workspace inteiro (upload-artifact com "
            "path '.' ou sem path), o .git vai junto e o token fica baixável por quem tiver "
            "acesso ao artefato. Use 'persist-credentials: false' no checkout quando o job não "
            "precisa empurrar commits, ou restrinja o 'path' do upload ao diretório de build.",
            "A02:2025 Security Misconfiguration",
            "CWE-522",
            finding_type=FindingType.SECRET_HANDLING,
            confidence=Confidence.HIGH,
        ),
        CheckMeta(
            "invalid-yaml",
            "Workflow com YAML inválido (análise estrutural pulada)",
            Severity.HIGH,
            "Corrija a sintaxe YAML: enquanto o arquivo não parseia, as checagens estruturais "
            "(gatilhos, permissões, checkout de PR) não rodam e podem esconder falhas — por isso "
            "isto falha o CI por padrão (fail-closed), em vez de passar como se estivesse limpo.",
            None,
            "CWE-1288",
            finding_type=FindingType.STRUCTURE,
            confidence=Confidence.HIGH,
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
    fix_suggestion: str | None = None,
) -> Finding:
    meta = CATALOG[check_id]
    # Ponto de estrangulamento da redação. Poderia ficar em cada detector, mas então cada
    # checagem NOVA nasceria vazando por omissão — e a única que importa é a que ninguém
    # lembrou de blindar. Os três campos redigidos são os que carregam texto vindo do arquivo
    # auditado; `recommendation` vem do catálogo e nunca contém dado do cliente.
    return Finding(
        check_id=meta.id,
        title=meta.title,
        severity=severity or meta.severity,
        path=path,
        line=line,
        detail=redact(detail) or detail,
        recommendation=meta.recommendation,
        finding_type=meta.finding_type,
        confidence=meta.confidence,
        evidence=redact(evidence),
        cwe=meta.cwe,
        owasp=meta.owasp,
        fix_suggestion=redact(fix_suggestion),
    )
