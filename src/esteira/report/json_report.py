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

# Classes de vulnerabilidade que NENHUMA checagem do catálogo cobre — diferente de
# `omitted_by_operator` (que é checagem existente que o operador excluiu com `--only`/`--skip`).
# Até agora essas classes só existiam em prosa na seção "Limitações conhecidas" do README: quem lia
# o JSON (dashboard/CI) não tinha como saber que um "0 achados" limpo não fala sobre elas. Cada
# entrada aqui é a mesma classe, com o mesmo texto, também na saída de máquina.
KNOWN_GAPS: tuple[dict[str, str], ...] = (
    {
        "id": "outputs-propagation-untracked",
        "detail": (
            "Propagação de taint por 'steps.*.outputs' / 'needs.*.outputs' entre steps não é "
            "rastreada: se um step captura contexto não-confiável numa saída e outro step depois "
            "interpola essa saída direto no shell, só a linha de ORIGEM é marcada — o segundo uso "
            "passa sem alerta."
        ),
    },
    {
        "id": "sha-pin-fork-origin-unverified",
        "detail": (
            "'unpinned-action-thirdparty'/'unpinned-action-firstparty' confirmam o FORMATO da "
            "referência (SHA completo de 40 caracteres vs. tag/branch mutável) — não que aquele "
            "SHA pertença de fato ao histórico do 'owner/repo' declarado, e não a um fork dele. "
            "GitHub resolve 'uses: owner/repo@sha' contra o grafo de objetos Git compartilhado "
            "entre um repositório e seus forks: se o commit existe em QUALQUER fork alcançável, "
            "ele resolve, mesmo sem nunca ter sido mesclado no repositório nomeado ('imposter "
            "commit'). Confirmar a origem genuína exige consulta de rede à API do GitHub — "
            "exatamente a classe de checagem que esta ferramenta mantém deliberadamente offline."
        ),
    },
    {
        "id": "cache-poisoning-by-eviction-unverified",
        "detail": (
            "'cache-poisoning' só casa um PAR estrutural visível no YAML: uma ESCRITA em "
            "contexto não-confiável e uma RESTAURAÇÃO da MESMA chave em contexto confiável. Não "
            "cobre o envenenamento por EVICÇÃO FORÇADA: encher a cota de cache do repositório "
            "(10 GB) com entradas descartáveis para o LRU do GitHub expulsar a entrada legítima, "
            "e então escrever uma entrada maliciosa sob a mesma chave, agora livre — sem um par "
            "escrita/restauração simétrico visível nos workflows escaneados. É a técnica real do "
            "compromisso do angular/dev-infra (dezembro/2025, bounty de US$ 31.337 pago pelo "
            "Google): a ferramenta 'Cacheract' encheu a cota para expulsar a entrada legítima, a "
            "entrada envenenada foi restaurada pelo workflow agendado 'ng-renovate', expondo um "
            "token de escrita administrativa. Confirmar esse padrão exige modelar a COTA e o LRU "
            "do cache, não só o grafo estático de write/restore — fora do escopo estrutural desta "
            "checagem. Alternativa gratuita: a auditoria 'cache-poisoning' do zizmor cobre esse "
            "caso por um caminho diferente (qualquer action com cache habilitado num workflow que "
            "ele classifica como de release/publicação é apontada, com ou sem par visível): "
            "'uvx zizmor .'."
        ),
    },
    {
        "id": "oidc-trust-policy-out-of-repo",
        "detail": (
            "A trust policy OIDC — quem pode trocar o token de federação de identidade "
            "(OpenID Connect) do GitHub Actions por uma credencial de nuvem — não é avaliada: "
            "ela não existe em lugar nenhum do repositório. Um workflow com "
            "'permissions: id-token: write' mais um 'uses: aws-actions/configure-aws-"
            "credentials'/'google-github-actions/auth'/'azure/login' só mostra a INTENÇÃO de "
            "pedir o token; quem de fato decide se aquele token é aceito é a condição "
            "configurada do lado do provedor — o 'sub'/'aud' da IAM role na AWS, a condição de "
            "atributo do Workload Identity Pool no GCP, o federated credential no Entra ID. "
            "Essa configuração mora na nuvem, fora do Git e fora do alcance de uma ferramenta "
            "que só lê '.github/**'. Uma trust policy mal restrita (sem 'ref:'/'environment:', "
            "aceitando qualquer branch ou 'repo:*') deixa qualquer workflow do repositório "
            "assumir a credencial — nenhuma checagem desta ferramenta pode confirmar ou refutar "
            "isso a partir do YAML. Confirmar exige inspecionar a configuração do provedor "
            "(ex.: 'aws iam get-role --role-name X' e ler o 'AssumeRolePolicyDocument'), fora "
            "do escopo desta ferramenta."
        ),
    },
)


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
        # Discriminador do que `commit` significa: aqui é o commit do repositório AUDITADO
        # ("target"), não o da ferramenta — para o cliente verificar os quatro relatórios da
        # suíte com uma receita só, sem adivinhar contra o que o SHA foi carimbado.
        "commit_scope": provenance.COMMIT_SCOPE,
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
    """Bloco de cobertura da suíte: quantas checagens rodaram, o total do catálogo, as que
    o operador deixou de fora, e as classes que o catálogo inteiro não cobre. `partial` é a
    bandeira que o CI lê para não tratar uma varredura recortada e sem achados como aprovação;
    `known_gaps` é fixo por versão da ferramenta (não muda por repositório escaneado) e cobre a
    outra forma de "0 achados" não ser "limpo": nenhuma checagem do catálogo procura por aquilo."""
    return {
        "partial": result.cobertura_parcial,
        "ran": result.checagens_executadas,
        "base_total": result.checagens_total,
        "omitted_by_operator": list(result.checagens_omitidas),
        "known_gaps": [dict(gap) for gap in KNOWN_GAPS],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_document(result), indent=2, ensure_ascii=False)
