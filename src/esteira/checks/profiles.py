"""Perfis de severidade por contexto (repositório público OSS x interno).

O catálogo (`checks/catalog.py`) declara UMA severidade padrão por checagem — a que faz
sentido sem saber nada sobre quem pode abrir PR. Mas o mesmo achado não pesa igual em todo
contexto: um runner self-hosted é uma porta aberta num repositório público (qualquer PR de
fork de qualquer pessoa aciona o runner) e é só higiene de infraestrutura própria num
repositório interno, onde só quem já tem push consegue abrir PR.

Este módulo é a fonte ÚNICA e declarada dessas exceções: cada entrada carrega a severidade
nova E a justificativa que vai para o relatório — a mudança nunca pode aparecer como um número
diferente sem explicação, porque isso é indistinguível de um bug de relatório.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from esteira.core.models import Finding, Profile, Severity


@dataclass(frozen=True)
class _Ajuste:
    severidade: Severity
    justificativa: str


# check_id -> ajuste, por perfil. Só entram aqui checagens cujo risco REALMENTE muda com o
# público que pode acionar o workflow — não é um multiplicador genérico sobre o catálogo
# inteiro (script-injection, segredo exposto e supply-chain de action pesam igual em
# qualquer contexto: quem já tem push também pode estar comprometido ou ser mal-intencionado).
_AJUSTES: dict[Profile, dict[str, _Ajuste]] = {
    Profile.OSS_PUBLICO: {
        "self-hosted-runner": _Ajuste(
            Severity.CRITICAL,
            "perfil oss-publico: em repositório público, PR de fork de QUALQUER pessoa "
            "aciona o runner self-hosted — de MÉDIA (padrão do catálogo) para CRÍTICA.",
        ),
        "dangerous-trigger": _Ajuste(
            Severity.MEDIUM,
            "perfil oss-publico: pull_request_target/workflow_run/issue_comment em "
            "repositório público são acionáveis por qualquer pessoa externa que abra PR, "
            "issue ou comentário — de BAIXA (padrão, informativo) para MÉDIA.",
        ),
        "missing-permissions": _Ajuste(
            Severity.MEDIUM,
            "perfil oss-publico: sem 'permissions:' explícito, um workflow acionado por PR "
            "externo herda o padrão da organização, que pode ser de escrita — de BAIXA "
            "(padrão) para MÉDIA.",
        ),
    },
    Profile.INTERNO: {
        "self-hosted-runner": _Ajuste(
            Severity.LOW,
            "perfil interno: só quem já tem push consegue abrir PR — o runner self-hosted "
            "deixa de ser vetor de execução externa e vira só higiene de infraestrutura "
            "própria — de MÉDIA (padrão do catálogo) para BAIXA.",
        ),
    },
}


def apply(findings: list[Finding], profile: Profile | None) -> list[Finding]:
    """Reescreve a severidade dos achados que o perfil ajusta, com a justificativa junto.

    `profile=None` devolve os achados intocados — severidade pura do catálogo é o padrão
    quando ninguém pediu um perfil. Achados sem ajuste declarado para este perfil também
    passam intocados: a ausência de entrada em `_AJUSTES` É a decisão de não mudar nada.
    """
    if profile is None:
        return findings
    ajustes = _AJUSTES.get(profile, {})
    if not ajustes:
        return findings
    saida: list[Finding] = []
    for finding in findings:
        ajuste = ajustes.get(finding.check_id)
        if ajuste is None:
            saida.append(finding)
            continue
        saida.append(
            replace(finding, severity=ajuste.severidade, severity_note=ajuste.justificativa)
        )
    return saida
