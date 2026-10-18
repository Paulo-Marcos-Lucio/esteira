"""Matriz de cobertura do Esteira contra o OWASP Top 10 CI/CD Security Risks (CICD-SEC).

O catálogo (`checks/catalog.py`) responde "o que a Esteira detecta". Esta matriz responde a
pergunta anterior, que o catálogo não deixa visível: "de que risco, no eixo de referência da
indústria para segurança de pipeline, cada detecção É evidência?" — e, mais importante, "quais
dos dez riscos a Esteira NÃO cobre hoje".

Declarar o `nao-coberto` é o ponto. Um produto de segurança que só lista o que acerta deixa o
cliente comprar confiança no que falta por omissão — e o eixo CICD-SEC é exatamente onde esse
gabarito existe (Insufficient Flow Control, IAM, Dependency Chain Abuse, PPE, PBAC, Credential
Hygiene, Insecure System Configuration, Ungoverned 3rd-Party Services, Artifact Integrity,
Logging/Visibility). A Esteira é um scanner ESTÁTICO do YAML do workflow: três das dez classes
dependem de configuração que não mora nesse YAML (proteção de branch, instalações de GitHub
Apps/escopos OAuth, audit log de execução) — ficam `nao-coberto` por desenho, não por descuido,
e cada uma carrega o motivo (por que esta análise não alcança) e um incidente público registrado
que mostra o risco se materializando sem o controle que falta.

`avaliar()` é o portão que tranca a CLASSE do defeito que motivou este módulo: a confusão entre
"não cobrimos" e "não dissemos nada". Toda classe `nao-coberto` sem `motivo` e `incidente` falha
na própria construção de `ClasseCICDSEC` — não é possível declarar ausência calada.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from esteira.checks.catalog import CATALOG

IDS_CICD_SEC = frozenset(f"CICD-SEC-{n}" for n in range(1, 11))


class StatusCobertura(str, Enum):
    COBERTO = "coberto"
    PARCIAL = "parcial"
    NAO_COBERTO = "nao-coberto"


@dataclass(frozen=True)
class ClasseCICDSEC:
    id: str
    nome: str
    status: StatusCobertura
    checks: tuple[str, ...] = ()
    motivo: str | None = None
    incidente: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, StatusCobertura):
            raise ValueError(f"{self.id}: status {self.status!r} fora de StatusCobertura")
        if self.status is StatusCobertura.NAO_COBERTO:
            if not self.motivo or not self.incidente:
                raise ValueError(
                    f"{self.id}: classe 'nao-coberto' exige `motivo` e `incidente` — "
                    "não ter procurado o controle não é o mesmo que ter constatado a ausência dele"
                )
        else:
            if not self.checks:
                raise ValueError(
                    f"{self.id}: classe '{self.status.value}' precisa citar ao menos uma checagem"
                )
            for cid in self.checks:
                if cid not in CATALOG:
                    raise ValueError(f"{self.id}: checagem '{cid}' não existe em CATALOG")


# ---------------------------------------------------------------------------------------------- #
# A matriz real. Cada classe aponta para as checagens do CATALOG que são evidência do risco, ou
# — quando `nao-coberto` — o motivo (o que esta análise estática não alcança) e um incidente
# público conhecido em que a ausência do controle correspondente foi explorada.
# ---------------------------------------------------------------------------------------------- #

CLASSES: dict[str, ClasseCICDSEC] = {
    c.id: c
    for c in [
        ClasseCICDSEC(
            "CICD-SEC-1",
            "Insufficient Flow Control Mechanisms",
            StatusCobertura.NAO_COBERTO,
            motivo=(
                "Exigiria consultar as regras de proteção de branch / revisão obrigatória do "
                "repositório (API de branch protection) — não aparecem no YAML do workflow, que "
                "é tudo que esta análise estática lê."
            ),
            incidente=(
                "Comprometimento do servidor git do PHP (mar/2021): commits maliciosos foram "
                "inseridos diretamente no histórico do projeto, contornando a revisão de código "
                "normal do fluxo."
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-2",
            "Inadequate Identity and Access Management",
            StatusCobertura.PARCIAL,
            checks=("falsifiable-actor-condition",),
            motivo=(
                "Cobre só o padrão de decidir privilégio por `github.actor` (atributo "
                "falsificável, não uma autenticação do autor); não avalia uso de OIDC vs. "
                "credencial estática de longa duração, nem conta/identidade compartilhada."
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-3",
            "Dependency Chain Abuse",
            StatusCobertura.COBERTO,
            checks=(
                "unpinned-action-thirdparty",
                "unpinned-action-firstparty",
                "unpinned-reusable-workflow",
                "unpinned-container-image",
                "known-compromised-action",
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-4",
            "Poisoned Pipeline Execution (PPE)",
            StatusCobertura.COBERTO,
            checks=(
                "pull-request-target-checkout",
                "script-injection",
                "dangerous-trigger",
                "ai-agent-rule-of-two",
                "ai-agent-untrusted-input",
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-5",
            "Insufficient PBAC (Pipeline-Based Access Controls)",
            StatusCobertura.COBERTO,
            checks=("broad-permissions", "missing-permissions"),
        ),
        ClasseCICDSEC(
            "CICD-SEC-6",
            "Insufficient Credential Hygiene",
            StatusCobertura.COBERTO,
            checks=(
                "secret-in-run",
                "secrets-inherit",
                "secret-to-thirdparty-action",
                "checkout-credentials-in-artifact",
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-7",
            "Insecure System Configuration",
            StatusCobertura.COBERTO,
            checks=("insecure-commands", "self-hosted-runner"),
        ),
        ClasseCICDSEC(
            "CICD-SEC-8",
            "Ungoverned Usage of 3rd-Party Services",
            StatusCobertura.NAO_COBERTO,
            motivo=(
                "Exigiria enumerar GitHub Apps instalados e escopos OAuth concedidos ao "
                "repositório/organização (API de Installations) — não aparecem no YAML do "
                "workflow, que é tudo que esta análise estática lê."
            ),
            incidente=(
                "Invasão da CircleCI (jan/2023): a sessão de um engenheiro foi comprometida por "
                "malware entregue via um pacote; o acesso resultante a um serviço terceiro de CI "
                "deu ao atacante alcance sobre segredos de clientes armazenados na plataforma."
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-9",
            "Improper Artifact Integrity Validation",
            StatusCobertura.PARCIAL,
            checks=("curl-pipe-shell", "cache-poisoning"),
            motivo=(
                "Cobre download-e-execução sem verificação e o par escrita/restauração de cache "
                "entre contextos de confiança distintos; não cobre assinatura/checksum de "
                "artefatos de build nem attestations de proveniência (SLSA)."
            ),
        ),
        ClasseCICDSEC(
            "CICD-SEC-10",
            "Insufficient Logging and Visibility",
            StatusCobertura.NAO_COBERTO,
            motivo=(
                "Esta é uma análise ESTÁTICA da definição do workflow; logging e alerta vivem na "
                "execução (API de audit log e de runs), fora do que o YAML declara."
            ),
            incidente=(
                "Supply-chain do Codecov (abr/2021): o script bash uploader foi adulterado e "
                "exfiltrou segredos de clientes por cerca de dois meses antes da detecção — o "
                "atraso é o sintoma clássico de visibilidade e alerta insuficientes."
            ),
        ),
    ]
}


def avaliar(
    classes: dict[str, ClasseCICDSEC] | None = None,
) -> dict[StatusCobertura, tuple[str, ...]]:
    """Particiona `classes` (padrão: `CLASSES`) em coberto/parcial/nao-coberto.

    Levanta ``ValueError`` quando a partição não é válida: falta alguma das dez classes do eixo,
    sobra alguma fora dele, ou a chave do dict não bate com `ClasseCICDSEC.id`. A exigência de
    `motivo`/`incidente` em toda classe `nao-coberto` já foi trancada em `ClasseCICDSEC.__post_init__`
    — não é possível montar o dict de entrada com uma ausência calada.
    """
    classes = CLASSES if classes is None else classes

    for chave, classe in classes.items():
        if classe.id != chave:
            raise ValueError(f"chave '{chave}' não bate com ClasseCICDSEC.id '{classe.id}'")

    ids = set(classes)
    faltando = IDS_CICD_SEC - ids
    fora_do_eixo = ids - IDS_CICD_SEC
    if faltando or fora_do_eixo:
        raise ValueError(
            f"partição incompleta do eixo CICD-SEC-1..10: faltando={sorted(faltando)} "
            f"fora_do_eixo={sorted(fora_do_eixo)}"
        )

    particao: dict[StatusCobertura, list[str]] = {status: [] for status in StatusCobertura}
    for chave, classe in classes.items():
        particao[classe.status].append(chave)

    return {status: tuple(sorted(valores)) for status, valores in particao.items()}
