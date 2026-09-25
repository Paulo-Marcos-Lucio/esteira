"""Modelos de domínio do Esteira."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confianca(str, Enum):
    """Confiança de que o achado é um verdadeiro-positivo (não a severidade do risco).

    Distinta de ``Severity``: uma checagem pode ser CRITICAL em severidade e ainda ter
    confiança BAIXA (achado indireto, sujeito a falso-positivo) — os dois eixos são
    ortogonais, por isso vivem em campos separados no ``Finding``.
    """

    ALTA = "alta"
    MEDIA = "media"
    BAIXA = "baixa"

    @property
    def rank(self) -> int:
        return _CONFIANCA_RANK[self]


_CONFIANCA_RANK: dict[Confianca, int] = {
    Confianca.BAIXA: 0,
    Confianca.MEDIA: 1,
    Confianca.ALTA: 2,
}


class Persona(str, Enum):
    """Para quem o achado é relevante — controla o que aparece por padrão vs. sob pedido.

    Ordem crescente de rigor: ``REGULAR`` é o que todo repositório quer ver; ``PEDANTIC``
    soma achados de estilo/robustez que nem todo time prioriza; ``AUDITOR`` soma o que só
    interessa a uma varredura exaustiva (a garantia de monotonicidade — auditor ⊇ pedantic
    ⊇ regular — é o que a suíte de invariantes de ES-05e trava).
    """

    REGULAR = "regular"
    PEDANTIC = "pedantic"
    AUDITOR = "auditor"

    @property
    def rank(self) -> int:
        return _PERSONA_RANK[self]


_PERSONA_RANK: dict[Persona, int] = {
    Persona.REGULAR: 0,
    Persona.PEDANTIC: 1,
    Persona.AUDITOR: 2,
}


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    path: str
    line: int
    detail: str
    recommendation: str
    evidence: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    # Sugestão concreta de correção específica do achado (ex.: env indirection para
    # script-injection). Complementa a 'recommendation' genérica do catálogo; None quando
    # a checagem não gera uma sugestão acionável por achado.
    fix_suggestion: str | None = None
    # Confiança e persona: defaults do catálogo (ver CheckMeta), com override por achado
    # pelo mesmo mecanismo que 'severity' já usa em make_finding — um caso concreto pode
    # ser mais/menos confiável que a média da checagem que o gerou.
    confidence: Confianca = Confianca.ALTA
    persona: Persona = Persona.REGULAR


@dataclass
class Workflow:
    """Um arquivo de workflow carregado: texto cru + árvore YAML."""

    path: str
    text: str
    data: dict[str, Any] | None  # None se o YAML não pôde ser parseado
    parse_error: str | None = None  # mensagem quando o YAML não parseou (data também é None)

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def find_line(self, needle: str, default: int = 1, start: int = 1) -> int:
        # Indexa a lista a partir de ``start`` em vez de iterar desde a linha 1 descartando o
        # que vem antes. Semântica idêntica (1ª linha >= start contendo ``needle``, senão
        # ``default``), mas com o ``cursor`` monotônico das checagens o custo total cai de
        # O(n²) para O(n): um workflow gerado com milhares de steps fazia a auditoria — que
        # roda DENTRO do CI — escalar em quadrado (8 mil `uses:` ⇒ ~3 s só de âncora), o que um
        # workflow hostil poderia inflar até estourar o timeout do próprio gate de segurança.
        lines = self.lines
        for index in range(max(start, 1), len(lines) + 1):
            if needle in lines[index - 1]:
                return index
        return default


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    # Raiz varrida, carregada até o relatório porque a proveniência (`commit`) tem de
    # identificar o CÓDIGO AUDITADO, não o diretório de onde a ferramenta foi invocada:
    # `esteira scan /outro/repo` rodando de dentro deste repo carimbaria o commit errado —
    # o pior tipo de metadado, o que parece certo.
    root: str | None = None
    # Cobertura da varredura. O MESMO `--only/--skip` que filtra os achados também reduz o
    # conjunto de checagens que de fato rodou: sem declarar isso, `--only <uma-checagem>` sem
    # achados certificava o repositório inteiro como limpo — a nota cega à cobertura. O
    # catálogo é o denominador honesto; `checagens_omitidas` é o que o operador deixou de
    # fora. Uma varredura parcial não certifica ausência de problema (ver `cobertura_parcial`).
    checagens_omitidas: tuple[str, ...] = ()
    checagens_total: int = 0

    @property
    def cobertura_parcial(self) -> bool:
        """Alguma checagem do catálogo ficou de fora (--only/--skip): o resultado fala só do
        que rodou, não do alvo inteiro. É o que impede a varredura recortada de passar verde."""
        return bool(self.checagens_omitidas)

    @property
    def checagens_executadas(self) -> int:
        """Quantas checagens do catálogo de fato rodaram — o numerador do laudo de cobertura."""
        return self.checagens_total - len(self.checagens_omitidas)

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
