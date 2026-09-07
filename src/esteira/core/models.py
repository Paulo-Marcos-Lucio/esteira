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


class Profile(str, Enum):
    """Contexto do repositório varrido, para ajustar severidade por risco real.

    O catálogo declara UMA severidade padrão por checagem, mas o mesmo achado
    não pesa igual em todo contexto — um runner self-hosted é vetor de
    execução externa num repositório público (qualquer PR de fork o aciona) e
    é só higiene de infraestrutura própria num repositório interno, onde
    só quem já tem push abre PR. `checks/profiles.py` é a fonte declarada de
    quais checagens mudam, para qual severidade, e por quê.
    """

    OSS_PUBLICO = "oss-publico"
    INTERNO = "interno"


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
    # Por que a severidade aqui difere do padrão do catálogo — preenchido só quando
    # `checks/profiles.py` ajustou este achado. Sem isto, uma severidade diferente do
    # `rules()` do CATALOG pareceria erro de relatório, não decisão declarada de perfil.
    severity_note: str | None = None


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
    # Perfil de severidade aplicado (`None` = nenhum, severidades puras do catálogo).
    # Carregado até o envelope para a mudança de severidade nunca ficar implícita.
    profile: Profile | None = None

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
