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


class FindingType(str, Enum):
    """Em qual SUPERFÍCIE do workflow o achado vive — independente da severidade e do
    rótulo OWASP, que classificam o IMPACTO, não o ponto de origem.

    Existe para quem consome o `-f json` (dashboard, triagem) agrupar achados por área
    de correção sem reabrir o detector de cada checagem: `SCRIPT` se corrige editando o
    `run:`, `SUPPLY_CHAIN` trocando um `uses:`, e assim por diante — a lista de checagens
    de cada valor está fixada em `checks/catalog.py::CATALOG` (ver
    `tests/test_catalogo.py::test_toda_checagem_declara_type_e_confidence`).
    """

    TRIGGER = "trigger"  # como/quando o workflow dispara e que contexto de privilégio herda
    PERMISSIONS = "permissions"  # escopo do GITHUB_TOKEN ou do cofre de segredos concedido
    SUPPLY_CHAIN = "supply_chain"  # fixação (ou falta dela) de action/imagem/reusable externo
    SCRIPT = "script"  # código executado dentro de um step (`run:`)
    SECRET_HANDLING = "secret_handling"  # caminho de exposição de credencial já presente
    STRUCTURE = "structure"  # o próprio arquivo de workflow, antes de qualquer análise semântica


class Confidence(str, Enum):
    """Confiança de que o FATO capturado é risco explorável — não uma medida de acerto da
    extração, que aqui é sempre determinística (parse de YAML + regex sobre o texto do
    `run:`, sem heurística estatística). O que varia por checagem é se o fato, quando
    encontrado, já é problema em qualquer repositório, ou só dependendo de como o
    repositório é operado, ou é puramente uma recomendação de boa prática.

    - HIGH: o padrão encontrado é explorável em qualquer contexto de implantação.
    - MEDIUM: risco real, mas cuja gravidade prática depende do repositório (público vs.
      privado, quem pode abrir PR, o que o job de fato faz) — a checagem não tem como saber.
    - LOW: acionável como boa prática/reprodutibilidade, não como exploração direta; o
      próprio catálogo descreve o achado como informativo.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    path: str
    line: int
    detail: str
    recommendation: str
    #: Superfície do workflow e confiança de exploração — ver `FindingType` e `Confidence`.
    #: Herdados do `CheckMeta` da checagem que disparou (via `catalog.make_finding`); toda
    #: entrada de `CATALOG` declara os dois (ver
    #: `tests/test_catalogo.py::test_toda_checagem_declara_type_e_confidence`). Sem default:
    #: uma checagem nova sem os dois quebra a IMPORTAÇÃO do módulo, antes de qualquer teste.
    finding_type: FindingType
    confidence: Confidence
    evidence: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    # Sugestão concreta de correção específica do achado (ex.: env indirection para
    # script-injection). Complementa a 'recommendation' genérica do catálogo; None quando
    # a checagem não gera uma sugestão acionável por achado.
    fix_suggestion: str | None = None


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

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
