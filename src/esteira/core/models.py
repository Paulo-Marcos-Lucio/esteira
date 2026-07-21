"""Modelos de domínio do Esteira."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
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


@dataclass
class Workflow:
    """Um arquivo de workflow carregado: texto cru + árvore YAML."""

    path: str
    text: str
    data: dict[str, Any] | None  # None se o YAML não pôde ser parseado

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def find_line(self, needle: str, default: int = 1) -> int:
        for index, line in enumerate(self.lines, start=1):
            if needle in line:
                return index
        return default


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
