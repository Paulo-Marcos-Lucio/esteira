"""Exceções declaradas em config: supressão por (regra opcional, glob de path, motivo).

Ponto ES-03b da trilha de config: `.esteira.yml` na raiz varrida declara achados que não
contam, com o MOTIVO registrado (auditável, ao contrário da supressão inline que não deixa
rastro fora do próprio arquivo de workflow). ES-03c (baseline) e ES-03d (hash de config na
proveniência) constroem em cima deste mesmo arquivo — aqui só a leitura e o casamento.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

CONFIG_FILENAME = ".esteira.yml"


@dataclass(frozen=True)
class Excecao:
    """Uma entrada de `excecoes:` no config: casa por path (glob POSIX) e, se `regra` vier
    preenchida, também pelo `check_id`. `expira` é opcional — sem ela, a exceção não vence."""

    path: str
    motivo: str
    regra: str | None = None
    expira: date | None = None

    def expirada(self, hoje: date) -> bool:
        return self.expira is not None and self.expira < hoje

    def casa(self, check_id: str, achado_path: str) -> bool:
        if self.regra is not None and self.regra != check_id:
            return False
        return PurePosixPath(achado_path).match(self.path)


def _excecao_de(item: dict[str, Any]) -> Excecao | None:
    caminho_glob = item.get("path")
    motivo = item.get("motivo")
    if not isinstance(caminho_glob, str) or not caminho_glob:
        return None
    if not isinstance(motivo, str) or not motivo:
        return None
    regra = item.get("regra")
    regra = regra if isinstance(regra, str) and regra else None
    expira_raw = item.get("expira")
    # Só string ISO ('AAAA-MM-DD'); qualquer outra forma é tratada como ausente — fail-closed
    # seria travar a config inteira, mas um typo aqui não deve derrubar a varredura inteira,
    # só deixar ESSA exceção sem validade (nunca vence: o lado conservador, não o silencioso).
    expira = date.fromisoformat(expira_raw) if isinstance(expira_raw, str) else None
    return Excecao(path=caminho_glob, motivo=motivo, regra=regra, expira=expira)


def carregar_excecoes(base: Path) -> list[Excecao]:
    """Lê `<base>/.esteira.yml`. Arquivo ausente, vazio ou sem `excecoes:` válida => lista
    vazia — o comportamento sem config continua sendo o de antes deste item (sem supressão)."""
    caminho = base / CONFIG_FILENAME
    if not caminho.is_file():
        return []
    bruto = yaml.safe_load(caminho.read_text(encoding="utf-8"))
    if not isinstance(bruto, dict):
        return []
    itens = bruto.get("excecoes")
    if not isinstance(itens, list):
        return []
    return [
        excecao
        for item in itens
        if isinstance(item, dict)
        for excecao in [_excecao_de(item)]
        if excecao is not None
    ]
