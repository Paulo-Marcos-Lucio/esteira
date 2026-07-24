"""Descoberta e carregamento de arquivos de workflow do GitHub Actions."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from esteira.core.models import Workflow

_YAML_EXTS = {".yml", ".yaml"}

# Diretórios em que nunca há workflows do *repositório* — só cópias de dependências
# (vendoradas) ou artefatos de VCS/cache. Descer neles geraria falso-positivo (auditaríamos
# o CI de uma dependência) e desperdiçaria I/O. Além destes, todo diretório oculto (começa
# com ``.``) é podado, exceto o próprio ``.github``.
_PRUNE_DIRS = frozenset({"node_modules", "venv", "__pycache__", "site-packages", "vendor"})


def iter_workflow_files(root: Path | str) -> list[Path]:
    """Descobre os arquivos de workflow a partir de ``root``.

    Aceita: um arquivo YAML direto, um repositório (procura em ``.github/workflows/``)
    ou um diretório de workflows apontado diretamente. Em um **monorepo**, encontra
    todo ``.github/workflows/`` sob ``root`` — o do repositório e o de cada subprojeto —
    e não apenas o do nível superior.
    """
    root = Path(root)
    if root.is_file():
        return [root] if root.suffix in _YAML_EXTS else []
    if not root.is_dir():
        return []

    workflow_dirs = _find_workflow_dirs(root)
    if workflow_dirs:
        files = {p for directory in workflow_dirs for p in _yaml_in(directory)}
        return sorted(files)
    # o usuário pode ter apontado direto para o diretório de workflows
    return _yaml_in(root)


def _find_workflow_dirs(root: Path) -> list[Path]:
    """Todos os ``.github/workflows/`` sob ``root`` (suporte a monorepo).

    Poda diretórios de dependência vendorada e caches/VCS ocultos para não confundir o
    CI de uma dependência com o do repositório auditado.
    """
    found: list[Path] = []
    for dirpath, dirnames, _files in os.walk(root):
        # Poda in-place: os.walk não desce nos nomes removidos de ``dirnames``.
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _PRUNE_DIRS and (name == ".github" or not name.startswith("."))
        ]
        current = Path(dirpath)
        if current.name == "workflows" and current.parent.name == ".github":
            found.append(current)
    return found


def _yaml_in(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in _YAML_EXTS)


def load(path: Path | str) -> Workflow:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    parse_error: str | None = None
    try:
        parsed = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        # Não só YAMLError: flow profundamente aninhado estoura RecursionError, que
        # também precisa virar 'invalid-yaml' em vez de derrubar a varredura.
        parsed = None
        parse_error = _format_yaml_error(exc)
    data = parsed if isinstance(parsed, dict) else None
    return Workflow(path=str(path), text=text, data=data, parse_error=parse_error)


def _format_yaml_error(exc: Exception) -> str:
    """Mensagem curta e legível a partir de um erro de parse."""
    problem = getattr(exc, "problem", None) or type(exc).__name__
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        return f"{problem} (linha {mark.line + 1}, coluna {mark.column + 1})"
    return str(problem)


def get_triggers(data: dict[Any, Any]) -> Any:
    """Devolve o valor de ``on:`` — que o YAML 1.1 pode ter virado a chave ``True``."""
    if "on" in data:
        return data["on"]
    if True in data:  # 'on' foi interpretado como booleano
        return data[True]
    return None


def trigger_names(data: dict[Any, Any]) -> set[str]:
    triggers = get_triggers(data)
    if isinstance(triggers, str):
        return {triggers}
    if isinstance(triggers, list):
        return {str(t) for t in triggers}
    if isinstance(triggers, dict):
        return {str(k) for k in triggers}
    return set()
