"""Descoberta e carregamento de arquivos de workflow do GitHub Actions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from esteira.core.models import Workflow

_YAML_EXTS = {".yml", ".yaml"}


def iter_workflow_files(root: Path | str) -> list[Path]:
    """Descobre os arquivos de workflow a partir de ``root``.

    Aceita: um arquivo YAML direto, um repositório (procura em
    ``.github/workflows/``) ou um diretório de workflows apontado diretamente.
    """
    root = Path(root)
    if root.is_file():
        return [root] if root.suffix in _YAML_EXTS else []
    if not root.is_dir():
        return []

    workflows_dir = root / ".github" / "workflows"
    if workflows_dir.is_dir():
        return _yaml_in(workflows_dir)
    # o usuário pode ter apontado direto para o diretório de workflows
    return _yaml_in(root)


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
