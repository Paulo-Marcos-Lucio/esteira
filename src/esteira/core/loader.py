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
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        parsed = None
    data = parsed if isinstance(parsed, dict) else None
    return Workflow(path=str(path), text=text, data=data)


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
