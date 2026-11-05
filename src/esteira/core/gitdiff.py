"""Diff local contra uma referência git, restrito a ``.github/**`` — base do ``--desde`` da CLI.

Existe para que ``esteira scan --desde <ref>`` possa auditar só o que uma mudança tocou, sem
reabrir achados pré-existentes em arquivos que ninguém mexeu no PR. O pathspec ``.github`` é
aplicado no PRÓPRIO comando git, não depois em Python: é o que torna a garantia "nunca acusa
achado fora do diff" verdadeira por construção, e não por um filtro que alguém pode esquecer de
chamar num novo caminho de código.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitDiffError(RuntimeError):
    """`git` ausente, `root` fora de um repositório, ou `ref` que o git não resolve."""


def arquivos_alterados(root: Path, ref: str) -> set[Path]:
    """Caminhos absolutos (resolvidos) sob ``.github/`` alterados entre ``ref`` e o working tree.

    Nunca levanta por engano: qualquer falha do git (ref inexistente, diretório fora de um
    repositório, binário ausente) vira ``GitDiffError`` — explícito, em vez de devolver um
    conjunto vazio que a CLI leria como "nada mudou" e silenciaria achados de verdade.
    """
    base = root if root.is_dir() else root.parent
    toplevel = _toplevel(base)
    saida = subprocess.run(
        ["git", "-C", str(toplevel), "diff", "--name-only", ref, "--", ".github"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if saida.returncode != 0:
        raise GitDiffError(saida.stderr.strip() or f"'git diff' falhou para a referência {ref!r}")
    return {(toplevel / linha).resolve() for linha in saida.stdout.splitlines() if linha.strip()}


def _toplevel(base: Path) -> Path:
    try:
        saida = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError as exc:
        raise GitDiffError(f"não foi possível executar o git: {exc}") from exc
    if saida.returncode != 0:
        raise GitDiffError(f"{base} não é um repositório git (ou está fora de um)")
    return Path(saida.stdout.strip())
