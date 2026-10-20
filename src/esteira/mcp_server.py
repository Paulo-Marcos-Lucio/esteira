"""Servidor MCP: expõe a varredura da Esteira a um cliente MCP (ex.: Claude Code).

Import deliberadamente isolado do `cli.py`: o SDK `mcp` fica num extra opcional
(`esteira[mcp]`), então quem só usa `esteira scan` não precisa instalá-lo. Importar este
módulo sem o extra levanta `ModuleNotFoundError` com o nome do pacote faltante — nunca um
`ImportError` silencioso dentro de `cli.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from esteira.checks.catalog import CATALOG
from esteira.checks.engine import scan as run_scan
from esteira.report.json_report import to_document

mcp = MCPServer(
    "esteira",
    version=__import__("esteira").__version__,
    instructions=(
        "Audita workflows do GitHub Actions (script injection, actions não fixadas por SHA, "
        "pull_request_target perigoso, permissões excessivas) e devolve o documento JSON "
        "versionado suite-appsec/1."
    ),
)


@mcp.tool()
def scan(
    path: str = ".",
    only: list[str] | None = None,
    skip: list[str] | None = None,
) -> dict[str, Any]:
    """Audita `path` (repositório, diretório de workflows ou arquivo .yml) e devolve o
    documento `suite-appsec/1` (achados, severidade, cobertura e proveniência).

    `only`/`skip` filtram pelos IDs do catálogo (ver a tool `rules`); um ID desconhecido
    levanta `ValueError` em vez de rodar uma varredura vazia e devolver um JSON "limpo" que
    não provaria nada.
    """
    unknown = sorted((set(only or []) | set(skip or [])) - set(CATALOG))
    if unknown:
        raise ValueError(f"Checagem(ns) desconhecida(s): {', '.join(unknown)}")
    result = run_scan(Path(path), only=only or None, skip=skip or None)
    return to_document(result)


@mcp.tool()
def rules() -> list[dict[str, str]]:
    """Lista o catálogo de checagens (id, severidade, título, OWASP/CWE)."""
    return [
        {
            "id": meta.id,
            "severity": meta.severity.value,
            "title": meta.title,
            "owasp": meta.owasp or "",
            "cwe": meta.cwe or "",
        }
        for meta in CATALOG.values()
    ]


def main() -> None:
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
