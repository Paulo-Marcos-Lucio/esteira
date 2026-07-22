"""Interface de linha de comando do Esteira."""

from __future__ import annotations

import contextlib
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from esteira import __version__
from esteira.checks.catalog import CATALOG
from esteira.checks.engine import scan as run_scan
from esteira.core.models import ScanResult, Severity
from esteira.report import console as console_report
from esteira.report.json_report import to_json
from esteira.report.sarif import to_sarif

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Esteira — audita a segurança de workflows do GitHub Actions.",
)
err = Console(stderr=True)


class Format(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


class FailOn(str, Enum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    def rank(self) -> int:
        return 99 if self is FailOn.none else Severity(self.value).rank


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"esteira {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    _v: bool = typer.Option(
        False, "--version", "-V", callback=_version_cb, is_eager=True, help="Mostra a versão."
    ),
) -> None:
    pass


def _emit(result: ScanResult, fmt: Format, output: Path | None) -> None:
    if fmt is Format.console:
        console_report.render(result)
        return
    payload = to_json(result) if fmt is Format.json else to_sarif(result)
    if output is not None:
        output.write_text(payload + "\n", encoding="utf-8")
        err.print(f"[green]{fmt.value}[/] salvo em [bold]{output}[/]")
    else:
        typer.echo(payload)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repositório, arquivo ou diretório de workflows."),
    fmt: Format = typer.Option(Format.console, "--format", "-f", help="Formato de saída."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Arquivo de saída."),
    fail_on: FailOn = typer.Option(FailOn.high, "--fail-on", help="Severidade que faz sair com 1."),
    only: list[str] = typer.Option([], "--only", help="Roda apenas estas checagens."),
    skip: list[str] = typer.Option([], "--skip", help="Pula estas checagens."),
) -> None:
    """Audita os workflows do GitHub Actions."""
    unknown = sorted((set(only) | set(skip)) - set(CATALOG))
    if unknown:
        err.print(f"[red]Checagem(ns) desconhecida(s):[/] {', '.join(unknown)}")
        err.print(f"[dim]IDs válidos:[/] {', '.join(sorted(CATALOG))}")
        raise typer.Exit(2)
    if fmt is Format.console and output is not None:
        raise typer.BadParameter("só faz sentido com --format json|sarif.", param_hint="--output")

    result = run_scan(path, only=only or None, skip=skip or None)
    if result.files_scanned == 0:
        err.print(
            f"[red]Nenhum workflow encontrado em[/] [bold]{path}[/]. "
            "Aponte para um repositório (com .github/workflows/), um diretório de "
            "workflows, ou um arquivo .yml/.yaml."
        )
        raise typer.Exit(2)

    _emit(result, fmt, output)
    top = result.max_severity()
    raise typer.Exit(1 if top is not None and top.rank >= fail_on.rank() else 0)


@app.command()
def rules() -> None:
    """Lista todas as checagens."""
    table = Table(title="Checagens do Esteira", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severidade", no_wrap=True)
    table.add_column("Título")
    table.add_column("OWASP / CWE", no_wrap=True)
    for meta in CATALOG.values():
        table.add_row(
            meta.id,
            meta.severity.value,
            meta.title,
            f"{(meta.owasp or '—').split(':')[0]} · {meta.cwe or '—'}",
        )
    Console().print(table)


def _force_utf8() -> None:
    """Evita UnicodeEncodeError no console legado do Windows (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    _force_utf8()
    app()
