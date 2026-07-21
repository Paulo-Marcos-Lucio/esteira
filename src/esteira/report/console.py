"""Renderizador para terminal."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from esteira.core.models import ScanResult, Severity

_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    if not result.findings:
        console.print(
            f"[bold green]✓ Nenhum problema encontrado[/] "
            f"[dim]({result.files_scanned} workflow(s)).[/]"
        )
        return

    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Checagem", no_wrap=True)
    table.add_column("Local", overflow="fold")
    table.add_column("Detalhe", overflow="fold")
    for finding in result.sorted():
        table.add_row(
            Text(finding.severity.value.upper(), style=_STYLE[finding.severity]),
            finding.check_id,
            f"{finding.path.replace(chr(92), '/')}:{finding.line}",
            finding.detail,
        )
    console.print(table)

    counts = _counts(result)
    parts = [f"[{_STYLE[s]}] {s.value}: {counts[s]} [/]" for s in Severity if counts[s]]
    console.print(
        f"\n[bold]{len(result.findings)} achado(s)[/] em {result.files_scanned} workflow(s) — "
        + "  ".join(parts)
    )


def _counts(result: ScanResult) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for finding in result.findings:
        counts[finding.severity] += 1
    return counts
