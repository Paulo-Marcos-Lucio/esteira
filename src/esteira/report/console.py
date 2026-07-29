"""Renderizador para terminal."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from esteira.core.models import Finding, ScanResult, Severity

_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
# Rótulo em PT-BR na tela; o identificador em inglês (`severity.value`) continua no JSON/SARIF.
_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRÍTICA",
    Severity.HIGH: "ALTA",
    Severity.MEDIUM: "MÉDIA",
    Severity.LOW: "BAIXA",
    Severity.INFO: "INFO",
}
_TOP_N = 3


def txt(value: object) -> Text:
    """Embrulha dado vindo do ALVO para o rich não interpretar como marcação.

    O `rich` lê `[tag]` no texto: um workflow com um job chamado `[/]` derrubava o relatório
    inteiro com MarkupError DEPOIS de a varredura já ter encontrado os achados — supressão de
    detecção a custo zero para quem controla o arquivo auditado. E `[bold green]` num campo
    externo permitia forjar texto colorido dentro do relatório entregue ao cliente. Todo
    campo de origem externa (caminho, detalhe, evidência, id) passa por aqui.
    """
    return Text(str(value))


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    if not result.findings:
        console.print(
            f"[bold green]✓ Nenhum problema encontrado[/] "
            f"[dim]({result.files_scanned} workflow(s)).[/]"
        )
        return

    findings = result.sorted()
    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Checagem", no_wrap=True)
    table.add_column("Local", overflow="fold")
    table.add_column("Detalhe", overflow="fold")
    for finding in findings:
        table.add_row(
            Text(_LABEL[finding.severity], style=_STYLE[finding.severity]),
            txt(finding.check_id),
            txt(f"{finding.path}:{finding.line}"),
            txt(finding.detail),
        )
    console.print(table)
    console.print(_plano_de_acao(findings))

    counts = _counts(result)
    parts = [f"[{_STYLE[s]}] {_LABEL[s]}: {counts[s]} [/]" for s in Severity if counts[s]]
    console.print(
        f"\n[bold]{len(result.findings)} achado(s)[/] em {result.files_scanned} workflow(s) — "
        + "  ".join(parts)
    )


def _plano_de_acao(findings: list[Finding]) -> Panel:
    """Os piores achados COM a correção — o que fazer, não só o que está errado.

    A `fix_suggestion` (correção concreta por achado) é o ativo mais valioso da ferramenta e
    só existia no JSON/SARIF; na saída que 100% dos usuários veem primeiro, nada.
    """
    corpo = Text()
    for posicao, finding in enumerate(findings[:_TOP_N], start=1):
        if posicao > 1:
            corpo.append("\n\n")
        corpo.append(f"{posicao}. ", style="bold")
        corpo.append(_LABEL[finding.severity], style=_STYLE[finding.severity])
        corpo.append(" ")
        corpo.append(f"{finding.path}:{finding.line}", style="dim")
        corpo.append("\n   ")
        corpo.append(finding.fix_suggestion or finding.recommendation)
    return Panel(
        corpo,
        title="🎯 Plano de ação — comece por aqui",
        border_style="green",
        box=box.ROUNDED,
    )


def _counts(result: ScanResult) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for finding in result.findings:
        counts[finding.severity] += 1
    return counts
