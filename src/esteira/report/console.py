"""Renderizador para terminal."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from esteira.core.models import Finding, Profile, ScanResult, Severity

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
        detalhe = finding.detail
        if finding.severity_note is not None:
            detalhe += " ⚠"
        table.add_row(
            Text(_LABEL[finding.severity], style=_STYLE[finding.severity]),
            txt(finding.check_id),
            txt(f"{finding.path}:{finding.line}"),
            txt(detalhe),
        )
    console.print(table)
    if result.profile is not None:
        console.print(_perfil_aplicado(result.profile, findings))
    console.print(_plano_de_acao(findings))

    counts = _counts(result)
    parts = [f"[{_STYLE[s]}] {_LABEL[s]}: {counts[s]} [/]" for s in Severity if counts[s]]
    console.print(
        f"\n[bold]{len(result.findings)} achado(s)[/] em {result.files_scanned} workflow(s) — "
        + "  ".join(parts)
    )


def _perfil_aplicado(profile: Profile, findings: list[Finding]) -> Panel:
    """As severidades que o perfil mudou, com a justificativa — nunca um número mudo.

    Só lista o que de fato mudou (`severity_note` presente); um perfil sem ajuste aplicável
    a este scan não gera painel vazio de confusão.
    """
    ajustadas = [f for f in findings if f.severity_note is not None]
    corpo = Text()
    if not ajustadas:
        corpo.append("Nenhuma severidade deste scan foi ajustada por este perfil.", style="dim")
    else:
        for posicao, finding in enumerate(ajustadas):
            if posicao:
                corpo.append("\n")
            corpo.append(f"⚠ {finding.check_id}", style="bold")
            corpo.append(f" ({finding.path}:{finding.line}) — ")
            corpo.append(str(finding.severity_note))
    return Panel(
        corpo,
        title=f"Perfil aplicado: {profile.value}",
        border_style="magenta",
        box=box.ROUNDED,
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
