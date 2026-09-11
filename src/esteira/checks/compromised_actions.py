"""Confirmador de ação comprometida (supply-chain de GitHub Actions) — estático, offline-first.

Responde à pergunta de contrato de 2026 — "estou exposto ao tj-actions / Shai-Hulud?" — SEM
rodar ataque na infra do cliente: casa cada ``uses: owner/action@ref`` do workflow contra um
SNAPSHOT curado e datado de actions com incidente de supply-chain CONHECIDO. É read-only e
determinístico; a vantagem sobre um motor ATIVO (que roda um attack-plan na pipeline do cliente)
é de LGPD/residência de dado — a Esteira só LÊ o YAML, nada é enviado nem executado.

``--online`` (seam injetável :data:`AdvisoryLookup`): quando fornecido, complementa o snapshot com
uma consulta read-only a OSV/GHSA do ecossistema ``actions``. O DEFAULT é offline (só o snapshot),
então a detecção funciona sem rede — "offline-first, ``--online`` para frescor". "Inconclusivo não é
ausência": o snapshot é DATADO; não casar não prova que a action é segura, só que ela não está na
lista conhecida na data do snapshot.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from esteira.checks.catalog import CATALOG, CheckMeta, make_finding
from esteira.checks.detectors import _action_ref, _jobs, _steps_of
from esteira.core.models import Finding, Severity, Workflow

#: Data do snapshot curado à mão. A ausência de match fora desta data NÃO é prova de segurança.
SNAPSHOT_DATA = "2026-09-11"


@dataclass(frozen=True)
class _Advisory:
    """Um incidente de supply-chain conhecido de uma action."""

    refs: frozenset[str]  # SHAs/tags comprometidos (comparados em minúsculo)
    fonte: str  # CVE/advisory
    nota: str  # explicação curta para o laudo


# Snapshot curado de incidentes REAIS de supply-chain de GitHub Actions. Casamos por ref EXATO
# (SHA malicioso ou tag comprometida) — não por "todas as tags" — para não gerar falso-positivo
# em quem já re-pinou num commit auditado pós-incidente. É o eixo de baixo-FP do produto.
KNOWN_COMPROMISED: dict[str, _Advisory] = {
    "tj-actions/changed-files": _Advisory(
        refs=frozenset({"0e58ed8671d6b60d0890c21b07f8835ace038e67"}),
        fonte="CVE-2025-30066",
        nota=(
            "commit malicioso para o qual as tags foram repontadas (mar/2025); imprimia segredos "
            "do runner nos logs. Rotacione TODOS os segredos que o workflow expôs."
        ),
    ),
    "reviewdog/action-setup": _Advisory(
        refs=frozenset({"f0d342d24037bb11d26b9bd8496e0808ba32e9ec"}),
        fonte="CVE-2025-30154",
        nota=(
            "commit malicioso (11/mar/2025, 18:42-20:31 UTC) para o qual a tag v1 foi repontada; "
            "dumpava segredos nos logs e foi o gatilho da cadeia que atingiu tj-actions. A tag v1 "
            "já foi remediada (re-tag para 3f401fe), por isso listamos o SHA malicioso DEFINITIVO "
            "e não a tag (evita FP em quem usa @v1 hoje, limpo; a higiene da tag mutável cai no "
            "'unpinned-action-thirdparty'). Re-pine por SHA auditado e rotacione os segredos."
        ),
    ),
}

#: Seam ``--online``: dado um ``owner/action``, devolve a lista de refs comprometidos (OSV/GHSA).
AdvisoryLookup = Callable[[str], list[str]]


CATALOG_ENTRIES: list[CheckMeta] = [
    CheckMeta(
        "known-compromised-action",
        "Ação de terceiro comprometida (supply-chain) em uso",
        Severity.CRITICAL,
        "Um 'uses:' aponta para uma action/ref com incidente de supply-chain CONHECIDO (ex.: "
        "tj-actions/changed-files, CVE-2025-30066). Remova ou re-pine por SHA de um commit auditado "
        "pós-incidente AGORA, e rotacione todos os segredos que este workflow pôde expor.",
        cwe="CWE-506",
        owasp="A03:2025 Software Supply Chain Failures",
    ),
]


def check_compromised_actions(
    wf: Workflow, advisory_lookup: AdvisoryLookup | None = None
) -> list[Finding]:
    """Casa cada ``uses:`` contra o snapshot (offline) e, se dado, contra ``advisory_lookup`` (--online).

    Read-only: só lê a árvore YAML já parseada. O ``advisory_lookup`` é o único ponto de rede — e é
    injetável e opcional; sem ele, a checagem é 100% offline (só o snapshot).
    """
    out: list[Finding] = []
    if wf.data is None:
        return out
    for job in _jobs(wf.data):
        for step in _steps_of(job):
            parsed = _action_ref(step.get("uses"))
            if parsed is None:
                continue
            action, ref = parsed
            chave = action.lower()
            # Normaliza subpath: `owner/action/subdir@ref` aponta pro MESMO repositório que
            # `owner/action@ref` — o incidente de supply-chain é do repo, não do subdiretório.
            raiz = "/".join(chave.split("/")[:2])
            ref_baixo = ref.lower()

            adv = KNOWN_COMPROMISED.get(raiz)
            comprometido = adv is not None and ref_baixo in adv.refs
            fonte = adv.fonte if (adv and comprometido) else ""
            nota = adv.nota if (adv and comprometido) else ""

            if (
                not comprometido
                and advisory_lookup is not None
                and ref_baixo in {x.lower() for x in advisory_lookup(raiz)}
            ):
                comprometido, fonte, nota = True, "OSV/GHSA", "advisory OSV/GHSA (--online)."

            if comprometido:
                linha = wf.find_line(f"{action}@{ref}") or wf.find_line(str(action)) or 1
                out.append(
                    make_finding(
                        "known-compromised-action",
                        wf.path,
                        linha,
                        f"'{action}@{ref}' consta como comprometida ({fonte}): {nota}",
                        evidence=f"{action}@{ref}",
                    )
                )
    return out


# Auto-registro no catálogo (para make_finding e os relatórios conhecerem o id sem editar catalog.py).
for _meta in CATALOG_ENTRIES:
    CATALOG.setdefault(_meta.id, _meta)
