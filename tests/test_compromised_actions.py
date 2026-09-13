"""CAP A — confirmador de ação comprometida (supply-chain), estático/offline-first.

Cobre: disparo pelo SHA malicioso do snapshot (tj-actions/changed-files e reviewdog/action-setup
pelo commit DEFINITIVO), NÃO-disparo na tag remediada (reviewdog @v1, re-tageada pós-incidente),
NÃO-disparo em ref seguro pós-incidente (baixo-FP), normalização de subpath, NÃO-disparo em action
fora da lista, e o seam ``--online`` (advisory_lookup injetável). O motor não toca a rede: a única
porta é o seam, injetado nos testes.
"""

from __future__ import annotations

import yaml

from esteira.checks.catalog import CATALOG
from esteira.checks.compromised_actions import (
    CATALOG_ENTRIES,
    KNOWN_COMPROMISED,
    check_compromised_actions,
)
from esteira.core.models import Severity, Workflow

_SHA_MALICIOSO = "0e58ed8671d6b60d0890c21b07f8835ace038e67"  # tj-actions CVE-2025-30066
_SHA_SEGURO = "b4ffde65f46336ab88eb53be808477a3936bae11"  # commit qualquer, não-incidente


def _wf(text: str, path: str = "w.yml") -> Workflow:
    data = yaml.safe_load(text)
    return Workflow(path=path, text=text, data=data if isinstance(data, dict) else None)


def _uses(action_ref: str) -> Workflow:
    return _wf(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: {action_ref}\n"
    )


def _ids(wf: Workflow) -> set[str]:
    return {f.check_id for f in check_compromised_actions(wf)}


def test_sha_malicioso_do_snapshot_dispara() -> None:
    wf = _uses(f"tj-actions/changed-files@{_SHA_MALICIOSO}")
    achados = check_compromised_actions(wf)
    assert len(achados) == 1
    f = achados[0]
    assert f.check_id == "known-compromised-action"
    assert f.severity is Severity.CRITICAL
    assert "CVE-2025-30066" in (f.detail or "")
    # Evidência é metadado (action@ref), nunca conteúdo além disso.
    assert f.evidence == f"tj-actions/changed-files@{_SHA_MALICIOSO}"


def test_reviewdog_sha_malicioso_dispara() -> None:
    # A tag v1 foi repontada para este commit durante a janela (CVE-2025-30154); casamos pelo
    # SHA DEFINITIVO, não pela tag mutável.
    sha = "f0d342d24037bb11d26b9bd8496e0808ba32e9ec"
    assert "known-compromised-action" in _ids(_uses(f"reviewdog/action-setup@{sha}"))


def test_reviewdog_v1_remediada_nao_dispara_como_comprometida() -> None:
    # v1 já foi re-tageada para um commit limpo (3f401fe): marcar @v1 como "comprometida"
    # (CRÍTICA) hoje seria FP — a higiene da tag mutável cai em 'unpinned-action-thirdparty'.
    assert "known-compromised-action" not in _ids(_uses("reviewdog/action-setup@v1"))


def test_ref_seguro_pos_incidente_nao_dispara() -> None:
    # Quem já re-pinou num commit auditado NÃO pode virar falso-positivo (baixo-FP).
    assert _ids(_uses(f"tj-actions/changed-files@{_SHA_SEGURO}")) == set()


def test_action_fora_da_lista_nao_dispara() -> None:
    assert _ids(_uses(f"actions/checkout@{_SHA_SEGURO}")) == set()


def test_action_local_ou_sem_ref_ignorada() -> None:
    assert (
        _ids(_wf("on: push\njobs:\n  b:\n    steps:\n      - uses: ./.github/actions/x\n")) == set()
    )


def test_seam_online_complementa_o_snapshot() -> None:
    # advisory_lookup injetável (--online): uma action FORA do snapshot é confirmada por OSV/GHSA.
    wf = _uses(f"some/fresh-action@{_SHA_SEGURO}")

    def lookup(action: str) -> list[str]:
        return [_SHA_SEGURO] if action == "some/fresh-action" else []

    achados = check_compromised_actions(wf, advisory_lookup=lookup)
    assert len(achados) == 1
    assert "OSV/GHSA" in (achados[0].detail or "")


def test_seam_online_nao_falso_positiva_action_limpa() -> None:
    wf = _uses(f"actions/checkout@{_SHA_SEGURO}")
    assert check_compromised_actions(wf, advisory_lookup=lambda _a: []) == []


def test_sem_data_yaml_nao_quebra() -> None:
    assert check_compromised_actions(Workflow(path="x.yml", text=":", data=None)) == []


def test_catalog_entries_registrado_e_unico() -> None:
    ids = [m.id for m in CATALOG_ENTRIES]
    assert ids == ["known-compromised-action"]
    assert "known-compromised-action" in CATALOG
    # snapshot curado e não-vazio
    assert "tj-actions/changed-files" in KNOWN_COMPROMISED
