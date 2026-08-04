"""Endurecimento de RESILIÊNCIA (2026-07-30): robustez em produção sobre workflows
DIVERSOS/malformados, distintos dos usados na calibração de acurácia.

Cada teste falha na versão anterior ao fix e passa depois — prova do defeito específico:

1. `find_line` era O(n²) (varria desde a linha 1 a cada chamada): um workflow gerado com
   milhares de steps fazia a auditoria — que roda DENTRO do CI — escalar em quadrado, um
   DoS do próprio gate de segurança. Agora indexa a partir de `start` → O(n).
2. YAML válido cujo topo NÃO é mapa (lista/escalar) caía no fallback por linha SEM sinal:
   estrutura inválida passava como "0 achados, exit 0" (fail-open). Agora vira `invalid-yaml`
   HIGH (fail-closed), sem perder os achados textuais do fallback.
3. `jobs:` presente mas não-mapa (lista/escalar) fazia TODA checagem por job devolver vazio
   em silêncio (no máximo um `missing-permissions` LOW, que não reprova o CI) — cegueira
   estrutural. Agora vira `invalid-yaml` HIGH (fail-closed).
"""

from __future__ import annotations

import time
from pathlib import Path

import yaml
from typer.testing import CliRunner

from esteira.checks.detectors import run_all
from esteira.checks.engine import scan
from esteira.cli import app
from esteira.core.models import Severity, Workflow

runner = CliRunner()


def _scan_ids(tmp_path: Path, text: str, name: str = "w.yml") -> set[str]:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(text, encoding="utf-8")
    return {f.check_id for f in scan(tmp_path).findings}


# --------------------------------------------------------------------------- #
# 1. find_line linear — o gargalo O(n²) que travava o gate em workflows grandes.
# --------------------------------------------------------------------------- #


def _many_jobs(n: int) -> Workflow:
    text = "on: push\npermissions: {}\njobs:\n"
    for i in range(n):
        text += (
            f"  job{i}:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some-org/act@v1\n"
        )
    return Workflow(path="x", text=text, data=yaml.safe_load(text))


def test_find_line_anchoring_is_preserved() -> None:
    """A otimização não pode mexer na âncora: mesmo número de linha de antes.

    Dois `uses: actions/checkout@v4`; o segundo (com ref de PR) é o ofensor. O finding tem
    de apontar para a linha do `ref:`, exatamente como o cursor monotônico garantia.
    """
    text = (
        "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n"
    )
    wf = Workflow(path="x", text=text, data=yaml.safe_load(text))
    ppt = [f for f in run_all(wf) if f.check_id == "pull-request-target-checkout"]
    assert len(ppt) == 1
    assert text.splitlines()[ppt[0].line - 1].strip().startswith("ref:")


def test_large_workflow_does_not_scale_quadratically() -> None:
    """8 mil `uses:` num arquivo: antes ~3,3 s só de âncora (O(n²)); agora <0,1 s (O(n)).

    Guarda de regressão com folga larga: o teto de 2 s é ~30x acima do custo linear atual e
    bem abaixo do custo quadrático anterior — separa os dois regimes sem depender da máquina.
    """
    wf = _many_jobs(8000)
    inicio = time.perf_counter()
    achados = run_all(wf)
    decorrido = time.perf_counter() - inicio
    assert len(achados) == 8000  # um unpinned por job — nada foi perdido
    assert decorrido < 2.0, f"run_all de 8000 jobs levou {decorrido:.2f}s (regressão quadrática?)"


# --------------------------------------------------------------------------- #
# 2. Topo não-mapa (lista/escalar): fail-open → fail-closed, sem perder fallback.
# --------------------------------------------------------------------------- #


def test_toplevel_list_yaml_is_flagged_not_silent(tmp_path: Path) -> None:
    ids = _scan_ids(tmp_path, "- one\n- two\n- run: echo ${{ github.head_ref }}\n")
    assert "invalid-yaml" in ids  # fail-closed, não some em silêncio
    assert "script-injection" in ids  # o fallback textual ainda roda: nenhum achado perdido


def test_toplevel_scalar_yaml_is_flagged(tmp_path: Path) -> None:
    ids = _scan_ids(tmp_path, "apenas um texto com ${{ github.event.issue.title }}\n")
    assert "invalid-yaml" in ids
    assert "script-injection" in ids


def test_toplevel_non_mapping_fails_ci(tmp_path: Path) -> None:
    """O gate reprova (exit 1) num documento estruturalmente inválido — não passa verde."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "w.yml").write_text("- a\n- b\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1


# --------------------------------------------------------------------------- #
# 3. jobs: como lista/escalar — cegueira estrutural vira sinal explícito.
# --------------------------------------------------------------------------- #


def test_jobs_as_list_is_flagged_not_silent(tmp_path: Path) -> None:
    wf = "on: push\njobs:\n  - runs-on: self-hosted\n  - run: echo ${{ github.head_ref }}\n"
    ids = _scan_ids(tmp_path, wf)
    assert "invalid-yaml" in ids  # antes: só missing-permissions (LOW) → CI verde por engano


def test_jobs_as_list_finding_is_high_severity(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "w.yml").write_text("on: push\njobs:\n  - runs-on: self-hosted\n", encoding="utf-8")
    result = scan(tmp_path)
    inval = [f for f in result.findings if f.check_id == "invalid-yaml"]
    assert inval and inval[0].severity is Severity.HIGH


# --------------------------------------------------------------------------- #
# Não-regressão: os casos LEGÍTIMOS de topo/jobs vazios NÃO viram falso-positivo.
# --------------------------------------------------------------------------- #


def test_empty_and_comment_only_files_stay_clean(tmp_path: Path) -> None:
    for text in ("", "# só comentário\n\n   \n", "null\n"):
        assert "invalid-yaml" not in _scan_ids(tmp_path, text)


def test_empty_jobs_map_is_not_flagged(tmp_path: Path) -> None:
    assert "invalid-yaml" not in _scan_ids(tmp_path, "on: push\npermissions: {}\njobs: {}\n")


def test_action_file_without_jobs_is_not_flagged(tmp_path: Path) -> None:
    # Arquivo de composite action tem 'runs:' e NÃO tem 'jobs:' — legítimo, sem sinal falso.
    action = (
        "runs:\n  using: composite\n  steps:\n    - run: echo ${{ github.event.issue.title }}\n"
    )
    ids = _scan_ids(tmp_path, action, name="action.yml")
    assert "invalid-yaml" not in ids
    assert "script-injection" in ids  # a checagem real do arquivo de action segue viva
