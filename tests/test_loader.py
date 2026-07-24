from __future__ import annotations

from pathlib import Path

from esteira.core.loader import iter_workflow_files, load, trigger_names


def test_finds_workflow_files(vuln_repo: Path) -> None:
    files = iter_workflow_files(vuln_repo)
    assert len(files) == 1
    assert files[0].name == "vuln.yml"


def test_on_parsed_as_bool_key_is_handled(tmp_path: Path) -> None:
    # YAML 1.1 transforma 'on:' na chave booleana True — o loader precisa lidar com isso.
    wf = tmp_path / "w.yml"
    wf.write_text("on: push\njobs: {}\n", encoding="utf-8")
    workflow = load(wf)
    assert workflow.data is not None
    assert trigger_names(workflow.data) == {"push"}


def test_multiple_triggers(tmp_path: Path) -> None:
    wf = tmp_path / "w.yml"
    wf.write_text("on:\n  pull_request_target:\n  push:\n", encoding="utf-8")
    workflow = load(wf)
    assert workflow.data is not None
    assert trigger_names(workflow.data) == {"pull_request_target", "push"}


def _wf(base: Path, rel: str) -> Path:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("on: push\njobs: {}\n", encoding="utf-8")
    return path


def test_monorepo_finds_workflows_in_every_subproject(tmp_path: Path) -> None:
    # Monorepo sem workflows no nível superior: cada subprojeto tem o seu.
    _wf(tmp_path, "services/api/.github/workflows/ci.yml")
    _wf(tmp_path, "services/web/.github/workflows/deploy.yaml")
    _wf(tmp_path, "packages/lib/.github/workflows/test.yml")

    files = iter_workflow_files(tmp_path)

    assert {p.name for p in files} == {"ci.yml", "deploy.yaml", "test.yml"}
    assert files == sorted(files)  # ordem determinística


def test_monorepo_includes_root_level_and_nested(tmp_path: Path) -> None:
    # Repo com workflow no topo E em subprojetos: os dois níveis são varridos.
    _wf(tmp_path, ".github/workflows/root.yml")
    _wf(tmp_path, "service-a/.github/workflows/a.yml")

    files = iter_workflow_files(tmp_path)

    assert {p.name for p in files} == {"root.yml", "a.yml"}


def test_discovery_skips_vendored_and_hidden_dirs(tmp_path: Path) -> None:
    # Negativo/sem-FP: workflows de dependências vendoradas e de caches/VCS ocultos
    # NÃO são o CI do repositório e não podem ser auditados como se fossem.
    real = _wf(tmp_path, "app/.github/workflows/ci.yml")
    _wf(tmp_path, "node_modules/dep/.github/workflows/dep.yml")
    _wf(tmp_path, ".venv/pkg/.github/workflows/vendored.yml")
    _wf(tmp_path, "vendor/x/.github/workflows/v.yml")
    _wf(tmp_path, ".git/hooks/.github/workflows/hook.yml")

    files = iter_workflow_files(tmp_path)

    assert files == [real]


def test_direct_workflows_dir_still_works(tmp_path: Path) -> None:
    # Apontar direto para um diretório de workflows (fora de .github) segue funcionando.
    wf_dir = tmp_path / "flows"
    _wf(tmp_path, "flows/a.yml")
    assert iter_workflow_files(wf_dir) == [wf_dir / "a.yml"]


def test_empty_repo_returns_nothing(tmp_path: Path) -> None:
    assert iter_workflow_files(tmp_path) == []
