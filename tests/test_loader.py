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
