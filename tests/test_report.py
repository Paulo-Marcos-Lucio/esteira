from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console

from esteira.checks.engine import scan
from esteira.core.models import Confidence, FindingType
from esteira.report.console import render
from esteira.report.json_report import to_json
from esteira.report.sarif import to_sarif


def test_json_structure(vuln_repo: Path) -> None:
    doc = json.loads(to_json(scan(vuln_repo)))
    assert doc["tool"] == "esteira"
    assert doc["summary"]["total"] == len(doc["findings"])
    assert doc["summary"]["files_scanned"] == 1
    assert doc["findings"], "vuln_repo precisa gerar achado para o assert abaixo valer algo"
    # EV-12: todo achado REAL do JSON traz `type`/`confidence` — não só as entradas do
    # catálogo em abstrato (isso o meta-teste do catálogo já cobre), o achado que de fato
    # sai no relatório que o cliente consome.
    for finding in doc["findings"]:
        assert finding["type"] in {t.value for t in FindingType}
        assert finding["confidence"] in {c.value for c in Confidence}


def test_sarif_structure(vuln_repo: Path) -> None:
    doc = json.loads(to_sarif(scan(vuln_repo)))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in declared
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_console_render(vuln_repo: Path) -> None:
    console = Console(file=io.StringIO(), width=200)
    render(scan(vuln_repo), console)
    assert "script-injection" in console.file.getvalue()  # type: ignore[attr-defined]
