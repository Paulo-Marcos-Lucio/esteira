from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from esteira import __version__
from esteira.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "script-injection" in result.stdout


def test_scan_vuln_json_exit1(vuln_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(vuln_repo), "-f", "json"])
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    assert doc["summary"]["total"] > 0


def test_scan_safe_exit0(safe_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(safe_repo)])
    assert result.exit_code == 0


def test_scan_sarif_to_file(vuln_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = runner.invoke(app, ["scan", str(vuln_repo), "-f", "sarif", "-o", str(out)])
    assert result.exit_code == 1
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
