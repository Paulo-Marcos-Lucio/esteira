"""O servidor MCP expõe exatamente o mesmo documento `suite-appsec/1` que o CLI em JSON — a
tool não pode reimplementar a varredura nem derivar um contrato próprio."""

from __future__ import annotations

from pathlib import Path

import pytest

from esteira.mcp_server import mcp, rules, scan
from esteira.report.json_report import SCHEMA


def test_scan_tool_devolve_schema_suite_appsec(vuln_repo: Path) -> None:
    documento = scan(str(vuln_repo))
    assert documento["schema"] == SCHEMA
    assert documento["summary"]["total"] > 0
    assert documento["findings"][0]["id"]


def test_scan_tool_repo_seguro_zero_achados(safe_repo: Path) -> None:
    documento = scan(str(safe_repo))
    assert documento["schema"] == SCHEMA
    assert documento["summary"]["total"] == 0


def test_scan_tool_checagem_desconhecida_levanta(vuln_repo: Path) -> None:
    with pytest.raises(ValueError, match="desconhecida"):
        scan(str(vuln_repo), only=["isto-nao-existe"])


def test_rules_tool_lista_catalogo() -> None:
    catalogo = rules()
    ids = {item["id"] for item in catalogo}
    assert "script-injection" in ids
    assert all({"id", "severity", "title"} <= item.keys() for item in catalogo)


def test_server_registra_as_duas_tools() -> None:
    nomes = {t.name for t in mcp._tool_manager.list_tools()}
    assert nomes == {"scan", "rules"}
