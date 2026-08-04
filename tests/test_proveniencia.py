"""P1-01 — o relatório precisa ser vinculável a um código, a um catálogo e a si mesmo.

Sem os três eixos o achado não é reauditável: seis meses depois ninguém prova se ele sumiu
porque o código foi corrigido ou porque a REGRA mudou de opinião.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from esteira.core import provenance
from esteira.report.json_report import to_document, to_json
from esteira.report.sarif import to_sarif


def _sem_git(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ESTEIRA_COMMIT", raising=False)


def test_envelope_json_carrega_os_tres_eixos_de_proveniencia(
    vuln_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ESTEIRA_COMMIT", "0" * 40)
    from esteira.checks.engine import scan

    doc = json.loads(to_json(scan(vuln_repo)))
    assert doc["commit"] == "0" * 40
    assert len(doc["ruleset_hash"]) == 64
    assert len(doc["artifact_sha256"]) == 64


def test_commit_e_null_fora_de_repositorio_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fora de um repo git a resposta honesta é ``null`` — não uma exceção, nem 'unknown'."""
    _sem_git(monkeypatch)
    assert provenance.commit(tmp_path) is None


def test_commit_e_null_quando_o_git_nao_existe_na_maquina(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sem_git(monkeypatch)

    def explode(*_a: object, **_k: object) -> None:
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", explode)
    assert provenance.commit(tmp_path) is None


def test_commit_aceita_um_arquivo_e_procura_o_repo_no_diretorio_dele(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`git rev-parse` com `cwd` apontando para um ARQUIVO é NotADirectoryError, não `None`."""
    _sem_git(monkeypatch)
    arquivo = tmp_path / "wf.yml"
    arquivo.write_text("on: push\n", encoding="utf-8")
    assert provenance.commit(arquivo) is None


def test_env_vence_o_git(vuln_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ESTEIRA_COMMIT", "a" * 40)
    assert provenance.commit(vuln_repo) == "a" * 40


def test_ruleset_hash_muda_quando_a_severidade_de_uma_regra_muda(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """O hash existe para provar QUE CATÁLOGO julgou o código. Se ele não se move quando o
    catálogo se move, não prova nada."""
    from esteira.checks.catalog import CATALOG
    from esteira.core.models import Severity

    antes = provenance.ruleset_hash()
    original = CATALOG["broad-permissions"]
    monkeypatch.setitem(
        CATALOG,
        "broad-permissions",
        type(original)(
            original.id,
            original.title,
            Severity.LOW,
            original.recommendation,
            original.owasp,
            original.cwe,
        ),
    )
    assert provenance.ruleset_hash() != antes


def test_artifact_sha256_e_verificavel_pela_receita_documentada(vuln_repo: Path) -> None:
    """Um hash que o destinatário não consegue recalcular é enfeite. A receita: zere o campo,
    serialize canonicamente (sort_keys, separadores compactos, sem escapar não-ASCII)."""
    from esteira.checks.engine import scan

    doc = json.loads(to_json(scan(vuln_repo)))
    declarado = doc["artifact_sha256"]
    doc["artifact_sha256"] = None
    canonico = json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert hashlib.sha256(canonico.encode("utf-8")).hexdigest() == declarado


def test_sarif_grava_owasp_edition_com_a_grafia_documentada(vuln_repo: Path) -> None:
    """A auditoria achou `owasp-edition` (hífen) onde a documentação promete `owasp_edition`.
    Consumidor que lê a chave documentada recebia KeyError."""
    from esteira.checks.engine import scan

    run = json.loads(to_sarif(scan(vuln_repo)))["runs"][0]
    for regra in run["tool"]["driver"]["rules"]:
        assert "owasp-edition" not in regra["properties"]
        assert regra["properties"]["owasp_edition"]


def test_sarif_declara_edicao_e_proveniencia_no_nivel_do_run(
    vuln_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Quem consome o SARIF do run inteiro (a aba Security) não deve precisar abrir uma regra
    para descobrir contra qual edição do OWASP e qual commit o relatório foi produzido."""
    monkeypatch.setenv("ESTEIRA_COMMIT", "b" * 40)
    from esteira.checks.engine import scan

    run = json.loads(to_sarif(scan(vuln_repo)))["runs"][0]
    assert run["properties"]["owasp_edition"]
    assert run["properties"]["commit"] == "b" * 40
    assert len(run["properties"]["ruleset_hash"]) == 64


def test_to_document_nao_explode_sem_raiz(monkeypatch: pytest.MonkeyPatch) -> None:
    """`ScanResult` construído à mão (o que meia dúzia de testes faz) não pode quebrar o
    envelope só por não carregar a raiz varrida."""
    _sem_git(monkeypatch)
    from esteira.core.models import ScanResult

    doc = to_document(ScanResult())
    assert doc["ruleset_hash"]
    assert "commit" in doc
