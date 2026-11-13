"""Testes do `esteira fix --safe` — correção automática determinística (ES-11pub).

Cobre as duas pernas do critério de aceite: (1) o fix seguro (pin por SHA, `permissions:
contents: read`, `persist-credentials: false`) de fato corrige e preserva comentário; (2)
`escrever(ler(x)) == x` quando nenhum fix é aplicado — testado DIRETO no motor de round-trip
(`core.fixer`), com um corpus de arquivos reais (os próprios `.github/workflows/` deste
repositório) mais estilos de indentação sintéticos, porque é aí que a fidelidade do ruamel é
de fato arriscada (ver `core/fixer.py::_detect_indent`).

Nenhum teste aqui toca rede: `_git_ls_remote_sha` (o único ponto que chama `git ls-remote`,
em `checks/fixes.py`) é testado isolado com `subprocess.run` trocado por um dublê; os testes
de ponta a ponta (CLI, `apply_safe_fixes`) injetam um `TagResolver` falso via
`make_unpinned_fixer` — a mesma fábrica que a produção usa para o resolvedor real.
"""

from __future__ import annotations

import dataclasses
import subprocess
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from esteira.checks.catalog import CATALOG
from esteira.checks.engine import scan
from esteira.checks.fixes import (
    _git_ls_remote_sha,
    fix_checkout_credentials,
    fix_missing_permissions,
    make_unpinned_fixer,
)
from esteira.cli import app
from esteira.core.fixer import apply_safe_fixes, dump_round_trip, load_round_trip, make_yaml
from esteira.core.models import Finding, ScanResult

runner = CliRunner()
_RAIZ = Path(__file__).resolve().parent.parent
_SHA_FALSA = "f" * 40


def _finding(check_id: str, line: int) -> Finding:
    meta = CATALOG[check_id]
    return Finding(
        check_id=check_id,
        title=meta.title,
        severity=meta.severity,
        path="w.yml",
        line=line,
        detail="d",
        recommendation=meta.recommendation,
    )


def _scan_text(tmp_path: Path, text: str, name: str = "w.yml") -> ScanResult:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(text, encoding="utf-8")
    return scan(tmp_path)


# --------------------------------------------------------------------------- #
# round-trip: escrever(ler(x)) == x quando nenhum fix é aplicado
# --------------------------------------------------------------------------- #

_WORKFLOWS_REAIS = sorted((_RAIZ / ".github" / "workflows").glob("*.yml"))


@pytest.mark.parametrize("caminho", _WORKFLOWS_REAIS, ids=lambda p: p.name)
def test_round_trip_identidade_em_workflow_real(caminho: Path) -> None:
    texto = caminho.read_text(encoding="utf-8")
    yaml = make_yaml(texto)
    doc = yaml.load(texto)
    assert dump_round_trip(yaml, doc) == texto


_ESTILOS = {
    "sequencia-rente": (
        "on: push\njobs:\n  build:\n    steps:\n    - uses: a/b@v1\n"
        "      with:\n        x: 1\n    - run: echo hi\n"
    ),
    "sequencia-recuada": (
        "on: push\njobs:\n  build:\n    steps:\n      - uses: a/b@v1\n"
        "        with:\n          x: 1\n      - run: echo hi\n"
    ),
    "sequencia-flow": "on: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    "aspas-preservadas": (
        'on: push\njobs:\n  build:\n    runs-on: "ubuntu-latest"\n'
        "    steps:\n      - run: 'echo \"hi\"'\n"
    ),
    "comentario-e-bloco-literal": (
        "on: push\n# comentário de topo\njobs:\n  build:\n    steps:\n"
        "      - run: |\n          echo linha1\n          echo linha2\n"
    ),
    "sem-sequencia-nenhuma": "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
}


@pytest.mark.parametrize("texto", _ESTILOS.values(), ids=list(_ESTILOS))
def test_round_trip_identidade_em_estilos_sinteticos(texto: str) -> None:
    yaml = make_yaml(texto)
    assert dump_round_trip(yaml, yaml.load(texto)) == texto


def test_apply_safe_fixes_sem_achado_fixavel_devolve_texto_intocado() -> None:
    texto = _ESTILOS["sequencia-recuada"]
    achado = _finding("curl-pipe-shell", 1)  # sem fixer registrado
    resultado = apply_safe_fixes("w.yml", texto, [achado])
    assert resultado.changed is False
    assert resultado.text == texto


def test_apply_safe_fixes_sem_nenhum_achado_devolve_texto_intocado() -> None:
    texto = _ESTILOS["sequencia-rente"]
    resultado = apply_safe_fixes("w.yml", texto, [])
    assert resultado.changed is False
    assert resultado.text == texto


# --------------------------------------------------------------------------- #
# fix_missing_permissions
# --------------------------------------------------------------------------- #


def test_fix_missing_permissions_insere_contents_read_depois_de_on() -> None:
    texto = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    doc = load_round_trip(texto)
    assert fix_missing_permissions(doc, _finding("missing-permissions", 1)) is True
    chaves = list(doc.keys())
    assert chaves.index("on") + 1 == chaves.index("permissions")
    assert doc["permissions"]["contents"] == "read"


def test_fix_missing_permissions_e_idempotente() -> None:
    doc = load_round_trip("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
    achado = _finding("missing-permissions", 1)
    assert fix_missing_permissions(doc, achado) is True
    assert fix_missing_permissions(doc, achado) is False  # já tem bloco: nada a fazer


def test_fix_missing_permissions_preserva_comentario_de_topo() -> None:
    texto = "on: push\n# nota sobre o pipeline\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    yaml = make_yaml(texto)
    doc = yaml.load(texto)
    fix_missing_permissions(doc, _finding("missing-permissions", 1))
    saida = dump_round_trip(yaml, doc)
    assert "# nota sobre o pipeline" in saida


def test_fix_missing_permissions_corrige_de_verdade_via_scan(tmp_path: Path) -> None:
    texto = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    resultado = _scan_text(tmp_path, texto)
    achados = [f for f in resultado.findings if f.check_id == "missing-permissions"]
    assert len(achados) == 1
    arquivo = tmp_path / ".github" / "workflows" / "w.yml"
    saida = apply_safe_fixes(str(arquivo), texto, achados)
    arquivo.write_text(saida.text, encoding="utf-8")
    assert not [f for f in scan(tmp_path).findings if f.check_id == "missing-permissions"]


# --------------------------------------------------------------------------- #
# fix_checkout_credentials
# --------------------------------------------------------------------------- #

_DOIS_JOBS_UM_JA_SEGURO = textwrap.dedent("""\
    on: push
    jobs:
      exposto:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          # comentário sobre o próximo step
          - uses: actions/upload-artifact@v4
            with:
              name: dist
      ja-seguro:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              persist-credentials: false
          - uses: actions/upload-artifact@v4
            with:
              name: dist
""")


def test_fix_checkout_credentials_mira_so_o_step_exposto(tmp_path: Path) -> None:
    resultado_antes = _scan_text(tmp_path, _DOIS_JOBS_UM_JA_SEGURO)
    achados = [
        f for f in resultado_antes.findings if f.check_id == "checkout-credentials-in-artifact"
    ]
    assert len(achados) == 1  # só o job 'exposto' — 'ja-seguro' não dispara

    arquivo = tmp_path / ".github" / "workflows" / "w.yml"
    saida = apply_safe_fixes(str(arquivo), _DOIS_JOBS_UM_JA_SEGURO, achados)
    assert saida.changed is True
    arquivo.write_text(saida.text, encoding="utf-8")

    assert not [
        f for f in scan(tmp_path).findings if f.check_id == "checkout-credentials-in-artifact"
    ]
    # o job já seguro não foi tocado: seu bloco with: continua idêntico ao original.
    assert (
        "ja-seguro:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
        in saida.text
    )
    # o comentário entre os dois steps do job exposto sobrevive (não foi apagado).
    assert "# comentário sobre o próximo step" in saida.text


def test_fix_checkout_credentials_e_idempotente() -> None:
    texto = textwrap.dedent("""\
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/upload-artifact@v4
                with:
                  name: dist
    """)
    yaml = make_yaml(texto)
    doc = yaml.load(texto)
    achado = _finding("checkout-credentials-in-artifact", 6)
    assert fix_checkout_credentials(doc, achado) is True
    assert fix_checkout_credentials(doc, achado) is False


def test_fix_checkout_credentials_nao_acha_nada_em_linha_errada() -> None:
    texto = (
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
    )
    doc = load_round_trip(texto)
    assert fix_checkout_credentials(doc, _finding("checkout-credentials-in-artifact", 999)) is False


# --------------------------------------------------------------------------- #
# pin por SHA (unpinned-action-thirdparty / -firstparty) — resolvedor injetado, sem rede
# --------------------------------------------------------------------------- #


def test_fixer_de_pin_resolve_e_comenta_a_ref_original() -> None:
    texto = (
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
    )
    yaml = make_yaml(texto)
    doc = yaml.load(texto)
    fixer = make_unpinned_fixer(lambda action, ref: _SHA_FALSA)
    assert fixer(doc, _finding("unpinned-action-firstparty", 5)) is True
    saida = dump_round_trip(yaml, doc)
    assert f"actions/checkout@{_SHA_FALSA} # v4" in saida


def test_fixer_de_pin_nao_aplica_quando_resolvedor_falha() -> None:
    texto = (
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
    )
    doc = load_round_trip(texto)
    fixer = make_unpinned_fixer(lambda action, ref: None)  # rede indisponível / ref não existe
    assert fixer(doc, _finding("unpinned-action-firstparty", 5)) is False


def test_fixer_de_pin_e_idempotente_ja_pinado() -> None:
    sha = "a" * 40
    texto = f"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"
    doc = load_round_trip(texto)
    fixer = make_unpinned_fixer(lambda action, ref: _SHA_FALSA)
    assert fixer(doc, _finding("unpinned-action-firstparty", 5)) is False


def test_fixer_de_pin_mira_reusable_workflow_chamado_pelo_job() -> None:
    texto = "jobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@v1\n"
    yaml = make_yaml(texto)
    doc = yaml.load(texto)
    fixer = make_unpinned_fixer(lambda action, ref: _SHA_FALSA)
    assert fixer(doc, _finding("unpinned-reusable-workflow", 3)) is True
    assert f"org/repo/.github/workflows/x.yml@{_SHA_FALSA} # v1" in dump_round_trip(yaml, doc)


# --------------------------------------------------------------------------- #
# _git_ls_remote_sha — parsing do 'git ls-remote', subprocess trocado por dublê (sem rede)
# --------------------------------------------------------------------------- #


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_git_ls_remote_sha_prioriza_a_tag_anotada_peeled(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = (
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\trefs/tags/v4\n"
        "cafecafecafecafecafecafecafecafecafecafe\trefs/tags/v4^{}\n"
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeCompleted(0, saida))
    assert (
        _git_ls_remote_sha("actions/checkout", "v4") == "cafecafecafecafecafecafecafecafecafecafe"
    )


def test_git_ls_remote_sha_usa_a_unica_linha_quando_nao_ha_peeled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saida = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\trefs/heads/main\n"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeCompleted(0, saida))
    assert (
        _git_ls_remote_sha("actions/checkout", "main") == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )


def test_git_ls_remote_sha_devolve_none_em_ref_inexistente(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeCompleted(0, ""))
    assert _git_ls_remote_sha("actions/checkout", "no-such-ref") is None


def test_git_ls_remote_sha_devolve_none_em_falha_de_processo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeCompleted(128, ""))
    assert _git_ls_remote_sha("actions/checkout", "v4") is None


def test_git_ls_remote_sha_devolve_none_sem_rede(monkeypatch: pytest.MonkeyPatch) -> None:
    def _sem_rede(*a: object, **k: object) -> None:
        raise OSError("rede indisponível")

    monkeypatch.setattr(subprocess, "run", _sem_rede)
    assert _git_ls_remote_sha("actions/checkout", "v4") is None


def test_git_ls_remote_sha_rejeita_action_sem_owner_repo() -> None:
    assert _git_ls_remote_sha("semowner", "v4") is None


# --------------------------------------------------------------------------- #
# CLI: `esteira fix` / `esteira fix --safe`
# --------------------------------------------------------------------------- #


def test_cli_fix_sem_safe_recusa_e_nao_escreve(tmp_path: Path) -> None:
    texto = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    _scan_text(tmp_path, texto)
    arquivo = tmp_path / ".github" / "workflows" / "w.yml"
    resultado = runner.invoke(app, ["fix", str(tmp_path)])
    assert resultado.exit_code == 2
    assert "--safe" in resultado.output
    assert arquivo.read_text(encoding="utf-8") == texto  # intocado


def test_cli_fix_safe_corrige_e_e_idempotente(tmp_path: Path) -> None:
    texto = textwrap.dedent("""\
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
              - uses: actions/upload-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
                with:
                  name: dist
    """)
    # já pinado por SHA de propósito: este teste não deve tocar rede (sem unpinned aqui).
    _scan_text(tmp_path, texto)
    arquivo = tmp_path / ".github" / "workflows" / "w.yml"

    primeira = runner.invoke(app, ["fix", "--safe", str(tmp_path)])
    assert primeira.exit_code == 0
    assert "corrigido" in primeira.output
    corrigido = arquivo.read_text(encoding="utf-8")
    assert "permissions" in corrigido
    assert "persist-credentials: false" in corrigido
    assert not [
        f
        for f in scan(tmp_path).findings
        if f.check_id in {"missing-permissions", "checkout-credentials-in-artifact"}
    ]

    segunda = runner.invoke(app, ["fix", "--safe", str(tmp_path)])
    assert segunda.exit_code == 0
    assert "Nada a corrigir" in segunda.output
    assert arquivo.read_text(encoding="utf-8") == corrigido  # nada mudou de novo


@pytest.fixture
def resolvedor_de_pin_falso() -> Iterator[None]:
    """Troca o fixer de pin das duas regras `unpinned-action-*` por um que resolve para
    `_SHA_FALSA` sem tocar rede, só para a duração do teste — restaura o original no fim."""
    originais = {
        cid: CATALOG[cid] for cid in ("unpinned-action-thirdparty", "unpinned-action-firstparty")
    }
    fixer_falso = make_unpinned_fixer(lambda action, ref: _SHA_FALSA)
    for cid in originais:
        CATALOG[cid] = dataclasses.replace(CATALOG[cid], fixer=fixer_falso)
    try:
        yield
    finally:
        CATALOG.update(originais)


def test_cli_fix_safe_pina_por_sha_sem_tocar_rede(
    tmp_path: Path, resolvedor_de_pin_falso: None
) -> None:
    texto = "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
    _scan_text(tmp_path, texto)
    resultado = runner.invoke(app, ["fix", "--safe", str(tmp_path)])
    assert resultado.exit_code == 0
    arquivo = tmp_path / ".github" / "workflows" / "w.yml"
    assert f"actions/checkout@{_SHA_FALSA} # v4" in arquivo.read_text(encoding="utf-8")


def test_cli_fix_safe_nao_escreve_arquivo_cujo_unico_achado_nao_resolveu(tmp_path: Path) -> None:
    # ref que não existe: o resolvedor REAL (git ls-remote) devolve None tanto por isso quanto
    # por falta de rede — o teste não depende de qual dos dois é o caso neste ambiente.
    texto = "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@ref-que-nao-existe-de-verdade\n        with:\n          persist-credentials: false\n"
    _scan_text(tmp_path, texto)
    arquivo = tmp_path / ".github" / "workflows" / "w.yml"
    resultado = runner.invoke(app, ["fix", "--safe", str(tmp_path)])
    assert resultado.exit_code == 0
    assert "Nada a corrigir" in resultado.output
    assert arquivo.read_text(encoding="utf-8") == texto
