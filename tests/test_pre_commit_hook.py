"""`.pre-commit-hooks.yaml` — o manifesto que deixa o Esteira instalável como hook remoto.

Dois jeitos de ele apodrecer sem que nenhum outro teste perceba: (1) o `entry:` desalinha do
nome real do console script em `pyproject.toml` (alguém renomeia um dos dois e o hook aponta
para um comando que não existe); (2) o filtro `files:` para de casar o próprio padrão de
workflow que o Esteira audita, e o hook nunca dispara. Os testes abaixo travam as duas classes,
e um terceiro roda o comando do `entry:` de ponta a ponta contra um repositório sintético para
provar que "funcional" não é só a sintaxe do YAML.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from esteira.cli import app

_RAIZ = Path(__file__).resolve().parent.parent
_MANIFESTO = _RAIZ / ".pre-commit-hooks.yaml"

runner = CliRunner()


def _hooks() -> list[dict[str, object]]:
    return yaml.safe_load(_MANIFESTO.read_text(encoding="utf-8"))


def test_manifesto_tem_um_hook_com_campos_obrigatorios() -> None:
    hooks = _hooks()
    assert isinstance(hooks, list) and len(hooks) == 1
    hook = hooks[0]
    for campo in ("id", "name", "description", "entry", "language", "files"):
        assert campo in hook, f"campo obrigatório ausente: {campo}"
    assert hook["id"] == "esteira"
    assert hook["language"] == "python"
    # `pass_filenames: false` é a escolha deliberada: `esteira scan` recebe UM diretório, não uma
    # lista de arquivos alterados — sem isso o pre-commit passaria os workflows staged como
    # argumentos posicionais extras e a CLI (Argument único) rejeitaria a chamada.
    assert hook.get("pass_filenames") is False


def test_entry_usa_o_console_script_declarado_no_pyproject() -> None:
    """Trava a classe: `entry:` e `[project.scripts]` precisam nomear o mesmo comando. Se alguém
    renomear o script instalado sem atualizar o hook (ou vice-versa), o pre-commit instala o
    pacote e falha ao executar um binário que não existe.

    Lê `pyproject.toml` como texto (não `tomllib`) de propósito: o piso de versão do projeto é
    Python 3.10, e `tomllib` só existe a partir do 3.11 — este teste roda nos quatro Pythons da
    matriz do CI.
    """
    secao = re.search(
        r"^\[project\.scripts\]\n(.+?)(?=\n\[|\Z)",
        (_RAIZ / "pyproject.toml").read_text(encoding="utf-8"),
        re.DOTALL | re.MULTILINE,
    )
    assert secao is not None, "pyproject.toml sem [project.scripts]"
    comandos = re.findall(r"^(\w[\w-]*)\s*=", secao.group(1), re.MULTILINE)
    assert len(comandos) == 1
    (comando,) = comandos

    entry = str(_hooks()[0]["entry"])
    assert entry.split()[0] == comando


@pytest.mark.parametrize(
    "caminho",
    [
        ".github/workflows/ci.yml",
        ".github/workflows/deploy.yaml",
        ".github/workflows/sub/reusable.yml",
    ],
)
def test_filtro_de_files_casa_workflows(caminho: str) -> None:
    padrao = str(_hooks()[0]["files"])
    assert re.match(padrao, caminho), f"{caminho!r} deveria casar {padrao!r}"


@pytest.mark.parametrize(
    "caminho",
    [
        "README.md",
        ".github/ISSUE_TEMPLATE.md",
        "src/esteira/cli.py",
        "github/workflows/ci.yml",  # sem o ponto inicial de ".github"
    ],
)
def test_filtro_de_files_ignora_nao_workflow(caminho: str) -> None:
    padrao = str(_hooks()[0]["files"])
    assert not re.match(padrao, caminho), f"{caminho!r} não deveria casar {padrao!r}"


def _args_do_entry() -> list[str]:
    entry = str(_hooks()[0]["entry"])
    # primeiro token é o executável (instalado pelo pre-commit no venv isolado do hook); o resto
    # são os argumentos que a CliRunner recebe diretamente, sem invocar o binário.
    return entry.split()[1:]


def test_hook_funcional_contra_workflow_vulneravel(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "deploy.yml").write_text(
        "on: pull_request_target\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo '${{ github.event.issue.title }}'\n",
        encoding="utf-8",
    )
    resultado = runner.invoke(app, [*_args_do_entry(), str(tmp_path)])
    assert resultado.exit_code == 1


def test_hook_funcional_contra_repositorio_limpo(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n",
        encoding="utf-8",
    )
    resultado = runner.invoke(app, [*_args_do_entry(), str(tmp_path)])
    assert resultado.exit_code == 0
