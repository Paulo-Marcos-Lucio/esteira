"""`esteira scan --desde <ref>`: a varredura nunca pode relatar achado fora do diff local.

A INVARIANTE (property-based, Hypothesis): para qualquer repositório git com N workflows
vulneráveis, se o commit mais recente só tocou um subconjunto deles sob `.github/`, rodar
`scan --desde <ref-anterior>` nunca produz um achado cujo `path` não esteja nesse subconjunto —
mesmo que os workflows não tocados estejam tão vulneráveis quanto os tocados. Sem essa garantia,
`--desde` reabriria em todo PR achados pré-existentes que ninguém mexeu.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from esteira.cli import app
from esteira.core.gitdiff import GitDiffError, arquivos_alterados

runner = CliRunner()

_VULN = """\
name: vuln-{nome}
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: curl https://exemplo.invalid/install.sh | bash
"""


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )


def _commit(repo: Path, mensagem: str) -> str:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.email=teste@exemplo.invalid",
        "-c",
        "user.name=Teste",
        "commit",
        "-m",
        mensagem,
        "--quiet",
    )
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _repo_com_workflows(tmp_path: Path, nomes: list[str]) -> tuple[Path, str]:
    """Repo git com um workflow vulnerável por nome, tudo num único commit base."""
    repo = tmp_path / "repo"
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    for nome in nomes:
        (wf_dir / f"{nome}.yml").write_text(_VULN.format(nome=nome), encoding="utf-8")
    _git(repo, "init", "--quiet", "-b", "main")
    base = _commit(repo, "base: workflows iniciais")
    return repo, base


def test_desde_so_relata_o_arquivo_tocado(tmp_path: Path) -> None:
    repo, base = _repo_com_workflows(tmp_path, ["antigo"])
    # 'novo' nasce DEPOIS do commit base — só ele está no diff.
    (repo / ".github" / "workflows" / "novo.yml").write_text(
        _VULN.format(nome="novo"), encoding="utf-8"
    )
    _commit(repo, "feat: workflow novo")

    result = runner.invoke(app, ["scan", str(repo), "--desde", base, "-f", "json"])
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    paths = {f["path"] for f in doc["findings"]}
    assert any("novo.yml" in p for p in paths)
    assert not any("antigo.yml" in p for p in paths)


def test_desde_sem_mudanca_no_github_nao_relata_nada(tmp_path: Path) -> None:
    repo, base = _repo_com_workflows(tmp_path, ["antigo"])
    (repo / "README.md").write_text("doc\n", encoding="utf-8")
    _commit(repo, "docs: readme")

    result = runner.invoke(app, ["scan", str(repo), "--desde", base, "-f", "json"])
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert doc["findings"] == []


def test_desde_com_ref_inexistente_sai_com_erro_de_uso(tmp_path: Path) -> None:
    repo, _base = _repo_com_workflows(tmp_path, ["antigo"])
    result = runner.invoke(app, ["scan", str(repo), "--desde", "nao-existe-essa-ref"])
    assert result.exit_code == 2


def test_desde_fora_de_repositorio_git_levanta(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    with __import__("pytest").raises(GitDiffError):
        arquivos_alterados(tmp_path, "HEAD")


# Nomes de arquivo simples — o que importa pro teste é QUANTOS mudam, não o alfabeto.
_NOMES = st.lists(
    st.from_regex(r"[a-z][a-z0-9]{0,8}", fullmatch=True), min_size=2, max_size=5, unique=True
)


@settings(
    max_examples=25,
    deadline=None,  # cada exemplo faz `git init`/`commit` de verdade — não é CPU-bound.
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(nomes=_NOMES, tocados=st.data())
def test_propriedade_findings_so_vem_de_arquivos_no_diff(
    tmp_path_factory: object, nomes: list[str], tocados: st.DataObject
) -> None:
    """INVARIANTE: nenhum achado de `--desde` referencia um arquivo fora do diff de .github/**,
    mesmo quando TODOS os workflows (tocados ou não) são igualmente vulneráveis."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo, base = _repo_com_workflows(tmp_path, nomes)
        subconjunto = tocados.draw(
            st.lists(st.sampled_from(nomes), min_size=1, max_size=len(nomes), unique=True)
        )
        for nome in subconjunto:
            # Reescreve o mesmo conteúdo vulnerável: o que muda é o DIFF (o arquivo entra no
            # commit), não o tipo de achado — isola a propriedade do caso "conteúdo diferente".
            caminho = repo / ".github" / "workflows" / f"{nome}.yml"
            caminho.write_text(_VULN.format(nome=nome) + "        # tocado\n", encoding="utf-8")
        _commit(repo, "feat: subconjunto tocado")

        result = runner.invoke(app, ["scan", str(repo), "--desde", base, "-f", "json"])
        doc = json.loads(result.stdout)
        tocados_nomes = {f"{nome}.yml" for nome in subconjunto}
        for finding in doc["findings"]:
            assert any(finding["path"].endswith(nome) for nome in tocados_nomes), (
                f"achado fora do diff: {finding['path']} (tocados: {tocados_nomes})"
            )
