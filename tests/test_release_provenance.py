"""ES-DISTc (P24) — o release publica proveniência SLSA verificável do artefato.

Dois jeitos de essa invariante quebrar em silêncio: (1) alguém edita `release.yml` e o
workflow continua existindo, mas o passo de atestação some ou perde o `subject-path`; (2) a
própria Esteira — que audita exatamente este tipo de arquivo — passa a reclamar dele porque
uma edição futura solta uma permissão ou desfixa uma action. O segundo é travado reusando o
motor de verdade (`esteira.checks.engine.scan`), não uma reimplementação da regra.
"""

from __future__ import annotations

from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
RELEASE = RAIZ / ".github" / "workflows" / "release.yml"


def _carregar() -> dict[str, object]:
    with open(RELEASE, encoding="utf-8") as fh:
        dados: dict[str, object] = yaml.safe_load(fh)
    return dados


def test_dispara_em_tag_de_versao() -> None:
    dados = _carregar()
    on = dados.get(True, dados.get("on"))  # PyYAML 5.x lê 'on:' como bool True
    assert isinstance(on, dict)
    tags = on["push"]["tags"]
    assert "v*.*.*" in tags


def test_job_de_release_tem_permissoes_minimas_e_explicitas() -> None:
    dados = _carregar()
    assert dados["permissions"] == {"contents": "read"}, "o padrão do repo é ler no topo"

    jobs = dados["jobs"]
    assert len(jobs) == 1
    (job,) = jobs.values()
    permissoes = job["permissions"]
    # Exatamente o que `attest-build-provenance` + `gh release create` precisam — nem mais.
    assert permissoes == {"contents": "write", "id-token": "write", "attestations": "write"}


def test_builda_o_pacote_antes_de_assinar() -> None:
    dados = _carregar()
    (job,) = dados["jobs"].values()
    steps = job["steps"]
    nomes = [s.get("uses") or s.get("name") for s in steps]
    idx_build = next(i for i, s in enumerate(steps) if "python -m build" in str(s.get("run", "")))
    idx_attest = next(i for i, u in enumerate(nomes) if u and "attest-build-provenance" in str(u))
    assert idx_build < idx_attest, "a proveniência tem de assinar o artefato já construído"


def test_atesta_proveniencia_slsa_dos_artefatos_publicados() -> None:
    dados = _carregar()
    (job,) = dados["jobs"].values()
    passos_attest = [s for s in job["steps"] if "attest-build-provenance" in str(s.get("uses", ""))]
    assert len(passos_attest) == 1
    (passo,) = passos_attest
    assert passo["uses"].split("@")[1].startswith("4d101475d8b20a2381f78447822ac1eab6504dd8")
    assert passo["with"]["subject-path"] == "dist/*"


def test_publica_release_via_gh_cli_sem_interpolar_segredo_no_shell() -> None:
    """`${{ github.token }}` só pode chegar ao shell via `env:` — nunca escrito dentro do
    `run:` (viraria secret-in-run). O token some do script e vira `$GH_TOKEN` do ambiente."""
    dados = _carregar()
    (job,) = dados["jobs"].values()
    passos_release = [s for s in job["steps"] if "gh release create" in str(s.get("run", ""))]
    assert len(passos_release) == 1
    (passo,) = passos_release
    assert "github.token" not in passo["run"]
    assert passo["env"]["GH_TOKEN"] == "${{ github.token }}"


def test_checkout_nao_persiste_credenciais() -> None:
    dados = _carregar()
    (job,) = dados["jobs"].values()
    (checkout,) = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout")]
    assert checkout["with"]["persist-credentials"] is False


def test_release_yml_nao_tem_nenhum_achado_da_propria_esteira() -> None:
    """A mesma régua que o job `self-scan` do CI aplica ao repositório inteiro — travada
    aqui para este arquivo específico, para falhar rápido e local, sem precisar do CI."""
    import sys

    sys.path.insert(0, str(RAIZ / "src"))
    from esteira.checks.engine import scan

    resultado = scan(RELEASE)
    assert resultado.findings == []
