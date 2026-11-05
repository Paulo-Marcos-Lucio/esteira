"""ES-01a — `# zizmor: ignore[regra]` deixa de calar QUALQUER achado da linha e passa a calar
só o achado nosso que a regra citada de fato cobre (`_ZIZMOR_PARA_ESTEIRA`); regra fora do mapa
não suprime nada e entra em `coverage.supressoes_nao_mapeadas`.

Antes desta correção, `_is_suppressed` honrava a simples PRESENÇA de `# zizmor: ignore[...]` na
linha como "revisada" e apagava todo achado nela — inclusive um sem relação com a regra citada.
`# zizmor: ignore[template-injection]` (revisão de injeção via template) apagava de brinde um
`unpinned-action-thirdparty` na mesma linha, sem o mantenedor ter revisado aquilo: fail-open no
pior lugar, o mecanismo de supressão.

O teste de propriedade abaixo é a INVARIANTE que tranca a classe (não o exemplo do
`template-injection`): para QUALQUER nome de regra do zizmor que não esteja no mapa, uma
diretiva `# zizmor: ignore[<regra>]` NUNCA suprime o achado da linha, e a ocorrência aparece na
cobertura — a diretiva não pode desaparecer em silêncio.
"""

from __future__ import annotations

import string
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.checks.detectors import _ZIZMOR_PARA_ESTEIRA
from esteira.checks.engine import scan

_ALFA_REGRA = string.ascii_lowercase + "-"


def _scan(tmp_path: Path, text: str):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(text, encoding="utf-8")
    return scan(tmp_path)


def _wf_com_write_all_e_regra(regra: str) -> str:
    # Dois jobs sem `permissions` próprio: ambos herdam do bloco de workflow, o que é o que faz
    # o escopo de escrita específico (`packages: write`) contar como amplo (ver check_permissions).
    return (
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        f"  packages: write # zizmor: ignore[{regra}]\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo a\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo b\n"
    )


# --------------------------------------------------------------------------- #
# O exemplo do criterio_aceite: template-injection não cobre unpinned-action-thirdparty.
# --------------------------------------------------------------------------- #
def test_template_injection_nao_apaga_unpinned_action_thirdparty(tmp_path: Path) -> None:
    wf = (
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: some-org/evil-action@v1  # zizmor: ignore[template-injection]\n"
    )
    ids = {f.check_id for f in _scan(tmp_path, wf).findings}
    assert "unpinned-action-thirdparty" in ids


def test_template_injection_mapeia_para_script_injection(tmp_path: Path) -> None:
    # a MESMA diretiva continua calando o achado que ela de fato cobre.
    linha = '      - run: echo "${{ github.event.issue.title }}"'
    wf = (
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n" + linha + "  # zizmor: ignore[template-injection]\n"
    )
    ids = {f.check_id for f in _scan(tmp_path, wf).findings}
    assert "script-injection" not in ids


# --------------------------------------------------------------------------- #
# Regra não mapeada: fail-closed (não suprime) + aparece na cobertura.
# --------------------------------------------------------------------------- #
def test_regra_nao_mapeada_nao_suprime_e_entra_na_cobertura(tmp_path: Path) -> None:
    wf = _wf_com_write_all_e_regra("regra-que-nao-existe")
    resultado = _scan(tmp_path, wf)
    assert "broad-permissions" in {f.check_id for f in resultado.findings}
    entradas = resultado.supressoes_nao_mapeadas
    assert len(entradas) == 1
    assert entradas[0].regra_zizmor == "regra-que-nao-existe"
    assert entradas[0].line == 4


def test_regra_mapeada_nao_entra_na_cobertura_de_nao_mapeadas(tmp_path: Path) -> None:
    # contraprova: a MESMA forma, com uma regra do mapa, suprime e não conta como não-mapeada.
    wf = _wf_com_write_all_e_regra("excessive-permissions")
    resultado = _scan(tmp_path, wf)
    assert "broad-permissions" not in {f.check_id for f in resultado.findings}
    assert resultado.supressoes_nao_mapeadas == ()


# --------------------------------------------------------------------------- #
# INVARIANTE (property-based): para QUALQUER regra fora do mapa, a diretiva nunca suprime o
# achado da linha, e a ocorrência aparece na cobertura. Isto é o que tranca a classe: um novo
# defeito do tipo "voltamos a honrar zizmor:ignore como blanket" faria este teste ficar
# vermelho para praticamente qualquer entrada, não só para 'template-injection'.
# --------------------------------------------------------------------------- #
@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    regra=st.text(alphabet=_ALFA_REGRA, min_size=1, max_size=30).filter(
        lambda s: s.strip("-") != "" and s.lower() not in _ZIZMOR_PARA_ESTEIRA
    )
)
def test_regra_fora_do_mapa_nunca_suprime(tmp_path: Path, regra: str) -> None:
    wf = _wf_com_write_all_e_regra(regra)
    resultado = _scan(tmp_path, wf)
    assert "broad-permissions" in {f.check_id for f in resultado.findings}, (
        f"regra fora do mapa {regra!r} suprimiu um achado sem relação — voltou o fail-open"
    )
    regras_na_cobertura = {s.regra_zizmor for s in resultado.supressoes_nao_mapeadas}
    assert regra in regras_na_cobertura


@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(regra=st.sampled_from(sorted(_ZIZMOR_PARA_ESTEIRA)))
def test_toda_regra_do_mapa_de_fato_suprime_broad_permissions_ou_nao(
    tmp_path: Path, regra: str
) -> None:
    # contraprova simétrica: regra DO mapa nunca aparece em supressoes_nao_mapeadas, esteja ou
    # não relacionada a broad-permissions (o que importa é ela nunca ser reportada como órfã).
    wf = _wf_com_write_all_e_regra(regra)
    resultado = _scan(tmp_path, wf)
    regras_na_cobertura = {s.regra_zizmor for s in resultado.supressoes_nao_mapeadas}
    assert regra not in regras_na_cobertura
