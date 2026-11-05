"""ES-03b — exceções de config: `.esteira.yml` suprime achados SEM deletá-los.

A supressão inline (`# esteira: ignore`) já existia mas some sem deixar rastro fora do
arquivo de workflow. Esta é a supressão de CONFIG: uma lista de exceções na raiz do
repositório (`.esteira.yml`), cada uma com um glob POSIX de `path`, um `motivo` obrigatório
e opcionalmente uma `regra` (check_id) e uma data `expira`. `engine.scan()` aplica essas
exceções depois de coletar os achados:

* exceção VIGENTE (sem `expira`, ou `expira` no futuro): o achado sai de `findings` e entra
  em `ScanResult.suppressed`, com `origem='config'` e o `motivo` declarado — nunca deletado.
* exceção VENCIDA (`expira` no passado): o achado PERMANECE em `findings` — a exceção não
  segura mais nada — e ganha a nota 'supressão expirada em <data>' no `detail`.

O teste de invariante (Hypothesis) ataca a classe do "não deletar": para qualquer conjunto
de achados e exceções, `len(visiveis) + len(suprimidos) == len(achados originais)` sempre,
e todo achado end-to-end (visível ou suprimido) é rastreável a um achado de entrada.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from esteira.checks.engine import _aplicar_excecoes, scan
from esteira.core.exceptions import Excecao, carregar_excecoes
from esteira.core.models import Finding, Severity

_ONTEM = date.today() - timedelta(days=1)
_AMANHA = date.today() + timedelta(days=1)


def _finding(check_id: str = "broad-permissions", path: str = ".github/workflows/w.yml") -> Finding:
    return Finding(
        check_id=check_id,
        title="t",
        severity=Severity.HIGH,
        path=path,
        line=1,
        detail="detalhe original",
        recommendation="r",
    )


# --------------------------------------------------------------------------- #
# core.exceptions — leitura do arquivo e casamento
# --------------------------------------------------------------------------- #


def test_sem_arquivo_de_config_nao_ha_excecoes(tmp_path: Path) -> None:
    assert carregar_excecoes(tmp_path) == []


def test_config_sem_bloco_excecoes_e_vazio(tmp_path: Path) -> None:
    (tmp_path / ".esteira.yml").write_text("outra_coisa: 1\n", encoding="utf-8")
    assert carregar_excecoes(tmp_path) == []


def test_excecao_sem_motivo_ou_path_e_ignorada(tmp_path: Path) -> None:
    (tmp_path / ".esteira.yml").write_text(
        "excecoes:\n  - path: '*.yml'\n  - motivo: sem path\n", encoding="utf-8"
    )
    assert carregar_excecoes(tmp_path) == []


def test_le_excecao_completa(tmp_path: Path) -> None:
    (tmp_path / ".esteira.yml").write_text(
        "excecoes:\n"
        "  - regra: secret-in-run\n"
        "    path: '.github/workflows/legacy-*.yml'\n"
        "    motivo: 'migração pro Vault, ticket OPS-123'\n"
        "    expira: '2099-01-01'\n",
        encoding="utf-8",
    )
    (excecao,) = carregar_excecoes(tmp_path)
    assert excecao.regra == "secret-in-run"
    assert excecao.motivo == "migração pro Vault, ticket OPS-123"
    assert excecao.expira == date(2099, 1, 1)


def test_glob_posix_casa_por_padrao_e_regra() -> None:
    excecao = Excecao(path=".github/workflows/legacy-*.yml", motivo="m", regra="secret-in-run")
    assert excecao.casa("secret-in-run", ".github/workflows/legacy-deploy.yml")
    assert not excecao.casa("secret-in-run", ".github/workflows/novo.yml")  # path não casa
    assert not excecao.casa("broad-permissions", ".github/workflows/legacy-deploy.yml")  # regra


def test_sem_regra_casa_qualquer_check_id() -> None:
    excecao = Excecao(path=".github/workflows/legacy-*.yml", motivo="m")
    assert excecao.casa("secret-in-run", ".github/workflows/legacy-x.yml")
    assert excecao.casa("broad-permissions", ".github/workflows/legacy-x.yml")


def test_expira_no_passado_e_expirada_no_futuro_nao() -> None:
    vencida = Excecao(path="*", motivo="m", expira=_ONTEM)
    vigente = Excecao(path="*", motivo="m", expira=_AMANHA)
    sem_validade = Excecao(path="*", motivo="m")
    hoje = date.today()
    assert vencida.expirada(hoje)
    assert not vigente.expirada(hoje)
    assert not sem_validade.expirada(hoje)


# --------------------------------------------------------------------------- #
# engine._aplicar_excecoes — mover para suppressed sem deletar / reaparecer vencida
# --------------------------------------------------------------------------- #


def test_excecao_vigente_move_para_suppressed() -> None:
    achado = _finding()
    excecao = Excecao(path=".github/workflows/*.yml", motivo="falso positivo conhecido")
    visiveis, suprimidos = _aplicar_excecoes([achado], [excecao], date.today())
    assert visiveis == []
    assert len(suprimidos) == 1
    assert suprimidos[0].finding == achado  # o achado original, intacto
    assert suprimidos[0].origem == "config"
    assert suprimidos[0].motivo == "falso positivo conhecido"


def test_excecao_vencida_achado_reaparece_com_nota() -> None:
    achado = _finding()
    excecao = Excecao(path=".github/workflows/*.yml", motivo="m", expira=_ONTEM)
    visiveis, suprimidos = _aplicar_excecoes([achado], [excecao], date.today())
    assert suprimidos == []
    assert len(visiveis) == 1
    assert f"supressão expirada em {_ONTEM}" in visiveis[0].detail
    assert visiveis[0].detail.startswith(achado.detail)  # nota é acrescentada, não substitui
    # só o detail muda; o resto do achado é preservado
    assert visiveis[0].check_id == achado.check_id
    assert visiveis[0].path == achado.path
    assert visiveis[0].line == achado.line


def test_achado_sem_excecao_casando_passa_intacto() -> None:
    achado = _finding(path=".github/workflows/outro.yml")
    excecao = Excecao(path=".github/workflows/legacy-*.yml", motivo="m")
    visiveis, suprimidos = _aplicar_excecoes([achado], [excecao], date.today())
    assert visiveis == [achado]
    assert suprimidos == []


def test_scan_integrado_aplica_config_do_repo(tmp_path: Path) -> None:
    """Ponta a ponta: `.esteira.yml` na raiz varrida, achado real suprimido pelo scan()."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "legacy.yml").write_text(
        "on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo oi\n",
        encoding="utf-8",
    )
    (tmp_path / ".esteira.yml").write_text(
        "excecoes:\n"
        "  - regra: broad-permissions\n"
        "    path: '.github/workflows/legacy.yml'\n"
        "    motivo: 'aceito até a migração, ticket OPS-1'\n",
        encoding="utf-8",
    )
    resultado = scan(tmp_path)
    assert "broad-permissions" not in {f.check_id for f in resultado.findings}
    assert [s.finding.check_id for s in resultado.suppressed] == ["broad-permissions"]
    assert resultado.suppressed[0].motivo == "aceito até a migração, ticket OPS-1"


# --------------------------------------------------------------------------- #
# invariante de classe: nunca deleta
# --------------------------------------------------------------------------- #

_CHECK_IDS = ["broad-permissions", "secret-in-run", "curl-pipe-shell"]
_PATHS = [".github/workflows/a.yml", ".github/workflows/b.yml", ".github/workflows/legacy-c.yml"]


@st.composite
def _achados_e_excecoes(draw: st.DrawFn) -> tuple[list[Finding], list[Excecao]]:
    achados = [
        _finding(check_id=draw(st.sampled_from(_CHECK_IDS)), path=draw(st.sampled_from(_PATHS)))
        for _ in range(draw(st.integers(min_value=0, max_value=6)))
    ]
    excecoes = [
        Excecao(
            path=draw(st.sampled_from([".github/workflows/*.yml", ".github/workflows/legacy-*"])),
            motivo="m",
            regra=draw(st.sampled_from([*_CHECK_IDS, None])),
            expira=draw(st.sampled_from([None, _ONTEM, _AMANHA])),
        )
        for _ in range(draw(st.integers(min_value=0, max_value=3)))
    ]
    return achados, excecoes


@given(dados=_achados_e_excecoes())
def test_aplicar_excecoes_nunca_perde_nem_duplica_achado(
    dados: tuple[list[Finding], list[Excecao]],
) -> None:
    achados, excecoes = dados
    visiveis, suprimidos = _aplicar_excecoes(achados, excecoes, date.today())
    assert len(visiveis) + len(suprimidos) == len(achados)
    # todo achado visível ou suprimido é rastreável a um achado de ENTRADA pela chave
    # (check_id, path, line) — o detail pode ganhar a nota de expiração, o resto não muda.
    chaves_entrada = {(a.check_id, a.path, a.line) for a in achados}
    for v in visiveis:
        assert (v.check_id, v.path, v.line) in chaves_entrada
    for s in suprimidos:
        assert (s.finding.check_id, s.finding.path, s.finding.line) in chaves_entrada
        assert s.origem == "config"
